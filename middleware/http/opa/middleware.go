/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/textproto"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"sync"

	"github.com/open-policy-agent/opa/rego"

	"github.com/dapr/components-contrib/common/httputils"
	contribMetadata "github.com/dapr/components-contrib/metadata"
	"github.com/dapr/components-contrib/middleware"
	"github.com/dapr/kit/logger"
	kitmd "github.com/dapr/kit/metadata"
	kitstrings "github.com/dapr/kit/strings"

	// added by 91
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/storage/inmem"

	// "github.com/open-policy-agent/opa/compile"
	"archive/tar"
	"compress/gzip"
	"path/filepath"
)

type Status int

// modified by 91
type middlewareMetadata struct {
	Rego                          string   `json:"rego" mapstructure:"rego"`
	RegoFilePath                  string   `json:"regoFilePath,omitempty" mapstructure:"regoFilePath"`
	OdrlPolicyDirPath             string   `json:"odrlPolicyDirPath,omitempty" mapstructure:"odrlPolicyDirPath"`
	UseRegoFile                   bool     `json:"useRegoFile,omitempty" mapstructure:"useRegoFile"`
	UseRegoBundle                 bool     `json:"useRegoBundle,omitempty" mapstructure:"useRegoBundle"`
	RegoBundleURL                 string   `json:"regoBundleURL,omitempty" mapstructure:"regoBundleURL"`
	UseOdrlFiles                  bool     `json:"useOdrlFiles,omitempty" mapstructure:"useOdrlFiles"`
	DefaultStatus                 Status   `json:"defaultStatus,omitempty" mapstructure:"defaultStatus"`
	IncludedHeaders               string   `json:"includedHeaders,omitempty" mapstructure:"includedHeaders"`
	ReadBody                      string   `json:"readBody,omitempty" mapstructure:"readBody"`
	internalIncludedHeadersParsed []string `json:"-" mapstructure:"-"`
}

// added by 91
func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// added by 91
func extractTarGz(gzipPath, targetDir string) error {
	file, err := os.Open(gzipPath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tarReader := tar.NewReader(gzr)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // end of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		targetPath := filepath.Join(targetDir, header.Name)
		fmt.Println(targetPath)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file: %w", err)
			}
			outFile.Close()
		default:
			return fmt.Errorf("unsupported file type %v in archive", header.Typeflag)
		}
	}

	return nil
}

// NewMiddleware returns a new Open Policy Agent middleware.
func NewMiddleware(logger logger.Logger) middleware.Middleware {
	return &Middleware{logger: logger}
}

func init() {
	fmt.Println("Hello from init function inside middleware.go")
}

// Middleware is an OPA  middleware.
type Middleware struct {
	logger logger.Logger
}

// RegoResult is the expected result from rego policy.
type RegoResult struct {
	Allow             bool              `json:"allow"`
	AdditionalHeaders map[string]string `json:"additional_headers,omitempty"`
	StatusCode        int               `json:"status_code,omitempty"`
}

const opaErrorHeaderKey = "x-dapr-opa-error"

var (
	errOpaNoResult          = errors.New("received no results back from rego policy. Are you setting data.http.allow?")
	errOpaInvalidResultType = errors.New("got an invalid type back from repo policy. Only a boolean or map is valid")
)

func (s *Status) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		if value != math.Trunc(value) {
			return fmt.Errorf("invalid float value %f parse to status(int)", value)
		}
		*s = Status(value)
	case string:
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		*s = Status(intVal)
	default:
		return fmt.Errorf("invalid value %v parse to status(int)", value)
	}
	if !s.Valid() {
		return fmt.Errorf("invalid status value %d expected in range [100-599]", *s)
	}

	return nil
}

// Check status is in the correct range for RFC 2616 status codes [100-599].
func (s *Status) Valid() bool {
	return s != nil && *s >= 100 && *s < 600
}

// func loadBundle(bundlePath string) error {
//     result, err := loader.NewFileLoader().AsBundle(bundlePath)
//     if err != nil {
//         return fmt.Errorf("failed to load bundle: %w", err)
//     }
//     store := inmem.NewFromObject(result.Data)
//     ctx := context.Background()
//     moduleOptions := []func(*rego.Rego){
//         rego.Store(store),
//         rego.Query("data.example.allow"), // Change to your rule
//     }
//     for name, module := range result.Modules {
//         nameStr := fmt.Sprintf("%v", name)
//         moduleOptions = append(moduleOptions, rego.Module(nameStr, string(module.Raw)))
//     }
//     r := rego.New(moduleOptions...)
//     policyQuery, err = r.PrepareForEval(ctx)
//     if err != nil {
//         return fmt.Errorf("failed to prepare rego query: %w", err)
//     }
//     return nil
// }

func (m *Middleware) GetHandler(parentCtx context.Context, metadata middleware.Metadata) (func(next http.Handler) http.Handler, error) {
	fmt.Println("hello from GetHandler")
	fmt.Println("hello again from GetHandler")

	meta, err := m.getNativeMetadata(metadata)
	if err != nil {
		return nil, err
	}

	ctx, _ := context.WithTimeout(parentCtx, time.Minute)

	var policyModule string
	var policyData map[string]interface{}
	var r *rego.Rego

	var (
		query   rego.PreparedEvalQuery
		queryMu sync.RWMutex
	)

	if meta.UseRegoFile {
		if meta.UseRegoBundle {
			refresh := func() error {
				downloadPath := "/tmp/file.tar.gz"
				extractPath := "/tmp/extracted"

				if err := downloadFile(meta.RegoBundleURL, downloadPath); err != nil {
					fmt.Printf("Download failed: %v\n", err)
					return err
				}

				if err := extractTarGz(downloadPath, extractPath); err != nil {
					fmt.Printf("Extraction failed: %v\n", err)
					return err
				}

				result, err := loader.NewFileLoader().AsBundle(extractPath)
				if err != nil {
					fmt.Printf("failed to load bundle: %v\n", err)
					return err
				}
				store := inmem.NewFromObject(result.Data)
				moduleOptions := []func(*rego.Rego){
					rego.Store(store),
					rego.Query("result = data.http.allow"),
				}
				for name, module := range result.Modules {
					nameStr := fmt.Sprintf("%v", name)
					moduleOptions = append(moduleOptions, rego.Module(nameStr, string(module.Raw)))
				}
				r = rego.New(moduleOptions...)
				newQuery, err := r.PrepareForEval(context.Background())
				if err != nil {
					return err
				}
				queryMu.Lock()
				query = newQuery
				queryMu.Unlock()
				return nil
			}

			if err := refresh(); err != nil {
				return nil, err
			}

			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for range ticker.C {
					if err := refresh(); err != nil {
						fmt.Printf("bundle refresh failed: %v\n", err)
					}
				}
			}()
		} else if meta.UseOdrlFiles {
			fmt.Println("using an odrl policy directory")
			files, err := os.ReadDir(meta.OdrlPolicyDirPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read ODRL policy directory: %w", err)
			}

			policies := make(map[string]interface{})

			for _, file := range files {
				if file.IsDir() {
					continue
				}
				name := file.Name()
				fmt.Println(name)
				if !strings.HasSuffix(name, ".json") {
					continue
				}
				prefix := strings.SplitN(name, ".", 2)[0]
				content, readErr := os.ReadFile(filepath.Join(meta.OdrlPolicyDirPath, name))
				if readErr != nil {
					return nil, fmt.Errorf("failed to read ODRL file %s: %w", name, readErr)
				}
				var odrlPolicy map[string]interface{}
				if err := json.Unmarshal(content, &odrlPolicy); err != nil {
					return nil, fmt.Errorf("failed to parse ODRL file %s: %w", name, err)
				}
				policies[prefix] = odrlPolicy
				fmt.Println(odrlPolicy)
			}

			policyData = map[string]interface{}{
				"policies": policies,
			}
			content, readErr := os.ReadFile(meta.RegoFilePath)
			if readErr != nil {
				return nil, fmt.Errorf("failed to read Rego file from %s: %w", meta.RegoFilePath, readErr)
			}
			policyModule = string(content)
			fmt.Println("preparing rego query, using ODRL")
			store := inmem.NewFromObject(policyData)
			r = rego.New(
				rego.Query("result = data.http.allow"),
				rego.Module("policy.rego", policyModule),
				rego.Store(store),
			)
			query, err = r.PrepareForEval(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			fmt.Println("using a rego file")
			content, readErr := os.ReadFile(meta.RegoFilePath)
			if readErr != nil {
				return nil, fmt.Errorf("failed to read Rego file from %s: %w", meta.RegoFilePath, readErr)
			}
			policyModule = string(content)
			fmt.Println(policyModule)
			fmt.Println("preparing rego query, NOT using ODRL")
			r = rego.New(
				rego.Query("result = data.http.allow"),
				rego.Module("policy.rego", policyModule),
			)
			query, err = r.PrepareForEval(ctx)
			if err != nil {
				return nil, err
			}
		}
	} else {
		policyModule = meta.Rego
		r = rego.New(
			rego.Query("result = data.http.allow"),
			rego.Module("policy.rego", policyModule),
		)
		query, err = r.PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			queryMu.RLock()
			defer queryMu.RUnlock()
			if allow := m.evalRequest(w, r, meta, &query); !allow {
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}



func (m *Middleware) evalRequest(w http.ResponseWriter, r *http.Request, meta *middlewareMetadata, query *rego.PreparedEvalQuery) bool {
	headers := map[string]string{}

	for key, value := range r.Header {
		if len(value) > 0 && slices.Contains(meta.internalIncludedHeadersParsed, key) {
			headers[key] = strings.Join(value, ", ")
		}
	}

	var body string
	if kitstrings.IsTruthy(meta.ReadBody) {
		buf, _ := io.ReadAll(r.Body)
		body = string(buf)
		r.Body = io.NopCloser(bytes.NewBuffer(buf)) // Reset body for downstream
	}

	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	// Parse user roles from header
	roleHeader := r.Header.Get("X-User-Roles")
	var roles []string
	if roleHeader != "" {
		roles = strings.Split(roleHeader, ",")
		for i := range roles {
			roles[i] = strings.TrimSpace(roles[i])
		}
	}

	input := map[string]interface{}{
		"request": map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"path_parts": pathParts,
			"raw_query":  r.URL.RawQuery,
			"query":      map[string][]string(r.URL.Query()),
			"headers":    headers,
			"scheme":     r.URL.Scheme,
			"body":       body,
		},

		"user_roles": roles,
		"resource":   r.URL.String(), // full path (e.g., /hello)
		"action":     "use",          // static or dynamic
	}

	results, err := query.Eval(r.Context(), rego.EvalInput(input))
	if err != nil {
		m.opaError(w, meta, err)
		return false
	}

	if len(results) == 0 {
		m.opaError(w, meta, errOpaNoResult)
		return false
	}

	return m.handleRegoResult(w, r, meta, results[0].Bindings["result"])
}

// handleRegoResult takes the in process request and open policy agent evaluation result
// and maps it the appropriate response or headers.
// It returns true if the request should continue, or false if a response should be immediately returned.
func (m *Middleware) handleRegoResult(w http.ResponseWriter, r *http.Request, meta *middlewareMetadata, result any) bool {
	if allowed, ok := result.(bool); ok {
		if !allowed {
			httputils.RespondWithError(w, int(meta.DefaultStatus))
		}
		return allowed
	}

	if _, ok := result.(map[string]any); !ok {
		m.opaError(w, meta, errOpaInvalidResultType)
		return false
	}

	// Is it expensive to marshal back and forth? Should we just manually pull out properties?
	marshaled, err := json.Marshal(result)
	if err != nil {
		m.opaError(w, meta, err)
		return false
	}

	regoResult := RegoResult{
		// By default, a non-allowed request with return a 403 response.
		StatusCode:        int(meta.DefaultStatus),
		AdditionalHeaders: make(map[string]string),
	}

	if err = json.Unmarshal(marshaled, &regoResult); err != nil {
		m.opaError(w, meta, err)
		return false
	}

	// If the result isn't allowed, set the response status and
	// apply the additional headers to the response.
	// Otherwise, set the headers on the ongoing request (overriding as necessary).
	if !regoResult.Allow {
		for key, value := range regoResult.AdditionalHeaders {
			w.Header().Set(key, value)
		}
		httputils.RespondWithError(w, regoResult.StatusCode)
	} else {
		for key, value := range regoResult.AdditionalHeaders {
			r.Header.Set(key, value)
		}
	}

	return regoResult.Allow
}

func (m *Middleware) opaError(w http.ResponseWriter, meta *middlewareMetadata, err error) {
	w.Header().Set(opaErrorHeaderKey, "true")
	httputils.RespondWithError(w, int(meta.DefaultStatus))
	m.logger.Warnf("Error procesing rego policy: %v", err)
}

func (m *Middleware) getNativeMetadata(metadata middleware.Metadata) (*middlewareMetadata, error) {
	meta := middlewareMetadata{
		DefaultStatus: 403,
	}
	err := kitmd.DecodeMetadata(metadata.Properties, &meta)
	if err != nil {
		return nil, err
	}

	meta.internalIncludedHeadersParsed = strings.Split(meta.IncludedHeaders, ",")
	n := 0
	for i := range meta.internalIncludedHeadersParsed {
		scrubbed := strings.ReplaceAll(meta.internalIncludedHeadersParsed[i], " ", "")
		if scrubbed != "" {
			meta.internalIncludedHeadersParsed[n] = textproto.CanonicalMIMEHeaderKey(scrubbed)
			n++
		}
	}
	meta.internalIncludedHeadersParsed = meta.internalIncludedHeadersParsed[:n]

	return &meta, nil
}

func (m *Middleware) GetComponentMetadata() (metadataInfo contribMetadata.MetadataMap) {
	metadataStruct := middlewareMetadata{}
	contribMetadata.GetMetadataInfoFromStructType(reflect.TypeOf(metadataStruct), &metadataInfo, contribMetadata.MiddlewareType)
	return
}
