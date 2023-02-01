/*
Copyright 2023 The Everoute Authors.

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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"reflect"
	"strconv"
	"strings"
)

// RequestInterface provides metadata of a http request
type RequestInterface interface {
	String() string       // humanreadable string
	GetReader() io.Reader // request body reader
	ContentType() string  // content-type in header
}

// MultipartWriterRequest generates multipart messages as RequestInterface, it wraps multipart
// writer. But differently, you can CreateFormFile with file reader directly.
type MultipartWriterRequest struct {
	*multipart.Writer

	readers              []io.Reader
	humanreadableContent string
}

// NewMultipartWriterRequest returns a new MultipartWriterRequest
func NewMultipartWriterRequest() *MultipartWriterRequest {
	m := &MultipartWriterRequest{}
	m.Writer = multipart.NewWriter(m)
	return m
}

func (m *MultipartWriterRequest) Write(data []byte) (int, error) {
	if len(m.readers) == 0 {
		m.readers = append(m.readers, bytes.NewBuffer(nil))
	}
	m.humanreadableContent += string(data)
	return m.readers[len(m.readers)-1].(io.Writer).Write(data)
}

func (m *MultipartWriterRequest) CreateFormFile(fieldname, filename string, reader io.Reader) error {
	_, err := m.Writer.CreateFormFile(fieldname, filename)
	if err != nil {
		return err
	}
	m.humanreadableContent += "COLLAPSED FORM FILE CONTENT\n"
	m.readers = append(m.readers, reader, bytes.NewBuffer(nil))
	return nil
}

func (m *MultipartWriterRequest) ContentType() string  { return m.FormDataContentType() }
func (m *MultipartWriterRequest) String() string       { return m.humanreadableContent }
func (m *MultipartWriterRequest) GetReader() io.Reader { return io.MultiReader(m.readers...) }

type JSONRequest []byte

func (r JSONRequest) ContentType() string  { return "application/json" }
func (r JSONRequest) String() string       { return string(r) }
func (r JSONRequest) GetReader() io.Reader { return bytes.NewReader(r) }

// EncodeRequest encode graphql request to http request. If req contains an upload
// file, it encode message as multipart/form-data, and the file will not be copied
func EncodeRequest(req *Request) (RequestInterface, error) {
	m := loadJSONPathUploadMap("variables", req.Variables)
	if len(m) == 0 {
		raw, err := json.Marshal(req)
		return JSONRequest(raw), err
	}

	indexJSONPathMap := map[string][]string{}
	index := 0
	for jsonPath := range m {
		indexJSONPathMap[strconv.Itoa(index)] = []string{jsonPath}
		index++
	}

	multipartWriter := NewMultipartWriterRequest()
	defer multipartWriter.Close()

	// Content-Disposition: form-data; name="operations"
	fw, err := multipartWriter.CreateFormField("operations")
	if err != nil {
		return nil, fmt.Errorf("encode request: %s", err)
	}
	err = json.NewEncoder(fw).Encode(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %s", err)
	}

	// Content-Disposition: form-data; name="map"
	fw, err = multipartWriter.CreateFormField("map")
	if err != nil {
		return nil, fmt.Errorf("encode request: %s", err)
	}
	err = json.NewEncoder(fw).Encode(indexJSONPathMap)
	if err != nil {
		return nil, fmt.Errorf("encode request: %s", err)
	}

	// Content-Disposition: form-data; name="0"; filename="fileName"
	// Content-Type: application/octet-stream
	for index, jsonPath := range indexJSONPathMap {
		upload := m[jsonPath[0]]
		err = multipartWriter.CreateFormFile(index, upload.FileName, upload.File)
		if err != nil {
			return nil, fmt.Errorf("encode request: %s", err)
		}
	}

	return multipartWriter, nil
}

// loadJSONPathUploadMap get all upload from the object
func loadJSONPathUploadMap(pathPrefix string, obj interface{}) map[string]Upload {
	m := make(map[string]Upload)
	if obj != nil {
		setJSONPathUploadMap(m, pathPrefix, reflect.ValueOf(obj))
	}
	return m
}

func setJSONPathUploadMap(m map[string]Upload, parentJSONPath string, obj reflect.Value) {
	switch obj.Type().Kind() {
	case reflect.Interface, reflect.Ptr:
		if !obj.IsNil() {
			setJSONPathUploadMap(m, parentJSONPath, obj.Elem())
		}

	case reflect.Array, reflect.Slice:
		for i := 0; i < obj.Len(); i++ {
			setJSONPathUploadMap(m, fmt.Sprintf("%s.%d", parentJSONPath, i), obj.Index(i))
		}

	case reflect.Map:
		for _, mapKey := range obj.MapKeys() {
			setJSONPathUploadMap(m, fmt.Sprintf("%s.%s", parentJSONPath, mapKey), obj.MapIndex(mapKey))
		}

	case reflect.Struct:
		if obj.Type() == reflect.TypeOf(Upload{}) {
			m[parentJSONPath] = obj.Interface().(Upload)
			return
		}
		for i := 0; i < obj.NumField(); i++ {
			jsonTagName := getFieldJSONTag(obj.Type().Field(i))
			if jsonTagName == "" {
				continue
			}
			setJSONPathUploadMap(m, fmt.Sprintf("%s.%s", parentJSONPath, jsonTagName), obj.Field(i))
		}
	}
}

func getFieldJSONTag(field reflect.StructField) string {
	jsonTag := field.Tag.Get("json")

	if field.PkgPath != "" || field.Anonymous || jsonTag == "-" {
		return ""
	}

	tag := strings.Split(jsonTag, ",")[0]
	if tag != "" {
		return tag
	}
	return field.Name
}
