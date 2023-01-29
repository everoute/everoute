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
	"io"
	"mime/multipart"
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
