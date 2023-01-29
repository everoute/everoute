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
	"mime"
	"mime/multipart"
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"
)

func TestJSONRequest(t *testing.T) {
	RegisterTestingT(t)

	content := rand.String(10)
	request := JSONRequest(content)

	Expect(request.ContentType()).Should(Equal("application/json"))
	Expect(request.String()).Should(Equal(content))
	raw, err := io.ReadAll(request.GetReader())
	Expect(err).ShouldNot(HaveOccurred())
	Expect(string(raw)).Should(Equal(content))
}

func TestMultipartWriterRequest(t *testing.T) {
	RegisterTestingT(t)

	request := NewMultipartWriterRequest()
	fieldName := rand.String(10)
	fileName := rand.String(10)
	fileContentRaw := rand.String(100)

	err := request.CreateFormFile(fieldName, fileName, bytes.NewBufferString(fileContentRaw))
	Expect(err).ShouldNot(HaveOccurred())
	Expect(request.Close()).ShouldNot(HaveOccurred())
	Expect(request.String()).ShouldNot(BeEmpty())

	mediatype, params, _ := mime.ParseMediaType(request.ContentType())
	Expect(mediatype).Should(Equal("multipart/form-data"))
	Expect(params["boundary"]).ShouldNot(BeEmpty())

	mp, err := multipart.NewReader(request.GetReader(), params["boundary"]).NextPart()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(mp.FormName()).Should(Equal(fieldName))
	Expect(mp.FileName()).Should(Equal(fileName))
	raw, err := io.ReadAll(mp)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(string(raw)).Should(Equal(fileContentRaw))
}

func TestEncodeRequest(t *testing.T) {
	t.Run("encode request without any uploads", func(t *testing.T) {
		RegisterTestingT(t)

		req, err := EncodeRequest(&Request{Query: "my{id}", Variables: map[string]interface{}{
			"v1": 1,
			"v2": "2",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(req.ContentType()).Should(Equal("application/json"))
		Expect(req.String()).Should(Equal(`{"query":"my{id}","variables":{"v1":1,"v2":"2"}}`))
	})

	t.Run("encode request with an upload", func(t *testing.T) {
		RegisterTestingT(t)

		fileName := rand.String(10)
		fileContentRaw := rand.String(100)
		req, err := EncodeRequest(&Request{Query: "my{id}", Variables: map[string]interface{}{
			"file": Upload{
				FileName: fileName,
				File:     bytes.NewBufferString(fileContentRaw),
			},
		}})
		Expect(err).ShouldNot(HaveOccurred())
		mediatype, params, _ := mime.ParseMediaType(req.ContentType())
		Expect(mediatype).Should(Equal("multipart/form-data"))
		Expect(params["boundary"]).ShouldNot(BeEmpty())
		mr := multipart.NewReader(req.GetReader(), params["boundary"])

		mp, err := mr.NextPart()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(mp.FormName()).Should(Equal("operations"))
		raw, err := io.ReadAll(mp)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(raw)).Should(Equal(`{"query":"my{id}","variables":{"file":{"FileName":"` + fileName + `","File":{}}}}` + "\n"))

		mp, err = mr.NextPart()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(mp.FormName()).Should(Equal("map"))
		raw, err = io.ReadAll(mp)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(raw)).Should(Equal(`{"0":["variables.file"]}` + "\n"))

		mp, err = mr.NextPart()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(mp.FormName()).Should(Equal("0"))
		Expect(mp.FileName()).Should(Equal(fileName))
		raw, err = io.ReadAll(mp)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(raw)).Should(Equal(fileContentRaw))
	})
}
