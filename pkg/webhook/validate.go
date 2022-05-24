/*
Copyright 2021 The Everoute Authors.

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

package webhook

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/everoute/everoute/pkg/webhook/validates"
)

// ValidateHandle defines capability about process AdmissionReview.
type ValidateHandle interface {
	Validate(ar *admv1.AdmissionReview) *admv1.AdmissionResponse
}

// ValidateWebhook register webhook for validate everoute objects.
type ValidateWebhook struct {
	Scheme *runtime.Scheme
}

// SetupWithManager create and add a ValidateWebhook to the manager.
func (v *ValidateWebhook) SetupWithManager(mgr ctrl.Manager) error {
	crdValidate := validates.NewCRDValidate(mgr.GetClient(), mgr.GetScheme())

	mgr.GetWebhookServer().Register("/validate/crds", v.Handler(crdValidate))
	return nil
}

// Handler handle validate admission http request.
func (v *ValidateWebhook) Handler(handle ValidateHandle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = ioutil.ReadAll(r.Body)
		}
		if len(reqBody) == 0 {
			http.Error(w, "empty request body", http.StatusBadRequest)
			return
		}
		// verify the content type is accurate
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			http.Error(w, "invalid Content-Type, expected `application/json`", http.StatusUnsupportedMediaType)
			return
		}
		var admissionResponse *admv1.AdmissionResponse
		ar := admv1.AdmissionReview{}
		ar.TypeMeta.Kind = "AdmissionReview"
		ar.TypeMeta.APIVersion = "admission.k8s.io/v1"
		if err := json.Unmarshal(reqBody, &ar); err != nil || ar.Request == nil {
			if err == nil {
				err = fmt.Errorf("invalidate request body")
			}
			admissionResponse = &admv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		} else {
			admissionResponse = handle.Validate(&ar)
		}

		aReview := admv1.AdmissionReview{}
		aReview.TypeMeta.Kind = "AdmissionReview"
		aReview.TypeMeta.APIVersion = "admission.k8s.io/v1"
		if admissionResponse != nil {
			aReview.Response = admissionResponse
			if ar.Request != nil {
				aReview.Response.UID = ar.Request.UID
			}
		}

		resp, err := json.Marshal(aReview)
		if err != nil {
			http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		}

		if _, err := w.Write(resp); err != nil {
			http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		}
	}
}
