/*
Copyright 2021 The Lynx Authors.

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

package utils

import (
	"encoding/json"
)

// LookupJSONRaw return json raw with giving keys
func LookupJSONRaw(raw json.RawMessage, key ...string) json.RawMessage {
	if len(key) == 0 {
		return raw
	}

	var rawMap map[string]json.RawMessage

	err := json.Unmarshal(raw, &rawMap)
	if err != nil {
		return json.RawMessage{}
	}

	return LookupJSONRaw(rawMap[key[0]], key[1:]...)
}
