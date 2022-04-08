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

package utils

import (
	"fmt"
	"reflect"
	"strings"
)

// GqlTypeMarshal encoding reflect type into gql query types
// Parameter skipFields contains map of skipped fields with parent type
func GqlTypeMarshal(t reflect.Type, skippFields map[string]string, bracketed bool) string {
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice:
		return GqlTypeMarshal(t.Elem(), skippFields, bracketed)

	case reflect.Struct:
		var gqlFields []string

		for i := 0; i < t.NumField(); i++ {
			name := lookupFieldName(t.Field(i))
			if name != "" && skippFields != nil && skippFields[name] == t.Name() {
				continue
			}
			subField := GqlTypeMarshal(t.Field(i).Type, skippFields, name != "")
			gqlFields = append(gqlFields, name+subField)
		}

		if bracketed && len(gqlFields) != 0 {
			return fmt.Sprintf("{%s}", strings.Join(gqlFields, ","))
		}
		return strings.Join(gqlFields, ",")

	default:
		return ""
	}
}

func lookupFieldName(f reflect.StructField) string {
	if tag, ok := f.Tag.Lookup("gql"); ok {
		return tag
	}

	if tag, ok := f.Tag.Lookup("json"); ok {
		// ignore json other tags
		return strings.Split(tag, ",")[0]
	}

	if f.Anonymous {
		// ignore anonymous and no tag field
		return ""
	}

	return f.Name
}
