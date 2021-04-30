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

package schema

// Object lets you work with object metadata from tower.
type Object interface {
	// GetID returns the object ID.
	GetID() string
}

// ObjectMeta is metadata that all tower resources must have.
type ObjectMeta struct {
	// ID is the unique in time and space value for this object
	ID string `json:"id"`
}

// GetID returns the object ID.
func (obj *ObjectMeta) GetID() string { return obj.ID }

// ObjectReference is the reference to other object
type ObjectReference ObjectMeta
