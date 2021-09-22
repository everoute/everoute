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

package informer

// Lister know how to list and get object from store.
type Lister interface {
	KeyLister

	// List returns a list of all the currently non-empty accumulators
	List() []interface{}

	// GetByKey returns the accumulator associated with the given key
	GetByKey(key string) (interface{}, bool, error)

	// ByIndex returns the stored objects whose set of indexed values
	// for the named index includes the given indexed value
	ByIndex(indexName, indexedValue string) ([]interface{}, error)
}

// KeyLister know how to list keys from store.
type KeyLister interface {

	// ListKeys returns the storage keys of the stored objects
	ListKeys() []string

	// IndexKeys returns the storage keys of the stored objects whose
	// set of indexed values for the named index includes the given
	// indexed value
	IndexKeys(indexName, indexedValue string) ([]string, error)
}
