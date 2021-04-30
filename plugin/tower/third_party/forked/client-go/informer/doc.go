/*
Copyright 2014 The Kubernetes Authors.

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

// This package forked from https://pkg.go.dev/k8s.io/client-go/tools/cache. This package implements
// cache.SharedIndexInformer in a more general approach. It's differs with cache.sharedIndexInformer
// in three ways. First, we generalize reflector class as reflector interface, listAndWatch becomes
// unnecessary, reflector can be implements by you own way. Second, we change the default keyFunc as
// parameter, and exampleObject could be any types. Third, we deprecated method SetWatchErrorHandler,
// it's coupling too much with cach.Reflector. You can add error handler in NewReflectorFunc now.
package informer
