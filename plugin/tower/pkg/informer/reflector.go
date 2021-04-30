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

package informer

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/gertd/go-pluralize"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	klog "k8s.io/klog"

	"github.com/smartxworks/lynx/plugin/tower/pkg/client"
	"github.com/smartxworks/lynx/plugin/tower/pkg/utils"
	"github.com/smartxworks/lynx/plugin/tower/third_party/forked/client-go/informer"
)

// NewReflectorBuilder return a NewReflectorFunc with giving client
func NewReflectorBuilder(client *client.Client) informer.NewReflectorFunc {
	return func(options *informer.ReflectorOptions) informer.Reflector {
		return &reflector{
			client:     client,
			store:      options.Store,
			expectType: gqlType{reflect.TypeOf(options.ExpectedType)},
			// With these parameters, backoff will stop at [30,60) sec interval which is 0.22 QPS.
			// If we don't backoff for 2min, assume server is healthy and we reset the backoff.
			backoffManager: wait.NewExponentialBackoffManager(800*time.Millisecond, 30*time.Second, 2*time.Minute, 2.0, 1.0, options.Clock),
			resyncPeriod:   options.ResyncPeriod,
			shouldResync:   options.ShouldResync,
			clock:          options.Clock,
		}
	}
}

// reflector use tower client watches a specified resource,
// causes all changes to be reflected in the given store.
type reflector struct {
	// client connect to resource server
	client *client.Client
	// The destination to sync up with the watch source
	store cache.Store

	// An example object of the type we expect to place in the store.
	expectType gqlType

	// backoff manages backoff of reflector listAndWatch
	backoffManager wait.BackoffManager

	// resyncPeriod is the period at which shouldResync is considered.
	resyncPeriod time.Duration
	// shouldResync is invoked periodically and whenever it returns `true` the Store's Resync operation is invoked
	shouldResync cache.ShouldResyncFunc
	// clock allows tests to manipulate time
	clock clock.Clock
}

// Run repeatedly fetch all the objects and subsequent deltas.
// Run will exit when stopCh is closed.
func (r *reflector) Run(stopCh <-chan struct{}) {
	klog.Infof("start reflector for object %s, with client %v", r.expectType.TypeName(), r.client.URL)
	defer klog.Infof("stop reflector for object %s, with client %v", r.expectType.TypeName(), r.client.URL)

	wait.BackoffUntil(r.reflectWorker(stopCh), r.backoffManager, true, stopCh)
}

// Resource version not support by gql server.
func (r *reflector) LastSyncResourceVersion() string {
	return "<unknown>"
}

func (r *reflector) reflectWorker(stopCh <-chan struct{}) func() {
	return func() {
		r.watchErrorHandler(r.listAndWatch(stopCh))
	}
}

func (r *reflector) listAndWatch(stopCh <-chan struct{}) ([]client.ResponseError, error) {
	// In order not to miss events between list and watch, we will send watch request first.
	respCh, stopWatch, err := r.client.Subscription(r.subscriptionRequest())
	if err != nil {
		return nil, err
	}
	defer stopWatch()
	klog.Infof("start watch resource %s from %s", r.expectType.TypeName(), r.client.URL)

	// List and replace all objects in store
	query, err := r.client.Query(r.queryRequest())
	if err != nil || len(query.Errors) != 0 {
		return query.Errors, err
	}

	err = r.syncWith(utils.LookupJsonRaw(query.Data, r.expectType.ListName()))
	if err != nil {
		return nil, fmt.Errorf("unable save objects: %s", err)
	}
	klog.V(4).Infof("replace store objects of type %s with: %s", r.expectType.ListName(), string(query.Data))

	stopResync := make(chan struct{})
	defer close(stopResync)
	go r.resyncWorker(stopResync)

	return r.watchHandler(respCh, stopCh)
}

// watchHandler watches respChan and keep store with latest objects.
func (r *reflector) watchHandler(respCh <-chan client.Response, stopCh <-chan struct{}) ([]client.ResponseError, error) {
	var err error

	for {
		select {
		case resp, ok := <-respCh:
			if !ok {
				// respchan chan has been closed
				return nil, io.EOF
			}
			if len(resp.Errors) != 0 {
				return resp.Errors, nil
			}
			err = r.eventHandler(utils.LookupJsonRaw(resp.Data, r.expectType.TypeName()))
			if err != nil {
				return nil, err
			}
		case <-stopCh:
			return nil, nil
		}
	}
}

func (r *reflector) eventHandler(raw json.RawMessage) error {
	var event client.MutationEvent
	var newObj = reflect.New(r.expectType.Type)

	err := json.Unmarshal(raw, &event)
	if err != nil {
		return fmt.Errorf("unable marshal %s into event %T", string(raw), event)
	}

	err = json.Unmarshal(event.Node, newObj.Interface())
	if err != nil {
		return fmt.Errorf("unable marshal %s into object %T", string(event.Node), r.expectType.TypeName())
	}

	var obj = newObj.Elem().Interface()
	klog.V(4).Infof("get %s event of type %s: %v", event.Mutation, r.expectType.TypeName(), obj)

	// todo: this is a bug of tower, delete object may got nil object
	if reflect.ValueOf(obj).IsNil() && event.Mutation == client.DeleteEvent {
		klog.Errorf("receieve delete event of type %s but nil object", r.expectType.TypeName())
		return nil
	}

	switch event.Mutation {
	case client.CreateEvent:
		err = r.store.Add(obj)
	case client.UpdateEvent:
		err = r.store.Update(obj)
	case client.DeleteEvent:
		err = r.store.Delete(obj)
	default:
		return fmt.Errorf("unknow mutation type: %s", event.Mutation)
	}

	return err
}

func (r *reflector) watchErrorHandler(respErrs []client.ResponseError, err error) {
	switch {
	case err == nil, err == io.EOF:
		// watch closed normally
	case err == io.ErrUnexpectedEOF:
		klog.Errorf("watch for %s closed with unexpected EOF: %s", r.expectType.TypeName(), err)
	default:
		klog.Errorf("failed to watch %s: %s", r.expectType.TypeName(), err)
	}

	// not logged in or token expired, need relogin
	if client.HasAuthError(respErrs) {
		klog.Errorf("receive auth failed error: %+v, try to login %s", respErrs, r.client.URL)

		if _, err = r.client.Auth(); err != nil {
			klog.Errorf("failed to login %s, got error: %s", r.client.URL, err)
			return
		}

		klog.Infof("login %s success", r.client.URL)
		return
	}

	if len(respErrs) != 0 {
		klog.Errorf("watch %s receive errors: %+v", r.expectType.TypeName(), respErrs)
	}
}

// syncWith replaces the store's items with the given json RawMessage.
func (r *reflector) syncWith(raw json.RawMessage) error {
	list := reflect.New(reflect.SliceOf(r.expectType.Type))

	err := json.Unmarshal(raw, list.Interface())
	if err != nil {
		return fmt.Errorf("unable marshal %s into slices of %s", string(raw), r.expectType.TypeName())
	}

	items := list.Elem()
	found := make([]interface{}, 0, items.Len())

	for i := 0; i < items.Len(); i++ {
		found = append(found, items.Index(i).Interface())
	}

	return r.store.Replace(found, r.LastSyncResourceVersion())
}

// resyncWorker will resync store when every after resyncPeriod and shouldResync
func (r *reflector) resyncWorker(stopCh <-chan struct{}) {
	resyncCh, cleanup := r.resyncChan()
	defer cleanup()

	for {
		select {
		case <-resyncCh:
		case <-stopCh:
			return
		}
		if r.shouldResync == nil || r.shouldResync() {
			if err := r.store.Resync(); err != nil {
				klog.Errorf("reflector of type %s, unable resync store: %s", r.expectType.TypeName(), err)
			}
		}
		cleanup()
		resyncCh, cleanup = r.resyncChan()
	}
}

// resyncChan returns a channel which will receive something when a resync is
// required, and a cleanup function.
func (r *reflector) resyncChan() (<-chan time.Time, func() bool) {
	if r.resyncPeriod == 0 {
		return make(chan time.Time), func() bool { return false }
	}
	// The cleanup function is required: imagine the scenario where watches
	// always fail so we end up listing frequently. Then, if we don't
	// manually stop the timer, we could end up with many timers active
	// concurrently.
	t := r.clock.NewTimer(r.resyncPeriod)
	return t.C(), t.Stop
}

func (r *reflector) queryRequest() *client.Request {
	request := &client.Request{
		Query: fmt.Sprintf("query {%s %s}", r.expectType.ListName(), r.expectType.QueryFields()),
	}
	return request
}

func (r *reflector) subscriptionRequest() *client.Request {
	request := &client.Request{
		Query: fmt.Sprintf("subscription {%s {mutation node %s}}", r.expectType.TypeName(), r.expectType.QueryFields()),
	}
	return request
}

type gqlType struct {
	reflect.Type
}

// TypeName return name with lower cases of the type.
func (t *gqlType) TypeName() string {
	var realType = t.Type

	for realType.Kind() == reflect.Ptr {
		realType = realType.Elem()
	}

	return strings.ToLower(realType.Name())
}

// ListName return name plural with lower cases of the type.
func (t *gqlType) ListName() string {
	return pluralize.NewClient().Plural(t.TypeName())
}

// QueryFields return the type fields as gql query fields.
func (t *gqlType) QueryFields() string {
	return utils.GqlTypeMarshal(t, true)
}
