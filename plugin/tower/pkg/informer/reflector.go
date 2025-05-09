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

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gertd/go-pluralize"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	"github.com/everoute/everoute/plugin/tower/pkg/utils"
	"github.com/everoute/everoute/plugin/tower/third_party/forked/client-go/informer"
)

// NewReflectorBuilder return a NewReflectorFunc with giving client
func NewReflectorBuilder(client *client.Client, crcEvent chan *CrcEvent) informer.NewReflectorFunc {
	return func(options *informer.ReflectorOptions) informer.Reflector {
		return &reflector{
			client:     client,
			store:      options.Store,
			expectType: gqlType{reflect.TypeOf(options.ExpectedType)},
			// With these parameters, backoff will stop at [30,60) sec interval which is 0.22 QPS.
			// If we don't backoff for 2min, assume server is healthy, and we reset the backoff.
			//nolint:staticcheck
			backoffManager: wait.NewExponentialBackoffManager(800*time.Millisecond, 30*time.Second, 2*time.Minute, 2.0, 1.0, options.Clock),
			resyncPeriod:   options.ResyncPeriod,
			shouldResync:   options.ShouldResync,
			clock:          options.Clock,
			reconnectMin:   time.Minute * 30,
			reconnectMax:   time.Minute * 60,
			crcEvent:       crcEvent,
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

	// skipFields contains map with type name and skipped fields.
	// When got field not exist error, we skip the fields
	skipFields map[string][]string

	// backoff manages backoff of reflector listAndWatch
	backoffManager wait.BackoffManager

	// reconnectMin and reconnectMax is the reconnect range of the websocket connection
	// listAndWatch will reset at a random time within the configured time range
	reconnectMin time.Duration
	reconnectMax time.Duration

	// resyncPeriod is the period at which shouldResync is considered.
	resyncPeriod time.Duration
	// shouldResync is invoked periodically and whenever it returns `true` the Store's Resync operation is invoked
	shouldResync cache.ShouldResyncFunc
	// clock allows tests to manipulate time
	clock clock.Clock

	crcEvent chan *CrcEvent
}

// Run repeatedly fetch all the objects and subsequent deltas.
// Run will exit when stopCh is closed.
func (r *reflector) Run(stopCh <-chan struct{}) {
	klog.Infof("start reflector for object %s, with client %v", r.expectType.TypeName(), r.client.URL)
	defer klog.Infof("stop reflector for object %s, with client %v", r.expectType.TypeName(), r.client.URL)

	go wait.BackoffUntil(r.reflectWorker(stopCh), r.backoffManager, true, stopCh)
	go r.crcEventHandler(stopCh)

	<-stopCh
}

func (r *reflector) crcEventHandler(stopCh <-chan struct{}) {
	klog.Infof("start crc event handler for %s", r.expectType)

	if r.crcEvent == nil {
		klog.Fatalf("fail to register crc event for %s", r.expectType)
		return
	}
	for {
		select {
		case event := <-r.crcEvent:
			var newObj any
			var err error
			if event.NewObj != nil {
				ctx, ctxCancel := context.WithTimeout(context.Background(), time.Second*10)
				newObj, err = r.query(ctx, event.NewObj.GetID())
				ctxCancel()
				if err != nil || newObj == nil {
					klog.Errorf("unable to query %s %s: %s", r.expectType, event.NewObj.GetID(), err)
					continue
				}
			}

			klog.V(4).Infof("get %s crc event of type %s: new %+v old %+v",
				event.EventType, r.expectType.TypeName(), newObj, event.OldObj)

			switch event.EventType {
			case CrcEventInsert:
				_ = r.store.Add(newObj)
			case CrcEventUpdate:
				if newObj != nil {
					_ = r.store.Update(newObj)
				}
			case CrcEventDelete:
				_ = r.store.Delete(event.OldObj)
			default:
				klog.Infof("reflector %s unknown event %+v", r.expectType, event)
			}
		case <-stopCh:
			return
		}
	}
}

// LastSyncResourceVersion not support by gql server.
func (r *reflector) LastSyncResourceVersion() string {
	return "<unknown>"
}

func (r *reflector) reflectWorker(stopCh <-chan struct{}) func() {
	return func() {
		defer runtime.HandleCrash()
		ctx, cancel := contextWithRandomTimeout(wait.ContextForChannel(stopCh), r.reconnectMin, r.reconnectMax)
		defer cancel()
		res, err := r.listAndWatch(ctx)
		r.watchErrorHandler(ctx, res, err)
	}
}

func contextWithRandomTimeout(ctx context.Context, minTimeout, maxTimeout time.Duration) (context.Context, context.CancelFunc) {
	timeout := minTimeout
	if maxTimeout > minTimeout {
		timeout = time.Duration(rand.Int63nRange(int64(minTimeout), int64(maxTimeout)))
	}
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func (r *reflector) query(ctx context.Context, id string) (any, error) {
	resp, err := r.client.Query(ctx, r.queryRequestWithID(id))
	if err != nil {
		return nil, err
	}
	if len(resp.Errors) != 0 {
		return nil, fmt.Errorf("query error, %v", resp.Errors)
	}

	jsonMap := make(map[string]json.RawMessage)
	if err := json.Unmarshal(resp.Data, &jsonMap); err != nil {
		return nil, err
	}

	list, err := r.unmarshalList(jsonMap[r.expectType.ListName()])
	if err == nil && len(list) == 1 {
		return list[0], nil
	}
	return nil, nil
}

func (r *reflector) listAndWatch(ctx context.Context) ([]client.ResponseError, error) {
	// In order not to miss events between list and watch, we will send watch request first.
	respCh, stopWatch, err := r.client.Subscription(r.subscriptionRequest())
	if err != nil {
		return nil, err
	}
	defer stopWatch()
	klog.Infof("start watch resource %s from %s", r.expectType.TypeName(), r.client.URL)

	// List and replace all objects in store
	query, err := r.client.Query(ctx, r.queryRequest())
	if err != nil {
		return nil, err
	}
	if len(query.Errors) != 0 {
		return query.Errors, nil
	}

	err = r.syncWith(utils.LookupJSONRaw(query.Data, r.expectType.ListName()))
	if err != nil {
		return nil, fmt.Errorf("unable save objects: %s", err)
	}
	klog.V(4).Infof("replace store objects of type %s with: %s", r.expectType.ListName(), string(query.Data))

	stopResync := make(chan struct{})
	defer close(stopResync)
	go r.resyncWorker(stopResync)

	return r.watchHandler(ctx, respCh)
}

// watchHandler watches respChan and keep store with the latest objects.
func (r *reflector) watchHandler(ctx context.Context, respCh <-chan client.Response) ([]client.ResponseError, error) {
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
			err = r.eventHandler(utils.LookupJSONRaw(resp.Data, r.expectType.TypeName()))
			if err != nil {
				return nil, err
			}
		case <-ctx.Done():
			return nil, nil
		}
	}
}

func (r *reflector) eventHandler(raw json.RawMessage) error {
	var event schema.MutationEvent
	var newObj = reflect.New(r.expectType.Type)

	err := unmarshalEvent(r.expectType.Type, raw, &event)
	if err != nil {
		return fmt.Errorf("unable marshal %s into event %T", string(raw), event)
	}

	err = json.Unmarshal(event.Node, newObj.Interface())
	if err != nil {
		return fmt.Errorf("unable marshal %s into object %T", string(event.Node), r.expectType.TypeName())
	}

	var obj = newObj.Elem().Interface()

	// delete object may got nil object, read object from previous values
	if reflect.ValueOf(obj).IsNil() && event.Mutation == schema.DeleteEvent {
		err = json.Unmarshal(event.PreviousValues, newObj.Interface())
		if err != nil {
			return fmt.Errorf("unable marshal %s into object %T for delete event", string(event.PreviousValues), r.expectType.TypeName())
		}
		obj = newObj.Elem().Interface()
	}
	klog.V(4).Infof("get %s event of type %s: %v", event.Mutation, r.expectType.TypeName(), obj)

	switch event.Mutation {
	case schema.CreateEvent:
		err = r.store.Add(obj)
	case schema.UpdateEvent:
		err = r.store.Update(obj)
	case schema.DeleteEvent:
		err = r.store.Delete(obj)
	default:
		return fmt.Errorf("unknow mutation type: %s", event.Mutation)
	}

	return err
}

func (r *reflector) watchErrorHandler(ctx context.Context, respErrs []client.ResponseError, err error) {
	switch {
	case err == nil, err == io.EOF:
		// watch closed normally
	case err == io.ErrUnexpectedEOF:
		klog.Errorf("watch for %s closed with unexpected EOF: %s", r.expectType.TypeName(), err)
	default:
		klog.Errorf("failed to watch %s: %s", r.expectType.TypeName(), err)
	}

	// reset skipFields from error message to handle the cause:
	//   after tower upgrade, query all fields from the tower
	r.skipFields = make(map[string][]string)
	for _, respErr := range respErrs {
		names := matchFieldNotExistFromMessage(respErr.Message)
		if names != nil {
			fieldName := names[0]
			typeName := names[1]
			// when the reflected objects not exist, we consider it as has synced
			// the reflector retries with backoff manager until the object exists
			if fieldName == r.expectType.ListName() && typeName == "Query" {
				_ = r.store.Replace(nil, r.LastSyncResourceVersion())
				break
			}
			r.skipFields[typeName] = append(r.skipFields[typeName], fieldName)
		}
	}

	// not logged in or token expired, need relogin
	if client.HasAuthError(respErrs) {
		klog.Errorf("receive auth failed error: %+v, try to login %s", respErrs, r.client.URL)

		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if _, err = r.client.Auth(ctx); err != nil {
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

func (r *reflector) unmarshalList(raw json.RawMessage) ([]any, error) {
	list := reflect.New(reflect.SliceOf(r.expectType.Type))

	err := unmarshalSlice(r.expectType.Type, raw, list.Interface())
	if err != nil {
		return nil, err
	}

	items := list.Elem()
	found := make([]any, 0, items.Len())

	for i := 0; i < items.Len(); i++ {
		found = append(found, items.Index(i).Interface())
	}
	return found, nil
}

// syncWith replaces the store's items with the given json RawMessage.
func (r *reflector) syncWith(raw json.RawMessage) error {
	list, err := r.unmarshalList(raw)
	if err != nil {
		return fmt.Errorf("unable to unmarshal %s into list %s", string(raw), r.expectType.TypeName())
	}
	return r.store.Replace(list, r.LastSyncResourceVersion())
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
	// always fail, so we end up listing frequently. Then, if we don't
	// manually stop the timer, we could end up with many timers active
	// concurrently.
	t := r.clock.NewTimer(r.resyncPeriod)
	return t.C(), t.Stop
}

// Queryable allow to mutate the default query request
type Queryable interface {
	GetQueryRequest(skipFields map[string][]string) string
}

// Subscribable allow to mutate the default subscription request
type Subscribable interface {
	GetSubscriptionRequest(skipFields map[string][]string) string
}

func (r *reflector) queryRequest() *client.Request {
	var queryRequest string

	switch t := reflect.New(r.expectType.Type).Elem().Interface().(type) {
	case Queryable:
		queryRequest = t.GetQueryRequest(r.skipFields)
	default:
		queryRequest = fmt.Sprintf("query {%s %s}", r.expectType.ListName(), r.expectType.QueryFields(r.skipFields))
	}

	return &client.Request{Query: queryRequest}
}

func (r *reflector) queryRequestWithID(id string) *client.Request {
	return &client.Request{
		Query: fmt.Sprintf("query {%s(where:{id:\"%s\"}) %s}", r.expectType.ListName(), id, r.expectType.QueryFields(r.skipFields))}
}

func (r *reflector) subscriptionRequest() *client.Request {
	var subscriptionRequest string

	switch t := reflect.New(r.expectType.Type).Elem().Interface().(type) {
	case Subscribable:
		subscriptionRequest = t.GetSubscriptionRequest(r.skipFields)
	default:
		subscriptionRequest = fmt.Sprintf("subscription {%s {mutation previousValues{id} node %s}}", r.expectType.TypeName(), r.expectType.QueryFields(r.skipFields))
	}

	return &client.Request{Query: subscriptionRequest}
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

	runesName := []rune(realType.Name())
	// convert head Upper to Lower
	for item, r := range runesName {
		if unicode.IsLower(r) {
			break
		}
		runesName[item] = unicode.ToLower(r)
	}
	return string(runesName)
}

// ListName return name plural with lower cases of the type.
func (t *gqlType) ListName() string {
	return pluralize.NewClient().Plural(t.TypeName())
}

// QueryFields return the type fields as gql query fields.
func (t *gqlType) QueryFields(skipFields map[string][]string) string {
	return utils.GqlTypeMarshal(t, skipFields, true)
}

// matchFieldNotExistFromMessage matchs field which not exist from error message.
// It returns two string values, the first is the field name, the second is the parent name.
// A return value of nil indicates no match.
func matchFieldNotExistFromMessage(message string) []string {
	notExistFieldPattern := regexp.MustCompile(`^Cannot query field "(?P<field>\w+)" on type "(?P<parent_name>\w+)"\.`)

	submatches := notExistFieldPattern.FindStringSubmatchIndex(message)
	if submatches != nil {
		result := string(notExistFieldPattern.ExpandString(nil, "$field:$parent_name", message, submatches))
		if names := strings.Split(result, `:`); result != ":" && len(names) == 2 {
			// todo: parent_name should be normalized, such as: "Vm" -> "VM"
			return names
		}
	}

	return nil
}

// EventUnmarshalable allow to mutate the default json decoder
type EventUnmarshalable interface {
	UnmarshalEvent(raw json.RawMessage, event *schema.MutationEvent) error
}

// SliceUnmarshalable allow to mutate the default json decoder
type SliceUnmarshalable interface {
	UnmarshalSlice(raw json.RawMessage, slice interface{}) error
}

func unmarshalEvent(originObjectType reflect.Type, raw json.RawMessage, event *schema.MutationEvent) error {
	switch t := reflect.New(originObjectType).Elem().Interface().(type) {
	case EventUnmarshalable:
		return t.UnmarshalEvent(raw, event)
	default:
		return json.Unmarshal(raw, event)
	}
}

func unmarshalSlice(originObjectType reflect.Type, raw json.RawMessage, slice interface{}) error {
	switch t := reflect.New(originObjectType).Elem().Interface().(type) {
	case SliceUnmarshalable:
		return t.UnmarshalSlice(raw, slice)
	default:
		return json.Unmarshal(raw, slice)
	}
}
