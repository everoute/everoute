package resolver

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"

	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/generated"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/model"
)

func (r *mutationResolver) Login(ctx context.Context, data model.LoginInput) (*model.Login, error) {
	obj, exists := r.Resolver.TrackerFactory().User().Get(data.Username)
	if !exists {
		return nil, fmt.Errorf("user %s not found", data.Username)
	}

	user := obj.(*model.User)

	if user.Source != data.Source {
		return nil, fmt.Errorf("user %s not found", data.Username)
	}
	if user.Password != data.Password {
		return nil, fmt.Errorf("the specified password for user %s is not correct", user.Name)
	}

	return &model.Login{Token: user.Token}, nil
}

func (r *queryResolver) Vms(ctx context.Context) ([]schema.VM, error) {
	vmList := r.TrackerFactory().VM().List()
	vms := make([]schema.VM, 0, len(vmList))
	for _, vm := range vmList {
		vms = append(vms, *vm.(*schema.VM))
	}
	return vms, nil
}

func (r *queryResolver) Labels(ctx context.Context) ([]schema.Label, error) {
	labelList := r.TrackerFactory().Label().List()
	labels := make([]schema.Label, 0, len(labelList))
	for _, label := range labelList {
		labels = append(labels, *label.(*schema.Label))
	}
	return labels, nil
}

func (r *queryResolver) SecurityPolicies(ctx context.Context) ([]schema.SecurityPolicy, error) {
	policyList := r.TrackerFactory().SecurityPolicy().List()
	policies := make([]schema.SecurityPolicy, 0, len(policyList))
	for _, policy := range policyList {
		policies = append(policies, *policy.(*schema.SecurityPolicy))
	}
	return policies, nil
}

func (r *queryResolver) IsolationPolicies(ctx context.Context) ([]schema.IsolationPolicy, error) {
	policyList := r.TrackerFactory().IsolationPolicy().List()
	policies := make([]schema.IsolationPolicy, 0, len(policyList))
	for _, policy := range policyList {
		policies = append(policies, *policy.(*schema.IsolationPolicy))
	}
	return policies, nil
}

func (r *queryResolver) EverouteClusters(ctx context.Context) ([]schema.EverouteCluster, error) {
	erClusterList := r.TrackerFactory().EverouteCluster().List()
	erClusters := make([]schema.EverouteCluster, 0, len(erClusterList))
	for _, erCluster := range erClusterList {
		erClusters = append(erClusters, *erCluster.(*schema.EverouteCluster))
	}
	return erClusters, nil
}

func (r *queryResolver) Hosts(ctx context.Context) ([]schema.Host, error) {
	hostList := r.TrackerFactory().Host().List()
	hosts := make([]schema.Host, 0, len(hostList))
	for _, host := range hostList {
		hosts = append(hosts, *host.(*schema.Host))
	}
	return hosts, nil
}

func (r *queryResolver) SystemEndpoints(ctx context.Context) (*schema.SystemEndpoints, error) {
	systemEndpointsList := r.TrackerFactory().SystemEndpoints().List()
	if len(systemEndpointsList) == 0 {
		return nil, nil
	}
	return systemEndpointsList[0].(*schema.SystemEndpoints), nil
}

func (r *queryResolver) Tasks(ctx context.Context, orderBy *model.TaskOrderByInput, last *int) ([]schema.Task, error) {
	taskList := r.TrackerFactory().Task().List()
	var tasks []schema.Task
	for index, task := range taskList {
		if last != nil && index >= *last {
			break
		}
		tasks = append(tasks, *task.(*schema.Task))
	}
	return tasks, nil
}

func (r *queryResolver) SecurityGroups(ctx context.Context) ([]schema.SecurityGroup, error) {
	groupList := r.TrackerFactory().SecurityGroup().List()
	groups := make([]schema.SecurityGroup, 0, len(groupList))
	for _, group := range groupList {
		groups = append(groups, *group.(*schema.SecurityGroup))
	}
	return groups, nil
}

func (r *subscriptionResolver) VM(ctx context.Context) (<-chan *model.VMEvent, error) {
	var vmEventCh = make(chan *model.VMEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().VM().Watch()
		defer stopWatch()
		defer close(vmEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				vmEventCh <- &model.VMEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.VM),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return vmEventCh, nil
}

func (r *subscriptionResolver) Label(ctx context.Context) (<-chan *model.LabelEvent, error) {
	var labelEventCh = make(chan *model.LabelEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().Label().Watch()
		defer stopWatch()
		defer close(labelEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				labelEventCh <- &model.LabelEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.Label),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return labelEventCh, nil
}

func (r *subscriptionResolver) SecurityPolicy(ctx context.Context) (<-chan *model.SecurityPolicyEvent, error) {
	var policyEventCh = make(chan *model.SecurityPolicyEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().SecurityPolicy().Watch()
		defer stopWatch()
		defer close(policyEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				policyEventCh <- &model.SecurityPolicyEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.SecurityPolicy),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return policyEventCh, nil
}

func (r *subscriptionResolver) IsolationPolicy(ctx context.Context) (<-chan *model.IsolationPolicyEvent, error) {
	var policyEventCh = make(chan *model.IsolationPolicyEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().IsolationPolicy().Watch()
		defer stopWatch()
		defer close(policyEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				policyEventCh <- &model.IsolationPolicyEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.IsolationPolicy),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return policyEventCh, nil
}

func (r *subscriptionResolver) EverouteCluster(ctx context.Context) (<-chan *model.EverouteClusterEvent, error) {
	var erClusterEventCh = make(chan *model.EverouteClusterEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().EverouteCluster().Watch()
		defer stopWatch()
		defer close(erClusterEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				erClusterEventCh <- &model.EverouteClusterEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.EverouteCluster),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return erClusterEventCh, nil
}

func (r *subscriptionResolver) Host(ctx context.Context) (<-chan *model.HostEvent, error) {
	var hostEventCh = make(chan *model.HostEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().Host().Watch()
		defer stopWatch()
		defer close(hostEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				hostEventCh <- &model.HostEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.Host),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return hostEventCh, nil
}

func (r *subscriptionResolver) SystemEndpoints(ctx context.Context) (<-chan *schema.SystemEndpoints, error) {
	var systemEndpointsCh = make(chan *schema.SystemEndpoints, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().SystemEndpoints().Watch()
		defer stopWatch()
		defer close(systemEndpointsCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				systemEndpointsCh <- event.Object.(*schema.SystemEndpoints)
			case <-ctx.Done():
				return
			}
		}
	}()

	return systemEndpointsCh, nil
}

func (r *subscriptionResolver) Task(ctx context.Context) (<-chan *model.TaskEvent, error) {
	var taskEventCh = make(chan *model.TaskEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().Task().Watch()
		defer stopWatch()
		defer close(taskEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				taskEventCh <- &model.TaskEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.Task),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return taskEventCh, nil
}

func (r *subscriptionResolver) SecurityGroup(ctx context.Context) (<-chan *model.SecurityGroupEvent, error) {
	var groupEventCh = make(chan *model.SecurityGroupEvent, 100)

	go func() {
		eventCh, stopWatch := r.TrackerFactory().SecurityGroup().Watch()
		defer stopWatch()
		defer close(groupEventCh)

		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				groupEventCh <- &model.SecurityGroupEvent{
					Mutation: event.Type,
					Node:     event.Object.(*schema.SecurityGroup),
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return groupEventCh, nil
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

// Subscription returns generated.SubscriptionResolver implementation.
func (r *Resolver) Subscription() generated.SubscriptionResolver { return &subscriptionResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type subscriptionResolver struct{ *Resolver }
