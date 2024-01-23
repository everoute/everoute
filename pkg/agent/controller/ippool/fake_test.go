package ippool

import "k8s.io/apimachinery/pkg/util/sets"

type OverlayIPtables struct {
	cidrs sets.Set[string]
	err   error
}

func newOverlayIPtables() *OverlayIPtables {
	return &OverlayIPtables{
		cidrs: sets.New[string](),
	}
}

func (o *OverlayIPtables) Update() {}

func (o *OverlayIPtables) AddRuleByCIDR(cidr string) error {
	return o.err
}
func (o *OverlayIPtables) DelRuleByCIDR(cidr string) error {
	return o.err
}

func (o *OverlayIPtables) InsertPodCIDRs(cidrs ...string) {
	o.cidrs.Insert(cidrs...)
}
func (o *OverlayIPtables) DelPodCIDRs(cidrs ...string) {
	o.cidrs.Delete(cidrs...)
}

type OverlayRoute struct {
	cidrs sets.Set[string]
	err   error
}

func newOverlayRoute() *OverlayRoute {
	return &OverlayRoute{
		cidrs: sets.New[string](),
	}
}

func (o *OverlayRoute) Update() {}
func (o *OverlayRoute) AddRouteByDst(dstCIDR string) error {
	return o.err
}
func (o *OverlayRoute) DelRouteByDst(dstCIDR string) error {
	return o.err
}
func (o *OverlayRoute) InsertPodCIDRs(cidrs ...string) {
	o.cidrs.Insert(cidrs...)
}
func (o *OverlayRoute) DelPodCIDRs(cidrs ...string) {
	o.cidrs.Delete(cidrs...)
}

func resetErr() {
	iptCtrl.err = nil
	routeCtrl.err = nil
}
