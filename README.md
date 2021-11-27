# everoute

[![Go Report Card](https://goreportcard.com/badge/github.com/everoute/everoute)](https://goreportcard.com/report/github.com/everoute/everoute)
[![codecov](https://codecov.io/gh/everoute/everoute/branch/main/graph/badge.svg)](https://codecov.io/gh/everoute/everoute)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](https://github.com/everoute/everoute/blob/main/LICENSE)

## Overview

Everoute is a Cloud Native network and security solution both for legacy
virtualization platform and [Kubernetes](https://kubernetes.io) native network
and security. Everoute focus on network Layer3 and Layer4 to provide networking
and security service for virtualization platform and Kubernetes platform, it
leverages [Open vSwitch](https://www.openvswitchd.org) as the networking data
plane.

Everoute mainly focuses on the networking and security control, it can be
integrated with Kubernetes cloud native platform, virtualization platform,
private cloud, public cloud and even hybrid cloud easily.

## Architecture

Everoute is based on SDN (Software Defined Network) methodology, decouples
the control plane and data plane, and uses software programming to control the
software network and security services.

All the Everoute related services are deployed as Kubernetes Pod, and are easy
to deploy and use.

<p align='center'>
<img src="docs/assets/everoute_arch.svg.png" width="550" alt="Everoute Architecture">
</p>

Everoute contains four main parts:

* **Everoute Central Controller**: Everoute central controller consists of
control service, API Server and etcd, it leverages the cloud native
architecture, all the services are deployed as container Pod. The Everoute
Central Controller leverages the [Kube API Server](https://github.com/kubernetes/apiserver)
and [etcd](https://etcd.io) to provide the controller cluster management and
data persistence. Throught cluster to support the controller high availability
and scale-out. The controller service focuses on the network and security policy
management, according the resources type, security policy and discovered IP
address to generate the network transimit policy rules.

* **Everoute Distributed Agent**: The Everoute Agent is deployed in each
K8s worker node or hypervisor host, the Agent is mainly responsible for the
coordinated processing of controller and data plane, it focuses on IP address
discovery and policy rule deployment to the data plane.

* **Everoute Datapath**: Everoute leverages the Open vSwitch as it's network
data plane, Everoute leverages it to implement virtual network forwarding, Pod
networking and security features. Everoute uses Open vSwitch openflow mode to
control the network forwarding and security rules.

* **3rd party plugins**: Everoute provides a plugin framework to integrate
with 3rd party platforms, such as [SmartX](https://www.smartx.com) -
[SMTX OS](https://www.smartx.com/smtx-os) virtualization platform or other
cloud platform.


## Main functions

In the current phase, Everoute support native Kubernetes platform and
SmartX virtualization platform [SMTX OS](https://www.smartx.com/smtx-os).

* **Kubernetes Platform**: For the Kubernetes platform, Everoute provides
the native K8s CNI network plug-in. The Everoute CNI supports Pod connection
management, Network Policies, cluster service and NodePort etc. Details please
refer to [Everoute CNI](https://github.com/everoute/everoute/blob/dev/docs/cni/README.md) 

* **Virtualization Platform**: [SMTX OS](https://www.smartx.com/smtx-os)
is [SmartX](https://www.smartx.com) native virtualization platform.
Everoute can be intergated with SMTX OS through the
[CloudTower](https://www.smartx.com/cloud-tower) plugin to provide the
Micro-Segmentation service.

## Roadmap

The following features are considered for the near future:
* Network Visibility: to support the network visibility, service map, traffic
monitor etc.
* Overlay support: to support the VXLAN tunnel.
* L3 routing: distributed virtual routing.
* Kubernetes networking enhancement: endPort, ingress LoadBalancer, cluster
service enhancement etc.
* Some function enhancement and performance improvement of the control plane
and data plane.
* Service Function Chain: to support integrated with 3rd party services such
as AV, IPS, IDS, traffic monitor etc.

## License

Everoute is licensed under the [Apache License, version 2.0](LICENSE)