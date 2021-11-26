# everoute

[![Go Report Card](https://goreportcard.com/badge/github.com/everoute/everoute)](https://goreportcard.com/report/github.com/everoute/everoute)
[![codecov](https://codecov.io/gh/everoute/everoute/branch/main/graph/badge.svg)](https://codecov.io/gh/everoute/everoute)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](https://github.com/everoute/everoute/blob/main/LICENSE)

## Overview

Everoute is a CloudNative network and security solution both for legacy
virtualization platform and [Kubernetes](https://kubernetes.io/) native network
and security. Everoute focus on network Layer3 and Layer4 to provide networking
and security service for virtualization platform and Kubernetes platform, it
leverages [Open vSwitch](https://www.openvswitchd.org/) as the networking data
plane.

## Architecture

Everoute is based on SDN (software defined network) methodology, decoples
the control plane and data plane, uses software programming to control the
network and security services.

<p align='center'>
<img src="docs/assets/everoute_arch.svg.png" width="550" alt="Everoute Architecture">
</p>

Everoute contains four main parts:
* **Everoute Central Controller Cluster**: Everoute central controller cluster
leverages the cloud native architecture, it is deployed as container service,
it leverages the [Kube API Server](https://github.com/kubernetes/apiserver) and
[etcd](https://etcd.io/) to provide the controller cluster management and data
persistent. The controller service focus on the network and security policy
management, according the resources type, security policy and discovered IP
address to calculate the security rules.  

* **Everoute Distributed Agent**: The Everoute Agent is deployed in each
hypervisor host or K8s node, it focus on the IP address discover and policy
rule depolyment to the data plane.

* **Everoute Datapath**: Everoute leverages the Open vSwitch as it's network
datapath, all the network functions implemented by the Open vSwitch, Everoute
uses Open vSwitch openflow mode to control the network forwarding and security
rules.

* **3rd party plugins** *: Everoute provides a plugin framework to intergated
with 3rd party platform, such as [SmartX](https://www.smartx.com/)
[SMTX OS](https://www.smartx.com/smtx-os) virtualaztion platform, Kuberneters
cloud native platform etc.


## Main functions

In current phase, Everoute support SmartX virtualization platform [SMTX OS](https://www.smartx.com/smtx-os) and Kubernetes platform.

* **Virtualization Platform** *: [SMTX OS](https://www.smartx.com/smtx-os)
is SmartX native virtualization platform. Everoute intergated with SMTX OS
with [CloudTower](https://www.smartx.com/cloud-tower) plugin to provide the
Micro-Segmentation functions.

* **Kubernetes Platform** *: For the Kubernetes platform, Everoute provides
the native K8s CNI network plug-in. The Everoute CNI supports Pod connection
management, networkPolicy, cluster service and NodePort etc.

## Roadmap

The following features are considered for the near future:
* Service Function Chain: to support intergated with 3rd party services such
as AV, IPS, IDS etc.
* Network Visibility: to support the network visibility, service map, traffic
monitor etc.
* Overlay support: to support the VXLAN tunnel.
* L3 routing: distributed virtual routing.
* Kubernetes networking enhancement: endPort, ingress LoadBalancer, cluster
service enhancement etc.
* Some function enhancement and performance improvement of the control plane
and date plane.


## License

Everoute is licensed under the [Apache License, version 2.0]
