# Everoute CNI QuickStart

# Backgroud
Everoute CNI provides standard K8S CNI function, 
including network support for POD communication,
and standard NetworkPolicy network strategy (currently supports up to k8s v1.21)

## Image
### build image
```shell
git glone https://github.com/everoute/everoute.git
cd everoute
make images
```
images need to be manually distributed to each node.

### public docker hub
hub.docker.io - everoute/release:latest

## Deployment
```shell
wget https://raw.githubusercontent.com/everoute/everoute/main/deploy/everoute.yaml
kubectl apply -f everoute.yaml
```

## Check
By default, everoute has one controller in whole cluster and one agent on each node
use `kubectl get pods -n kube-system | grep everoute` to check if all the related pods are running
###sample output
```text
everoute-agent-7v596                   2/2     Running   0          4h30m
everoute-agent-kmzl8                   2/2     Running   0          4h30m
everoute-agent-q8qq2                   2/2     Running   0          4h30m
everoute-controller-57fc7bc784-xcm9s   1/1     Running   0          4h30m
```
### Check case
Pending