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
hub.docker.io (Pending)

### private docker hub
harbor.smartx.com - everoute/release

## Deployment
```shell
wget https://raw.githubusercontent.com/everoute/everoute/main/deploy/everoute.yaml
kubectl apply -f everoute.yaml
```

## Check
By default everoute has one controller in whole cluster and one agent on each node
use `kubectl get pods -n kube-system` to check if all the related pods are running

### Check case
Pending