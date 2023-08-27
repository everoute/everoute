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

package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/cenkalti/backoff"
	admv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/controller/common"
	endpointctrl "github.com/everoute/everoute/pkg/controller/endpoint"
	groupctrl "github.com/everoute/everoute/pkg/controller/group"
	"github.com/everoute/everoute/pkg/controller/k8s"
	ctrlpolicy "github.com/everoute/everoute/pkg/controller/policy"
	"github.com/everoute/everoute/pkg/healthz"
	"github.com/everoute/everoute/pkg/webhook"
	towerplugin "github.com/everoute/everoute/plugin/tower/pkg/register"
	"github.com/everoute/everoute/third_party/cert"
)

func init() {
	utilruntime.Must(corev1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(admv1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(networkingv1.AddToScheme(clientsetscheme.Scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var disableAutoTLS bool
	var tlsCertDir string
	var serverPort int
	var leaderElectionNamespace string
	var towerPluginOptions towerplugin.Options
	var enableCNI bool
	var enableProxy bool

	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true, "Enable leader election for controller manager.")
	flag.BoolVar(&disableAutoTLS, "disable-auto-tls", false, "Disable auto tls cert generate for webhook.")
	flag.StringVar(&tlsCertDir, "tls-certs-dir", "/etc/ssl/certs", "The certs dir for everoute webhook use.")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "", "The namespace in which the leader election configmap will be created.")
	flag.IntVar(&serverPort, "port", 9443, "The port for the Everoute controller to serve on.")
	flag.BoolVar(&enableCNI, "enable-cni", false, "Enable CNI related controller.")
	flag.BoolVar(&enableProxy, "enable-proxy", false, "Enable CNI service proxy")
	klog.InitFlags(nil)
	towerplugin.InitFlags(&towerPluginOptions, nil, "plugins.tower.")
	flag.Parse()

	config := ctrl.GetConfigOrDie()
	config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(constants.ControllerRuntimeQPS, constants.ControllerRuntimeBurst)
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                  clientsetscheme.Scheme,
		MetricsBindAddress:      metricsAddr,
		Port:                    serverPort,
		LeaderElection:          enableLeaderElection,
		LeaderElectionNamespace: leaderElectionNamespace,
		LeaderElectionID:        "24d5749e.leader-election.everoute.io",
		CertDir:                 tlsCertDir,
	})
	if err != nil {
		klog.Fatalf("unable to start manager: %s", err.Error())
	}

	if !disableAutoTLS {
		// set secret and webhook
		setWebhookCert(mgr.GetAPIReader(), tlsCertDir)
		if err = (&common.WebhookReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			klog.Fatalf("unable to create webhook controller: %s", err.Error())
		}
	}

	// endpoint controller sync endpoint status from agentinfo.
	if err = (&endpointctrl.EndpointReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create endpoint controller: %s", err.Error())
	}

	// group controller sync & manager group members.
	if err = (&groupctrl.GroupReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create group controller: %s", err.Error())
	}

	if err = (&ctrlpolicy.Reconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		ReadClient: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create policy controller: %s", err.Error())
	}

	if enableCNI {
		// pod controller
		if err = (&k8s.PodReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			klog.Fatalf("unable to create pod controller: %s", err.Error())
		}
		klog.Info("start pod controller")

		// networkPolicy controller
		if err = (&k8s.NetworkPolicyReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			klog.Fatalf("unable to create networkPolicy controller: %s", err.Error())
		}
		klog.Info("start networkPolicy controller")

		if enableProxy {
			if err = (&k8s.EndpointsReconcile{
				APIReader: mgr.GetAPIReader(),
				Client:    mgr.GetClient(),
				Scheme:    mgr.GetScheme(),
			}).SetupWithManager(mgr); err != nil {
				klog.Fatalf("unable to create endpoints controller: %s", err.Error())
			}
			klog.Info("start endpoints controller")
		}
	}

	// register validate handle
	if err = (&webhook.ValidateWebhook{
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create crd validate webhook %s", err.Error())
	}

	// register tower plugin
	err = towerplugin.AddToManager(&towerPluginOptions, mgr)
	if err != nil {
		klog.Fatalf("unable register tower plugin: %s", err.Error())
	}

	// install /healthz handler
	healthz.InstallHandler(mgr.GetWebhookServer(),
		healthz.PingHealthz,
		healthz.LogHealthz,
		healthz.NewCacheSyncHealthz(mgr.GetCache()),
		healthz.WithEnable(
			towerPluginOptions.Enable,
			healthz.NewInformerSyncHealthz(towerPluginOptions.SharedFactory),
		),
	)

	klog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		klog.Fatalf("error while running manager: %s", err.Error())
	}
}

func setWebhookCert(k8sReader client.Reader, tlsCertDir string) {
	ctx := context.Background()
	k8sClient := k8sReader.(client.Client)

	secretReq := types.NamespacedName{
		Name:      constants.EverouteSecretName,
		Namespace: constants.EverouteSecretNamespace,
	}
	secret := &corev1.Secret{}

	// get and create secret
	if err := backoff.Retry(func() error {
		if err := k8sClient.Get(ctx, secretReq, secret); err == nil {
			if len(secret.Data["ca.crt"]) == 0 {
				_ = k8sClient.Delete(ctx, secret)
				return fmt.Errorf("invalid secret")
			}
		} else {
			// create secret
			secret = genSecret(secretReq)
			if err = k8sClient.Create(ctx, secret); err != nil {
				return err
			}
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 10)); err != nil {
		klog.Fatalf("fail to create secret after 10 tries. err: %s", err)
	}

	// write tls cert into file
	certPath, keyPath := cert.PathsForCertAndKey(tlsCertDir, "tls")
	if err := certutil.WriteCert(certPath, secret.Data["tls.crt"]); err != nil {
		klog.Fatalf("fail to write tls cert. err: %s", err)
	}
	if err := keyutil.WriteKey(keyPath, secret.Data["tls.key"]); err != nil {
		klog.Fatalf("fail to write tls key. err: %s", err)
	}
}

func genSecret(secretReq types.NamespacedName) *corev1.Secret {
	data := make(map[string][]byte)

	// create ca & caKey
	caConf := &cert.CertConfig{
		Config: certutil.Config{
			CommonName:   "everoute",
			Organization: []string{"Everoute"},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		PublicKeyAlgorithm: x509.RSA,
	}
	ca, caKey, _ := cert.NewCertificateAuthority(caConf)

	// sign a new tls cert
	tlsConf := &cert.CertConfig{
		Config: certutil.Config{
			CommonName:   "everoute",
			Organization: []string{"Everoute"},
			AltNames: certutil.AltNames{
				DNSNames: []string{"everoute-validator-webhook.kube-system.svc"},
				IPs:      []net.IP{net.ParseIP("127.0.0.1")},
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		PublicKeyAlgorithm: x509.RSA,
	}
	tls, tlsKey, _ := cert.NewCertAndKey(ca, caKey, tlsConf, time.Now().AddDate(100, 0, 0))
	tlsKeyByte, _ := keyutil.MarshalPrivateKeyToPEM(tlsKey)

	// set ca & tls into secret
	data["tls.crt"] = append(data["tls.crt"], cert.EncodeCertPEM(tls)...)
	data["tls.key"] = append(data["tls.key"], tlsKeyByte...)
	data["ca.crt"] = append(data["ca.crt"], cert.EncodeCertPEM(ca)...)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretReq.Name,
			Namespace: secretReq.Namespace,
		},
		Data: data,
		Type: "kubernetes.io/tls",
	}
}
