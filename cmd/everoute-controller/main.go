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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cenkalti/backoff"
	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	ipamctrl "github.com/everoute/ipam/pkg/controller"
	ipamcron "github.com/everoute/ipam/pkg/cron"
	admv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	podv1alpha1 "github.com/everoute/everoute/pkg/apis/pod/v1alpha1"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	"github.com/everoute/everoute/pkg/constants"
	cniconst "github.com/everoute/everoute/pkg/constants/cni"
	"github.com/everoute/everoute/pkg/controller/common"
	endpointctrl "github.com/everoute/everoute/pkg/controller/endpoint"
	groupctrl "github.com/everoute/everoute/pkg/controller/group"
	ctrlipam "github.com/everoute/everoute/pkg/controller/ipam"
	"github.com/everoute/everoute/pkg/controller/k8s"
	ctrlpolicy "github.com/everoute/everoute/pkg/controller/policy"
	"github.com/everoute/everoute/pkg/healthz"
	"github.com/everoute/everoute/pkg/ipam"
	"github.com/everoute/everoute/pkg/metrics"
	"github.com/everoute/everoute/pkg/webhook"
	towerplugin "github.com/everoute/everoute/plugin/tower/pkg/register"
	"github.com/everoute/everoute/third_party/cert"
)

var opts *Options

func init() {
	utilruntime.Must(corev1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(admv1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(networkingv1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(appsv1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(ipamv1alpha1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(podv1alpha1.AddToScheme(clientsetscheme.Scheme))
}

func main() {
	var disableAutoTLS bool
	opts = NewOptions()
	var towerPluginOptions towerplugin.Options

	flag.BoolVar(&disableAutoTLS, "disable-auto-tls", false, "Disable auto tls cert generate for webhook.")
	flag.StringVar(&opts.metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.BoolVar(&opts.enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&opts.tlsCertDir, "tls-certs-dir", "/etc/ssl/certs", "The certs dir for everoute webhook use.")
	flag.StringVar(&opts.namespace, "namespace", "", "The namespace which everoute deploy in.")
	flag.IntVar(&opts.serverPort, "port", 9443, "The port for the Everoute controller to serve on.")
	flag.StringVar(&opts.serverAddr, "host", "", "The host for the Everoute controller to serve on.")

	klog.InitFlags(nil)
	towerplugin.InitFlags(&towerPluginOptions, nil, "plugins.tower.")
	flag.Parse()

	ctrl.SetLogger(klog.Background())
	stopCtx := ctrl.SetupSignalHandler()
	if err := opts.complete(); err != nil {
		klog.Fatalf("Failed to complete Options, err: %v", err)
	}

	config := ctrl.GetConfigOrDie()
	config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(constants.ControllerRuntimeQPS, constants.ControllerRuntimeBurst)
	if opts.getAPIServer() != "" {
		config.Host = opts.getAPIServer()
	}

	s := kwebhook.NewServer(kwebhook.Options{
		Host:    opts.serverAddr,
		Port:    opts.serverPort,
		CertDir: opts.tlsCertDir,
		TLSOpts: []func(*tls.Config){func(conf *tls.Config) { conf.MinVersion = tls.VersionTLS13 }},
	})

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                  clientsetscheme.Scheme,
		MetricsBindAddress:      opts.metricsAddr,
		Logger:                  klogr.New(),
		LeaderElection:          opts.enableLeaderElection,
		LeaderElectionNamespace: opts.namespace,
		LeaderElectionID:        "24d5749e.leader-election.everoute.io",
		WebhookServer:           s,
	})
	if err != nil {
		klog.Fatalf("unable to start manager: %s", err.Error())
	}

	controllerMetric := metrics.NewControllerMetric()
	controllerMetric.Init()

	if !disableAutoTLS {
		// set secret and webhook
		setWebhookCert(mgr.GetAPIReader())
		if err = (&common.WebhookReconciler{
			Client:    mgr.GetClient(),
			Scheme:    mgr.GetScheme(),
			Namespace: opts.namespace,
		}).SetupWithManager(mgr); err != nil {
			klog.Fatalf("unable to create webhook controller: %s", err.Error())
		}
	}

	// endpoint controller sync endpoint status from agentinfo.
	if err = (&endpointctrl.EndpointReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		IPMigrateCount: controllerMetric.GetIPMigrateCount(),
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

	if opts.IsEnableCNI() {
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

		if opts.IsEnableProxy() {
			if err = (&k8s.EndpointsReconcile{
				APIReader: mgr.GetAPIReader(),
				Client:    mgr.GetClient(),
				Scheme:    mgr.GetScheme(),
			}).SetupWithManager(mgr); err != nil {
				klog.Fatalf("unable to create endpoints controller: %s", err.Error())
			}
			klog.Info("start endpoints controller")
		}

		if opts.IsEnableOverlay() {
			if err = (&k8s.NodeReconciler{
				Client:        mgr.GetClient(),
				Scheme:        mgr.GetScheme(),
				GwEpNamespace: os.Getenv(constants.NamespaceNameENV),
			}).SetupWithManager(mgr); err != nil {
				klog.Fatalf("unable to create node controller: %v", err)
			}
			klog.Info("start node controller")
		}

		if opts.useEverouteIPAM() {
			startIPAM(stopCtx, mgr)
		}
	} else {
		if err := (&endpointctrl.StrictMacController{
			Client: mgr.GetClient(),
		}).SetupWithManager(mgr); err != nil {
			klog.Fatalf("unable to create strictMac endpoint controller %s", err)
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
	controllerMetric.InstallHandler(mgr.GetWebhookServer().Register)
	controllerMetric.Run(stopCtx)

	klog.Info("starting manager")
	if err := mgr.Start(stopCtx); err != nil {
		klog.Fatalf("error while running manager: %s", err.Error())
	}
}

func setWebhookCert(k8sReader client.Reader) {
	ctx := context.Background()
	k8sClient := k8sReader.(client.Client)

	secretReq := types.NamespacedName{
		Name:      constants.EverouteSecretName,
		Namespace: opts.namespace,
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
	certPath, keyPath := cert.PathsForCertAndKey(opts.tlsCertDir, "tls")
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

	webhookDNS := fmt.Sprintf("everoute-validator-webhook.%s.svc", opts.namespace)
	// sign a new tls cert
	tlsConf := &cert.CertConfig{
		Config: certutil.Config{
			CommonName:   "everoute",
			Organization: []string{"Everoute"},
			AltNames: certutil.AltNames{
				DNSNames: []string{webhookDNS},
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

func startIPAM(ctx context.Context, mgr ctrl.Manager) {
	var err error
	if err = (&ipamv1alpha1.IPPool{}).SetupWebhookWithManager(mgr); err != nil {
		klog.Fatalf("unable to create ippool webhook %v", err)
	}

	selfNs := os.Getenv(constants.NamespaceNameENV)
	if err = (&ctrlipam.Reconciler{
		Client:       mgr.GetClient(),
		GWIPPoolNs:   selfNs,
		GWIPPoolName: cniconst.GwIPPoolName,
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create ipam controller %v", err)
	}

	if err = (&ipamctrl.STSReconciler{
		Client: mgr.GetClient(),
	}).SetUpWithManager(mgr); err != nil {
		klog.Fatalf("unable to create ipam statefulset controller %v", err)
	}

	if opts.getIPAMCleanPeriod() <= 0 {
		klog.Fatalf("invalid ipam stale ip clean period %d", opts.getIPAMCleanPeriod())
	}
	cleanStaleIP := ipamcron.NewCleanStaleIP(time.Duration(opts.getIPAMCleanPeriod())*time.Minute, mgr.GetClient(), mgr.GetAPIReader())
	cleanStaleIP.RegistryCleanFunc(ipam.NewCleanStaleIP(selfNs, cniconst.GwIPPoolName, selfNs).Process)
	cleanStaleIP.Run(ctx)
}
