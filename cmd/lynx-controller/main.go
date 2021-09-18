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

package main

import (
	"context"
	"crypto/x509"
	"flag"
	"net"
	"time"

	"github.com/cenkalti/backoff"
	"k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	matev1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	clientsetscheme "github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset/scheme"
	endpointctrl "github.com/smartxworks/lynx/pkg/controller/endpoint"
	groupctrl "github.com/smartxworks/lynx/pkg/controller/group"
	policyctrl "github.com/smartxworks/lynx/pkg/controller/policy"
	"github.com/smartxworks/lynx/pkg/webhook"
	towerplugin "github.com/smartxworks/lynx/plugin/tower/pkg/register"
	"github.com/smartxworks/lynx/third_party/cert"
)

func init() {
	utilruntime.Must(corev1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(v1beta1.AddToScheme(clientsetscheme.Scheme))
	utilruntime.Must(networkingv1.AddToScheme(clientsetscheme.Scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var tlsCertDir string
	var serverPort int
	var leaderElectionNamespace string
	var towerPluginOptions towerplugin.Options

	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&tlsCertDir, "tls-certs-dir", "/etc/ssl/certs", "The certs dir for lynx webhook use.")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "", "The namespace in which the leader election configmap will be created.")
	flag.IntVar(&serverPort, "port", 9443, "The port for the Lynx controller to serve on.")
	klog.InitFlags(nil)
	towerplugin.InitFlags(&towerPluginOptions, nil, "plugins.tower.")
	flag.Parse()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  clientsetscheme.Scheme,
		MetricsBindAddress:      metricsAddr,
		Port:                    serverPort,
		LeaderElection:          enableLeaderElection,
		LeaderElectionNamespace: leaderElectionNamespace,
		LeaderElectionID:        "24d5749e.lynx.smartx.com",
		CertDir:                 tlsCertDir,
	})
	if err != nil {
		klog.Fatalf("unable to start manager: %s", err.Error())
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

	if err = (&policyctrl.PolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		ReadClient: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create policy controller: %s", err.Error())
	}

	// register validate handle
	setWebhookCert(mgr.GetAPIReader(), tlsCertDir)
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

	klog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		klog.Fatalf("error while running manager: %s", err.Error())
	}
}

func setWebhookCert(k8sReader client.Reader, tlsCertDir string) {
	ctx := context.Background()
	k8sClient := k8sReader.(client.Client)

	secretReq := types.NamespacedName{
		Name:      "lynx-controller-tls",
		Namespace: "kube-system",
	}
	secret := &corev1.Secret{}

	// get secret, if not existed, create a new one
	if err := backoff.Retry(func() error {
		if err := k8sClient.Get(ctx, secretReq, secret); err != nil {
			if errors.IsNotFound(err) {
				secret = GenSecret()
				if err = k8sClient.Create(ctx, secret); err != nil {
					return err
				}
			}
			return err
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 10)); err != nil {
		klog.Fatalf("fail to get secret after 10 tries. err: %s", err)
	}

	// update webhook
	webhookReq := types.NamespacedName{Name: "validator.lynx.smartx.com"}
	webhookObj := &v1beta1.ValidatingWebhookConfiguration{}
	if err := backoff.Retry(func() error {
		if err := k8sClient.Get(ctx, webhookReq, webhookObj); err != nil {
			return err
		}
		if len(webhookObj.Webhooks[0].ClientConfig.CABundle) > 0 {
			return nil
		}
		webhookObj.Webhooks[0].ClientConfig.CABundle = append(webhookObj.Webhooks[0].ClientConfig.CABundle, secret.Data["ca.crt"]...)
		return k8sClient.Update(ctx, webhookObj)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 10)); err != nil {
		klog.Fatalf("fail to update webhook after 10 tries. err: %s", err)
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

func GenSecret() *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: matev1.ObjectMeta{
			Name:      "lynx-controller-tls",
			Namespace: "kube-system",
		},
		Data: map[string][]byte{},
		Type: corev1.SecretTypeTLS,
	}

	// create ca & caKey
	caConf := &cert.CertConfig{
		Config: certutil.Config{
			CommonName:   "everoute",
			Organization: []string{"SmartX"},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		PublicKeyAlgorithm: x509.RSA,
	}
	ca, caKey, _ := cert.NewCertificateAuthority(caConf)
	caKeyByte, _ := keyutil.MarshalPrivateKeyToPEM(caKey)

	// sign a new tls cert
	tlsConf := &cert.CertConfig{
		Config: certutil.Config{
			CommonName:   "everoute",
			Organization: []string{"SmartX"},
			AltNames: certutil.AltNames{
				DNSNames: []string{"lynx-validator-webhook.kube-system.svc"},
				IPs:      []net.IP{net.ParseIP("127.0.0.1")},
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		PublicKeyAlgorithm: x509.RSA,
	}
	tls, tlsKey, _ := cert.NewCertAndKey(ca, caKey, tlsConf, time.Now().AddDate(100, 0, 0))
	tlsKeyByte, _ := keyutil.MarshalPrivateKeyToPEM(tlsKey)

	// set ca & tls into secret
	secret.Data["tls.crt"] = append(secret.Data["tls.crt"], cert.EncodeCertPEM(tls)...)
	secret.Data["tls.key"] = append(secret.Data["tls.key"], tlsKeyByte...)
	secret.Data["ca.crt"] = append(secret.Data["ca.crt"], cert.EncodeCertPEM(ca)...)
	secret.Data["ca.key"] = append(secret.Data["ca.key"], caKeyByte...)

	return secret
}
