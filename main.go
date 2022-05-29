/*
Copyright 2022.

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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/jmespath/go-jmespath"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"os"

	"github.com/ooraini/ca-controllers/controllers"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	configv2 "github.com/ooraini/ca-controllers/api/v2"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(configv2.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "",
		"The controller will load its initial configuration from this file. "+
			"Omit this flag to use the default configuration values. "+
			"Command-line flags override configuration from this file.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	var err error
	ctrlConfig := configv2.ProjectConfig{}
	options := ctrl.Options{Scheme: scheme}
	if configFile != "" {
		options, err = options.AndFrom(ctrl.ConfigFile().AtPath(configFile).OfKind(&ctrlConfig))
		if err != nil {
			setupLog.Error(err, "unable to load the config file")
			os.Exit(1)
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = startControllers(mgr, ctrlConfig); err != nil {
		setupLog.Error(err, "unable to start controllers")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func startControllers(mgr ctrl.Manager, projectConfig configv2.ProjectConfig) error {

	var caCert *x509.Certificate
	var privateKey crypto.PrivateKey
	var err error

	if projectConfig.SignerEnabled {
		certPem, err := os.ReadFile(projectConfig.CaCertPath)
		if err != nil {
			return fmt.Errorf("unable to read certificate %s", projectConfig.CaCertPath)
		}

		keyPem, err := os.ReadFile(projectConfig.CaKeyPath)
		if err != nil {
			return fmt.Errorf("unable to read private key%s", projectConfig.CaKeyPath)
		}

		caPemBlock, _ := pem.Decode(certPem)
		if caPemBlock == nil {
			return fmt.Errorf("invalid certificate pem")
		}

		keyPemBlock, _ := pem.Decode(keyPem)
		if keyPemBlock == nil {
			return fmt.Errorf("invalid key pem")
		}

		caCert, err = x509.ParseCertificate(caPemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("unable to parse CA certificate")
		}

		if keyPemBlock.Type == "RSA PRIVATE KEY" {
			privateKey, err = x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
			if err != nil {
				return fmt.Errorf("unable to parse RSA key")
			}
		} else if keyPemBlock.Type == "EC PRIVATE KEY" {
			privateKey, err = x509.ParseECPrivateKey(keyPemBlock.Bytes)
			if err != nil {
				return fmt.Errorf("unable to parse EC key")
			}
		} else {
			return fmt.Errorf("unkown key type %s", keyPemBlock.Type)
		}
	}

	var rootCert *x509.Certificate
	if projectConfig.RootCA != nil {
		block, _ := pem.Decode(projectConfig.RootCA)
		rootCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("unable to parse root certificate")
		}
	}

	keyType := controllers.DefaultKeyType
	if projectConfig.KeyType != "" {
		_, ok := controllers.SupportedKeyTypes[projectConfig.KeyType]
		if !ok {
			return fmt.Errorf("unsupported key type %s", projectConfig.KeyType)
		}
		keyType = projectConfig.KeyType
	}

	if projectConfig.SignerName == "" {
		return fmt.Errorf("empty signer")
	}

	clusterDomain := controllers.DefaultClusterDomain
	if projectConfig.ClusterDomain != "" {
		// validate DNS
		clusterDomain = projectConfig.ClusterDomain
	}

	var gvkConfigs []controllers.GvkConfig

	for _, gvkConfig := range projectConfig.GvkConfigs {
		gvk := schema.GroupVersionKind{
			Group:   gvkConfig.Group,
			Version: gvkConfig.Version,
			Kind:    gvkConfig.Kind,
		}

		if gvkConfig.Jmes == "" {
			setupLog.Info("Empty JMES expression", "gvk", gvk.String())
			continue
		}

		jmesPath, err := jmespath.Compile(gvkConfig.Jmes)
		if err != nil {
			setupLog.Error(err, "could not compile JMESPath expression", "gvk", gvk.String())
			continue
		}

		objectSupport := controllers.ObjectSupport(gvkConfig.ObjectSupportDefault)
		if objectSupport.IsValid() != nil {
			setupLog.Info(fmt.Sprintf("invalid object support value '%s'", objectSupport), "gvk", gvk)
			objectSupport = controllers.ObjectSupportDisabled
		}

		gvkConfigs = append(gvkConfigs, controllers.GvkConfig{
			GroupVersionKind:     gvk,
			JMESPath:             jmesPath,
			DefaultObjectSupport: objectSupport,
		})
	}

	setupLog.Info(fmt.Sprintf("Starting with %d GVKs", len(gvkConfigs)))

	config := &controllers.Config{
		CaCert:                caCert,
		CaPrivateKey:          privateKey,
		SignerName:            projectConfig.SignerName,
		RootCACertificate:     rootCert,
		RootCAPem:             projectConfig.RootCA,
		CertificateDuration:   projectConfig.CertificateDuration.Duration,
		ClusterDomain:         clusterDomain,
		ClusterExternalDomain: projectConfig.ClusterExternalDomain,
		KeyType:               keyType,
		GvkConfigs:            gvkConfigs,
	}

	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return err
	}

	if projectConfig.ApproverEnabled {
		approver, err := controllers.NewApproverReconciler(
			mgr.GetClient(),
			mgr.GetScheme(),
			clientset,
			config)

		if err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "approver")
			return err
		}

		if err = approver.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "approver")
			return err
		}
	}

	if projectConfig.SignerEnabled {
		signer, err := controllers.NewSignerReconciler(mgr.GetClient(), mgr.GetScheme(), clientset, config)
		if err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "signer")
			return err
		}

		if err = signer.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "signer")
			return err
		}
	}

	secretReconciler, err := controllers.NewSecretReconciler(mgr.GetClient(), mgr.GetScheme(), config)

	if err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "secret")
		return err
	}

	if err = secretReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "secret")
		return err
	}

	return nil
}
