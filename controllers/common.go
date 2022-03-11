package controllers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"math"
	"math/big"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch;update;patch;delete
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=update
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign;approve,resourceNames=ca-controllers.io/server
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch

type Config struct {
	CaCert                *x509.Certificate
	CaPrivateKey          crypto.PrivateKey
	SignerName            string
	RootCACertificate     *x509.Certificate
	RootCAPem             []byte
	CertificateDuration   time.Duration
	ClusterDomain         string
	ClusterExternalDomain string
	// Key type to use when generate new private keys.
	// Either RSA or EC
	KeyType string
}

const (
	DefaultKeyType               = "EC"
	DefaultClusterDomain         = "cluster.local"
	SecretNameMeta               = "ca-controllers.io/secret.metadata.name"
	SecretNamespaceMeta          = "ca-controllers.io/secret.metadata.namespace"
	ServiceNameMeta              = "ca-controllers.io/service.metadata.name"
	ServiceNamespaceMeta         = "ca-controllers.io/service.metadata.namespace"
	SignerNameAnnotation         = "ca-controllers.io/signerName"
	IncludeRootCAAnnotation      = "ca-controllers.io/include-root-ca"
	ControllerNameAnnotation     = "ca-controllers.io/controller"
	ServiceSupportControllerName = "servicesupport"
	IngressSupportControllerName = "ingresssupport"
	FinalizerName                = "ca-controllers.io/finalizer"

	ServiceSupportAnnotation string = "ca-controllers.io/servicesupport"
	ServiceSupportEnabled    string = "Enabled"
	ServiceSupportDisabled   string = "Disabled"
	// IngressSupportAnnotation is applied to either a namespace or an ingress.
	// On a namespace, the allowed values are:
	// IngressSupportWhenAnnotated
	// IngressSupportAutomatic
	// IngressSupportDisabled
	// On an ingress, the allowed values are "True" or "False".
	IngressSupportAnnotation    string = "ca-controllers.io/ingresssupport"
	IngressSupportWhenAnnotated string = "WhenAnnotated"
	IngressSupportAutomatic     string = "Automatic"
	IngressSupportDisabled      string = "Disabled"
)

var (
	SupportedKeyTypes = map[string]bool{
		"RSA": true,
		"EC":  true,
	}
	ignoreDeletesPredicate = predicate.Funcs{
		DeleteFunc: func(event event.DeleteEvent) bool {
			return false
		},
	}
)

type SecretReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Config         *Config
	ControllerName string
}

func NewSecretReconciler(client client.Client, scheme *runtime.Scheme, config *Config, controllerName string) *SecretReconciler {
	return &SecretReconciler{Client: client, Scheme: scheme, Config: config, ControllerName: controllerName}
}

// Returning nil,nil means continue
func (r *SecretReconciler) finalizer(ctx context.Context, req reconcile.Request) (*ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "unable to fetch secret")
			return &ctrl.Result{}, err
		}
	} else {
		if secret.ObjectMeta.DeletionTimestamp.IsZero() {
			if !controllerutil.ContainsFinalizer(secret, FinalizerName) {
				controllerutil.AddFinalizer(secret, FinalizerName)
				if err = r.Update(ctx, secret); err != nil {
					log.Error(err, "unable to add finalizer")
					return &ctrl.Result{}, err
				}
			}
		} else {
			if controllerutil.ContainsFinalizer(secret, FinalizerName) {
				list := &certv1.CertificateSigningRequestList{}
				err := r.List(ctx, list, client.MatchingLabels{SecretNamespaceMeta: secret.Namespace, SecretNameMeta: secret.Name})
				if err != nil {
					log.Error(err, "unable to list CSRs")
					return &ctrl.Result{}, err
				}
				for _, csr := range list.Items {
					csr := csr
					log.V(1).Info("deleting csr", "csr", csr.Name)
					if err = r.Delete(ctx, &csr); err != nil && !errors.IsNotFound(err) {
						log.Error(err, "unable to delete CSR")
					}
				}

				controllerutil.RemoveFinalizer(secret, FinalizerName)
				if err = r.Update(ctx, secret); err != nil {
					log.Error(err, "unable to remove finalizer")
					return &ctrl.Result{}, err
				}
				log.Info("secret finalized")
			}

			return &ctrl.Result{}, nil
		}
	}

	return nil, nil
}

func (r *SecretReconciler) namespaceSigner(ctx context.Context, name string, namespace *corev1.Namespace) (*ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)
	err := r.Get(ctx, types.NamespacedName{Name: name}, namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("object not found")
			return &ctrl.Result{}, nil
		}
		log.Error(err, "failed to load namespace")
		return &ctrl.Result{}, err
	}

	namespaceSigner, ok := namespace.Annotations[SignerNameAnnotation]
	if !ok || namespaceSigner != r.Config.SignerName {
		log.V(1).Info("namespace is not annotated with the signerName")
		return &ctrl.Result{}, nil
	}

	return nil, nil
}

func findSecretFromCsr(csr *certv1.CertificateSigningRequest) []reconcile.Request {
	namespace := csr.Labels[SecretNamespaceMeta]
	name := csr.Labels[SecretNameMeta]

	if namespace != "" && name != "" {
		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Name:      name,
					Namespace: namespace,
				},
			},
		}
	}

	return nil
}

func signerPredicate(signerName string) predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			switch event.Object.(type) {
			case *certv1.CertificateSigningRequest:
				return event.Object.(*certv1.CertificateSigningRequest).Spec.SignerName == signerName
			default:
				return true
			}
		},
		UpdateFunc: func(event event.UpdateEvent) bool {
			switch event.ObjectNew.(type) {
			case *certv1.CertificateSigningRequest:
				return event.ObjectNew.(*certv1.CertificateSigningRequest).Spec.SignerName == signerName
			default:
				return true
			}
		},
		DeleteFunc: func(event event.DeleteEvent) bool {
			switch event.Object.(type) {
			case *certv1.CertificateSigningRequest:
				return event.Object.(*certv1.CertificateSigningRequest).Spec.SignerName == signerName
			default:
				return true
			}
		},
	}
}

func (r *SecretReconciler) reconcileSecret(ctx context.Context, req ctrl.Request, owner metav1.Object, hosts []string, includeRoot bool) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	secret := &corev1.Secret{}
	err := r.Get(ctx, req.NamespacedName, secret)
	// 1. Create or retrieve secret
	if err != nil {
		if errors.IsNotFound(err) {
			key, err := generateKey(r.Config.KeyType)
			if err != nil {
				log.Error(err, "unable to generate key")
				return ctrl.Result{}, err
			}

			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
					Labels:    nil,
					Annotations: map[string]string{
						ControllerNameAnnotation: r.ControllerName,
					},
				},
				Data: map[string][]byte{
					"tls.key": toPem(key),
					"tls.crt": nil,
					"ca.crt":  nil,
				},
				Type: "kubernetes.io/tls",
			}

			_ = controllerutil.SetOwnerReference(owner, secret, r.Scheme)

			if includeRoot {
				secret.Data["ca.crt"] = r.Config.RootCAPem
			}

			if err = r.Create(ctx, secret); err != nil {
				log.Error(err, "unable to create secret")
				return ctrl.Result{}, err
			}

			log.Info("created")
		} else {
			log.Error(err, "failed to load object")
			return ctrl.Result{}, err
		}
	}

	secretControllerName, ok := secret.Annotations[ControllerNameAnnotation]
	if !ok {
		log.Info(fmt.Sprintf("secret with no %s annotation, delete the secret to reconcile", ControllerNameAnnotation))
		return ctrl.Result{}, nil
	}

	if ok && secretControllerName != r.ControllerName {
		log.Info("secret is managed by a different controller, make sure that a secret is not referred to by more than one resource")
		return ctrl.Result{}, nil
	}

	keyPem := secret.Data["tls.key"]
	csrList := &certv1.CertificateSigningRequestList{}
	err = r.List(ctx, csrList,
		client.MatchingLabels{SecretNamespaceMeta: secret.Namespace, SecretNameMeta: secret.Name})

	if err != nil {
		log.Error(err, "unable to list CSRs")
		return ctrl.Result{}, err
	}

	if keyPem == nil {
		for _, csr := range csrList.Items {
			err = r.Delete(ctx, &csr)
			if err != nil {
				log.Error(err, "unable to delete csr")
				return ctrl.Result{}, err
			}
		}
		log.Info("secret with existing csr but no key, deleting all CSRs")
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second}, nil
	}

	block, _ := pem.Decode(keyPem)
	privateKey, err := parseKey(block)
	if err != nil {
		log.Info("unable to parse private key")
		return ctrl.Result{}, err
	}

	ownerSet := false
	for _, ownerRef := range secret.GetOwnerReferences() {
		if ownerRef.UID == owner.GetUID() {
			ownerSet = true
		}
	}

	if ownerSet == false {
		_ = controllerutil.SetOwnerReference(owner, secret, r.Scheme)
		err := r.Update(ctx, secret)
		if err != nil {
			log.Error(err, "unable to update owner reference")
			return ctrl.Result{}, err
		}
	}

	labels := map[string]string{
		SecretNamespaceMeta: secret.Namespace,
		SecretNameMeta:      secret.Name,
	}

	createCsr := func() (*certv1.CertificateSigningRequest, error) {
		template := &x509.CertificateRequest{
			SignatureAlgorithm: 0,
			Subject: pkix.Name{
				CommonName: hosts[0],
			},
			DNSNames: hosts,
		}

		csrDer, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)

		if err != nil {
			log.Info("unable to create x509 csr")
			return nil, err
		}

		csrPem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDer,
		})

		sum := sha1.Sum(csrDer)
		suffix := hex.EncodeToString(sum[:])[:8]

		return &certv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:        fmt.Sprintf("%s-%s-%s", secret.Namespace, secret.Name, suffix),
				Labels:      labels,
				Annotations: nil,
			},
			Spec: certv1.CertificateSigningRequestSpec{
				Request:           csrPem,
				SignerName:        r.Config.SignerName,
				ExpirationSeconds: nil,
				Usages: []certv1.KeyUsage{
					certv1.UsageDigitalSignature,
					certv1.UsageKeyEncipherment,
					certv1.UsageServerAuth,
				},
			},
		}, nil
	}

	var bestCSR *certv1.CertificateSigningRequest
	var bestCertificate *x509.Certificate
	pendingCSRs := 0

	// Delete expired CSRs and CSRs with mis-matched DNS names
	for _, csr := range csrList.Items {
		csr := csr
		block, _ = pem.Decode(csr.Spec.Request)
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			panic("invalid CSR: " + csr.Name)
		}

		if !reflect.DeepEqual(request.DNSNames, hosts) {
			log.V(1).Info("deleting CSR with wrong hosts", "csr", csr.Name)
			err = r.Delete(ctx, &csr)
			if err != nil {
				log.Error(err, "unable to delete csr")
				return ctrl.Result{}, err
			}
			continue
		}

		if csr.Status.Certificate == nil {
			pendingCSRs = pendingCSRs + 1
			continue
		}

		block, _ = pem.Decode(csr.Status.Certificate)
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Info("deleting csr with invalid certificate")
			err = r.Delete(ctx, &csr)
			if err != nil {
				log.Error(err, "unable to delete csr")
				return ctrl.Result{}, err
			}

			continue
		}

		// expired
		if time.Now().UTC().After(certificate.NotAfter) {
			log.V(1).Info("deleting csr with expired certificate", "csr", csr.Name)
			err = r.Delete(ctx, &csr)
			if err != nil {
				log.Error(err, "unable to delete csr")
				return ctrl.Result{}, err
			}
			continue
		}

		if bestCSR == nil {
			bestCSR = &csr
			bestCertificate = certificate
		} else {
			if certificate.NotAfter.After(bestCertificate.NotAfter) {
				bestCSR = &csr
				bestCertificate = certificate
			}
		}
	}

	if bestCSR == nil && pendingCSRs > 0 {
		log.V(1).Info("pending csr, waiting")
		return ctrl.Result{}, nil
	}

	if bestCSR == nil && pendingCSRs == 0 {
		log.Info("no pending CSRs, creating a new one")
		csr, err := createCsr()
		if err != nil {
			log.Error(err, "unable to create csr")
			return ctrl.Result{}, err
		}

		err = r.Create(ctx, csr)
		if err != nil {
			log.Info("unable to create csr")
			return ctrl.Result{}, err
		}

		log.Info("csr created", "csr", csr.Name)
		return ctrl.Result{}, nil
	}

	if !reflect.DeepEqual(bestCSR.Status.Certificate, secret.Data["tls.crt"]) {
		log.Info("replacing certificate in secret", "csr", bestCSR.Name)
		if bestCSR.Status.Certificate == nil {
			panic(bestCSR.Name)
		}
		secret.Data["tls.crt"] = bestCSR.Status.Certificate
		if err = r.Update(ctx, secret); err != nil {
			log.Error(err, "unable to update secret")
			return ctrl.Result{}, err
		}
	}

	if pendingCSRs > 0 {
		return ctrl.Result{}, nil
	}

	// Renew
	certDuration := bestCertificate.NotAfter.Sub(bestCertificate.NotBefore)
	renewTime := bestCertificate.NotAfter.Add(-(certDuration / 10))

	now := time.Now().UTC()
	if now.After(renewTime) {
		csr, err := createCsr()
		if err != nil {
			log.Error(err, "unable to create csr")
			return ctrl.Result{}, err
		}

		log.Info("renewing certificate by creating a new csr", "csr", csr.Name)

		err = r.Create(ctx, csr)
		if err != nil {
			log.Info("unable to create csr")
			return ctrl.Result{}, err
		}

		log.Info("csr created", "csr", csr.Name)
		return ctrl.Result{}, nil
	}

	log.V(1).Info(fmt.Sprintf("renewTime: '%s'", renewTime.String()))
	return ctrl.Result{RequeueAfter: renewTime.Sub(now)}, nil
}

func toPem(key crypto.PrivateKey) []byte {
	switch key.(type) {
	case *rsa.PrivateKey:
		rsaKey := key.(*rsa.PrivateKey)
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}
		return pem.EncodeToMemory(block)
	case *ecdsa.PrivateKey:
		//
		ecdsaKey := key.(*ecdsa.PrivateKey)
		keyDer, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			panic("cannot marshal ec key")
		}

		block := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyDer,
		}
		return pem.EncodeToMemory(block)
	default:
		panic("unknown key type")
	}
}

func generateKey(keyType string) (crypto.PrivateKey, error) {
	if keyType == "RSA" {
		return rsa.GenerateKey(rand.Reader, 2048)
	} else if keyType == "EC" {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		panic("unknown key type")
	}
}

func parseKey(block *pem.Block) (crypto.PrivateKey, error) {
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	} else {
		panic("unknown key type")
	}

}

// Returns PEM encoded certificate
func createCertificate(csr *x509.CertificateRequest, duration time.Duration, parent *x509.Certificate, privateKey crypto.PrivateKey) ([]byte, error) {

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	maxSerial := big.NewInt(math.MaxInt64)
	serialNumber, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(duration)
	if notAfter.After(parent.NotAfter) {
		notAfter = parent.NotAfter
	}

	CertTemplate := &x509.Certificate{
		SignatureAlgorithm: parent.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		IsCA:               false,
		DNSNames:           csr.DNSNames,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, CertTemplate, parent, CertTemplate.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parent.Raw})...), nil
}
