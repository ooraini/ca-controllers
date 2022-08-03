package controllers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/go-logr/logr"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"time"
)

type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Config *Config
}

func NewSecretReconciler(client client.Client, scheme *runtime.Scheme, config *Config) (*SecretReconciler, error) {
	return &SecretReconciler{
		Client: client,
		Scheme: scheme,
		Config: config,
	}, nil
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	log.V(1).Info("request received")

	// Check finalizer
	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "unable to fetch secret")
			return ctrl.Result{}, err
		}
	}

	if !secret.ObjectMeta.DeletionTimestamp.IsZero() && controllerutil.ContainsFinalizer(secret, FinalizerName) {
		csr := &certv1.CertificateSigningRequest{}
		csrName := fmt.Sprintf("%s-%s", secret.Namespace, secret.Name)
		err := r.Get(ctx, types.NamespacedName{Name: csrName}, csr)

		if err != nil && !errors.IsNotFound(err) {
			log.Error(err, "unable to fetch csr")
			return ctrl.Result{}, err
		}

		err = r.Delete(ctx, csr)
		if err != nil && !errors.IsNotFound(err) {
			log.Error(err, "unable to delete csr")
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(secret, FinalizerName)
		if err = r.Update(ctx, secret); err != nil {
			log.Error(err, "unable to remove finalizer")
			return ctrl.Result{}, err
		}

		log.V(1).Info("finalized")
		return ctrl.Result{}, nil
	}

	// Check singer
	namespace := &corev1.Namespace{}
	err := r.Get(ctx, types.NamespacedName{Name: req.Namespace}, namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to load namespace")
		return ctrl.Result{}, err
	}

	if signer := namespace.Annotations[SignerNameAnnotation]; signer != r.Config.SignerName {
		log.V(1).Info("namespace is not annotated with the signerName")
		return ctrl.Result{}, nil
	}

	// List resources
	var reconcileRequests []SecretReconcileRequest = nil

	for _, gvkConfig := range r.Config.GvkConfigs {
		log := log.WithValues("gvk", gvkConfig.GroupVersionKind)
		requests, err := r.listSecretReconcileRequests(ctx, log, namespace, gvkConfig)
		if err != nil {
			log.Error(err, "unable to process GVK")
			return ctrl.Result{}, err
		}

		for _, request := range requests {
			if request.secretName == req.Name && request.tracked {
				reconcileRequests = append(reconcileRequests, request)
			} /*else if request.secretName == req.Name { // FOR DEBUGGING
				log.V(1).Info("untracked object with secret reference",
					"object_name", request.object.GetName(),
				)
			}*/
		}
	}

	// Reconcile or ignore
	if len(reconcileRequests) == 0 {
		log.V(1).Info("no resource with reference to secret")
		return reconcile.Result{}, nil
	}

	if len(reconcileRequests) > 1 {
		log.Info(fmt.Sprintf("%d resources refer to the same secret, ignoreing", len(reconcileRequests)))
		return reconcile.Result{}, nil
	}

	owner := reconcileRequests[0].object
	includeRoot := reconcileRequests[0].includeRoot
	hosts := reconcileRequests[0].hosts

	// Create the secret if it doesn't exist
	if secret.Name == "" {
		key, err := generateKey(r.Config.KeyType)
		if err != nil {
			log.Error(err, "unable to generate key")
			return ctrl.Result{}, err
		}

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.Name,
				Namespace: req.Namespace,
				Labels: map[string]string{
					ManagedByLabelKey: ManagedByLabelValue,
				},
				Annotations: map[string]string{
					NameAnnotation: owner.GetName(),
				},
			},
			Data: map[string][]byte{
				"tls.key": toPem(key),
				"tls.crt": nil,
			},
			Type: "kubernetes.io/tls",
		}

		_ = controllerutil.SetOwnerReference(owner, secret, r.Scheme)

		if includeRoot && r.Config.RootCAPem != nil {
			secret.Data["ca.crt"] = r.Config.RootCAPem
		}

		if err = r.Create(ctx, secret); err != nil {
			log.Error(err, "unable to create secret")
			return ctrl.Result{}, err
		}

		log.Info("created")
	}

	if secret.Labels[ManagedByLabelKey] != ManagedByLabelValue {
		log.V(1).Info("not managed by ca-controllers, ignoring")
		return ctrl.Result{}, nil
	}

	if secret.Type != corev1.SecretTypeTLS {
		log.Info("incorrect secret type, deleting")
		if err = r.Delete(ctx, secret); err != nil {
			log.Error(err, "unable to delete secret")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second}, nil
	}

	// Ensure privateKey
	var privateKey crypto.PrivateKey
	{
		keyPem := secret.Data["tls.key"]

		if keyPem == nil || len(keyPem) == 0 {
			log.Info("secret with no tls.key")
			key, err := generateKey(r.Config.KeyType)
			if err != nil {
				log.Error(err, "unable to generate key")
				return ctrl.Result{}, err
			}
			secret.Data["tls.key"] = toPem(key)
			secret.Data["tls.crt"] = nil
			secret.Annotations = map[string]string{
				NameAnnotation: owner.GetName(),
			}

			if err = r.Update(ctx, secret); err != nil {
				log.Error(err, "unable to update private key")
				return ctrl.Result{}, err
			}

			keyPem = secret.Data["tls.key"]
		}

		block, _ := pem.Decode(keyPem)
		if block == nil {
			log.Error(err, "unable to decode PEM")
			if err = r.Delete(ctx, secret); err != nil {
				log.Error(err, "unable to delete secret")
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second}, nil
		}
		err = nil
		privateKey, err = parseKey(block)
		if err != nil {
			log.Error(err, "unable to parse private key, deleting secret")
			if err = r.Delete(ctx, secret); err != nil {
				log.Error(err, "unable to delete secret")
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second}, nil
		}
	}

	// Ensure secret metadata
	{
		wrongRoot := includeRoot && !bytes.Equal(secret.Data["ca.crt"], r.Config.RootCAPem)
		noOwner := true
		noFinalizer := secret.ObjectMeta.DeletionTimestamp.IsZero() &&
			!controllerutil.ContainsFinalizer(secret, FinalizerName)

		for _, ownerRef := range secret.GetOwnerReferences() {
			if ownerRef.UID == owner.GetUID() {
				noOwner = false
			}
		}

		if owner.GetName() != secret.Annotations[NameAnnotation] ||
			wrongRoot ||
			noOwner ||
			noFinalizer {

			if secret.Annotations == nil {
				secret.Annotations = map[string]string{}
			}

			secret.Annotations[NamespaceAnnotation] = owner.GetNamespace()
			controllerutil.AddFinalizer(secret, FinalizerName)
			_ = controllerutil.SetOwnerReference(owner, secret, r.Scheme)
			if includeRoot {
				secret.Data["ca.crt"] = r.Config.RootCAPem
			}
			if err = r.Update(ctx, secret); err != nil {
				log.Error(err, "unable to update owner reference")
				return ctrl.Result{}, err
			}
			log.V(1).Info("metadata updated")
		}
	}

	csrName := fmt.Sprintf("%s-%s", secret.Namespace, secret.Name)
	csr := &certv1.CertificateSigningRequest{}
	if err := r.Get(ctx, types.NamespacedName{Name: csrName}, csr); err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "unable to fetch csr")
			return ctrl.Result{}, err
		}

		csr, err = newCsr(csrName, secret.Name, secret.Namespace, r.Config.SignerName, hosts, privateKey)
		if err != nil {
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, csr); err != nil {
			log.Error(err, "unable to create csr")
			return ctrl.Result{}, err
		}
	}

	// Ensure DNS SANs
	{
		block, _ := pem.Decode(csr.Spec.Request)
		request, err := x509.ParseCertificateRequest(block.Bytes)
		check(err)

		if !sameStringSlice(request.DNSNames, hosts) {
			log.V(1).Info("deleting csr with wrong SANs")
			if err = r.Delete(ctx, csr); err != nil {
				log.Error(err, "unable to delete csr")
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second}, nil
		}
	}

	if csr.Status.Certificate == nil {
		log.V(1).Info("pending csr")
		return ctrl.Result{}, nil
	}

	if !bytes.Equal(csr.Status.Certificate, secret.Data["tls.crt"]) {
		log.Info("replacing certificate in secret", "csr", csr.Name)
		secret.Data["tls.crt"] = csr.Status.Certificate
		if err = r.Update(ctx, secret); err != nil {
			log.Error(err, "unable to update secret")
			return ctrl.Result{}, err
		}
	}

	// Renewal
	block, _ := pem.Decode(csr.Status.Certificate)
	certificate, err := x509.ParseCertificate(block.Bytes)
	check(err)

	certDuration := certificate.NotAfter.Sub(certificate.NotBefore)
	if r.Config.CertificateDuration < certDuration {
		certDuration = r.Config.CertificateDuration
	}

	renewTime := certificate.NotAfter.Add(-(certDuration / 10))

	now := time.Now().UTC()
	if now.After(renewTime) {
		if err := r.Client.Delete(ctx, csr); err != nil {
			log.Error(err, "unable to delete csr")
			return ctrl.Result{}, err
		}

		csr, err := newCsr(csrName, secret.Name, secret.Namespace, r.Config.SignerName, hosts, privateKey)
		if err != nil {
			log.Error(err, "unable to create csr")
			return ctrl.Result{}, err
		}

		err = r.Create(ctx, csr)
		if err != nil {
			log.Error(err, "unable to create csr")
			return ctrl.Result{}, err
		}

		log.V(1).Info("csr submitted")
		return ctrl.Result{}, nil
	}

	log.V(1).Info(fmt.Sprintf("renewing certificate at: '%s'", renewTime.String()))
	return ctrl.Result{RequeueAfter: renewTime.Sub(now)}, nil
}

func extractHosts(object map[string]interface{}) []string {
	hostsInt, ok := object["hosts"]
	if !ok {
		return nil
	}

	hosts, ok := hostsInt.([]interface{})

	if !ok {
		return nil
	}

	var hostsAsStrings []string

	for _, host := range hosts {
		if hostString, ok := host.(string); ok && hostString != "" && checkDomain(hostString) == nil {
			hostsAsStrings = append(hostsAsStrings, hostString)
		}
	}

	return hostsAsStrings
}

func uniqueStrings(slice []string) []string {
	if len(slice) == 0 {
		return nil
	}

	set := make(map[string]struct{})

	for _, item := range slice {
		set[item] = struct{}{}
	}

	var result []string
	for k := range set {
		result = append(result, k)
	}

	return result
}

func extractSecretName(object map[string]interface{}) string {
	secretNameInt, ok := object["secretName"]
	if !ok {
		return ""
	}

	secretName, ok := secretNameInt.(string)

	if !ok {
		return ""
	}

	return secretName
}

func (r *SecretReconciler) listSecretReconcileRequests(ctx context.Context, log logr.Logger, namespace client.Object, gvkConfig GvkConfig) ([]SecretReconcileRequest, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvkConfig.GroupVersionKind)

	if err := r.List(ctx, list, client.InNamespace(namespace.GetName())); err != nil {
		return nil, err
	}

	var result []SecretReconcileRequest
	for _, obj := range list.Items {
		obj := obj

		tracked := false
		switch gvkConfig.DefaultObjectSupport {
		case ObjectSupportDisabled:
			tracked = false
		case ObjectSupportEnabled:
			_, ok := obj.GetAnnotations()[ObjectIgnore]
			tracked = !ok
		default:
			_, ok := obj.GetAnnotations()[ObjectAccept]
			tracked = ok
		}

		obj.Object["clusterDomain"] = r.Config.ClusterDomain
		if r.Config.ClusterExternalDomain != "" {
			obj.Object["clusterExternalDomain"] = r.Config.ClusterExternalDomain
		}

		search, err := gvkConfig.JMESPath.Search(obj.Object)
		if err != nil {
			return nil, err
		}

		for _, tlsRequest := range extractTlsRequests(search) {
			_, includeRoot := obj.GetAnnotations()[IncludeRootCAAnnotation]
			result = append(result, SecretReconcileRequest{
				object:      &obj,
				tracked:     tracked,
				includeRoot: includeRoot,
				secretName:  tlsRequest.secretName,
				hosts:       tlsRequest.hosts,
			})
		}
	}

	return result, nil
}

func extractTlsRequests(search interface{}) []TlsRequest {
	requests := make(map[string]TlsRequest)

	switch search.(type) {
	case []interface{}:
		list := search.([]interface{})
		for _, s := range list {
			s := s
			if item, ok := s.(map[string]interface{}); ok {
				secretName := extractSecretName(item)
				hosts := extractHosts(item)
				if secretName != "" && len(hosts) > 0 {
					old, ok := requests[secretName]
					if ok {
						old.hosts = append(old.hosts, hosts...)
						old.hosts = uniqueStrings(old.hosts)
					} else {
						requests[secretName] = TlsRequest{
							secretName: secretName,
							hosts:      uniqueStrings(hosts),
						}
					}
				}
			}
		}
	case map[string]interface{}:
		item := search.(map[string]interface{})
		secretName := extractSecretName(item)
		hosts := extractHosts(item)
		if secretName != "" && len(hosts) > 0 {
			old, ok := requests[secretName]
			if ok {
				old.hosts = append(old.hosts, hosts...)
				old.hosts = uniqueStrings(old.hosts)
			} else {
				requests[secretName] = TlsRequest{
					secretName: secretName,
					hosts:      uniqueStrings(hosts),
				}
			}
		}
	}

	var out []TlsRequest
	for _, v := range requests {
		out = append(out, v)
	}

	return out
}

type TlsRequest struct {
	secretName string
	hosts      []string
}
type SecretReconcileRequest struct {
	object      *unstructured.Unstructured
	tracked     bool
	includeRoot bool
	secretName  string
	hosts       []string
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctrlBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Watches(
			&source.Kind{Type: &corev1.Namespace{}},
			handler.EnqueueRequestsFromMapFunc(r.findSecretsInNamespace),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&source.Kind{Type: &certv1.CertificateSigningRequest{}},
			handler.EnqueueRequestsFromMapFunc(r.findSecretFromCsr),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Named("secret")

	for _, gvkConfig := range r.Config.GvkConfigs {
		gvkConfig := gvkConfig
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(gvkConfig.GroupVersionKind)
		ctrlBuilder = ctrlBuilder.Watches(
			&source.Kind{Type: u},
			handler.EnqueueRequestsFromMapFunc(func(object client.Object) []reconcile.Request {
				obj := object.(*unstructured.Unstructured)

				search, err := gvkConfig.JMESPath.Search(obj.Object)
				if err != nil {
					return nil
				}

				var result []reconcile.Request

				for _, tlsRequest := range extractTlsRequests(search) {
					result = append(result, reconcile.Request{NamespacedName: types.NamespacedName{
						Name:      tlsRequest.secretName,
						Namespace: object.GetNamespace(),
					}})
				}

				return result
			}),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		)
	}

	return ctrlBuilder.Complete(r)
}

func (r *SecretReconciler) findSecretsInNamespace(object client.Object) []reconcile.Request {
	namespace := object.(*corev1.Namespace)

	var requests []reconcile.Request

	for _, gvkConfig := range r.Config.GvkConfigs {
		tlsRequests, err := r.listSecretReconcileRequests(context.Background(), logr.Discard(), namespace, gvkConfig)
		if err == nil {
			for _, tlsRequest := range tlsRequests {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      tlsRequest.secretName,
						Namespace: namespace.Name,
					},
				})
			}
		}
	}

	return requests
}

func (r *SecretReconciler) findSecretFromCsr(object client.Object) []reconcile.Request {
	csr := object.(*certv1.CertificateSigningRequest)
	namespace := csr.Labels[NamespaceAnnotation]
	name := csr.Labels[NameAnnotation]

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
			panic("unable to marshal EC key")
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
		return nil, fmt.Errorf("unsupported key type '%s'", block.Type)
	}

}

func newCsr(name, secretName, secretNamespace string, signerName string, hosts []string, privateKey crypto.PrivateKey) (*certv1.CertificateSigningRequest, error) {
	template := &x509.CertificateRequest{
		SignatureAlgorithm: 0,
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		DNSNames: hosts,
	}

	csrDer, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)

	if err != nil {
		return nil, err
	}

	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDer,
	})

	return &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				NamespaceAnnotation: secretNamespace,
				NameAnnotation:      secretName,
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:           csrPem,
			SignerName:        signerName,
			ExpirationSeconds: nil,
			Usages: []certv1.KeyUsage{
				certv1.UsageDigitalSignature,
				certv1.UsageKeyEncipherment,
				certv1.UsageServerAuth,
			},
		},
	}, nil
}

// Return true if x and y contain the same strings ignoring the order of elements
func sameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	return len(diff) == 0
}
