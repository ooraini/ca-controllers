package controllers

import (
	"context"
	"fmt"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	networking1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"strings"
)

type IngressSupportReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Config           *Config
	SecretReconciler *SecretReconciler
}

func NewIngressSupportReconciler(client client.Client, scheme *runtime.Scheme, config *Config) (*IngressSupportReconciler, error) {
	return &IngressSupportReconciler{
		Client:           client,
		Scheme:           scheme,
		Config:           config,
		SecretReconciler: NewSecretReconciler(client, scheme, config, "ca-controllers.io/ingress", "networking.k8s.io", "v1", "Ingress"),
	}, nil
}

func (r *IngressSupportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	log.V(1).Info("request received")

	// 1. Check finalizer
	result, err := r.SecretReconciler.finalize(ctx, req)
	if result != nil || err != nil {
		return *result, err
	}

	// 2. Check singer
	namespace := &corev1.Namespace{}
	result, err = r.SecretReconciler.namespaceSigner(ctx, req.Namespace, namespace)
	if result != nil || err != nil {
		return *result, err
	}

	// 3. Check namespace support
	nsSupport, ok := namespace.Annotations[IngressSupportAnnotation]
	// treat un-annotated and unknown values as ObjectWhenAnnotated
	if !ok || (!strings.EqualFold(nsSupport, ObjectSupportEnabled) && !strings.EqualFold(nsSupport, ObjectSupportDisabled)) {
		nsSupport = ObjectWhenAnnotated
	}

	if strings.EqualFold(nsSupport, ObjectSupportDisabled) {
		log.V(1).Info("disabled at namespace, ignoring")
		return ctrl.Result{}, nil
	}

	// 4. Check number of resources
	list := &networking1.IngressList{}
	if err = r.Client.List(ctx, list, client.InNamespace(req.Namespace)); err != nil {
		log.Error(err, "unable to list ingresses")
		return ctrl.Result{}, err
	}

	ingresses := make([]networking1.Ingress, 0)
	for _, ingress := range list.Items {
		resourceSupport, ok := ingress.Annotations[IngressSupportAnnotation]
		if strings.EqualFold(nsSupport, ObjectSupportEnabled) || (ok && strings.EqualFold(resourceSupport, ObjectSupportEnabled)) {
			for _, tls := range ingress.Spec.TLS {
				if tls.SecretName == req.Name {
					ingresses = append(ingresses, ingress)
					break
				}
			}
		}
	}

	switch {
	case len(ingresses) == 0:
		log.V(1).Info("no ingress with reference to secret")
		return ctrl.Result{}, nil
	case len(ingresses) > 1:
		var names []string = nil
		for _, ingress := range ingresses {
			names = append(names, ingress.Name)
		}
		log.Info(fmt.Sprintf("ingresses: [%s] refer to the same secret, ignoring", strings.Join(names, ", ")))
		return reconcile.Result{}, nil
	}

	ingress := &ingresses[0]

	var hosts []string = nil
	for _, tls := range ingress.Spec.TLS {
		if tls.SecretName == req.Name {
			hosts = append(hosts, tls.Hosts...)
		}
	}

	_, includeRoot := ingress.Annotations[IncludeRootCAAnnotation]

	return r.SecretReconciler.reconcileSecret(ctx, req, ingress, hosts, includeRoot)
}

func (r *IngressSupportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Watches(
			&source.Kind{Type: &networking1.Ingress{}},
			handler.EnqueueRequestsFromMapFunc(r.findSecretFromIngress),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
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
		Named("ingress").
		Complete(r)
}

func (r *IngressSupportReconciler) findSecretFromIngress(object client.Object) []reconcile.Request {
	ingress := object.(*networking1.Ingress)

	var requests []reconcile.Request = nil

	for _, tls := range ingress.Spec.TLS {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: ingress.Namespace,
				Name:      tls.SecretName,
			},
		})
	}

	return requests
}

func (r *IngressSupportReconciler) findSecretsInNamespace(object client.Object) []reconcile.Request {
	namespace := object.(*corev1.Namespace)

	list := &networking1.IngressList{}
	if err := r.Client.List(context.Background(), list, client.InNamespace(namespace.Name)); err != nil {
		return nil
	}

	var requests []reconcile.Request = nil
	for _, ingress := range list.Items {
		for _, tls := range ingress.Spec.TLS {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      tls.SecretName,
				Namespace: namespace.Name,
			}})
		}
	}

	return requests
}

func (r *IngressSupportReconciler) findSecretFromCsr(object client.Object) []reconcile.Request {
	csr := object.(*certv1.CertificateSigningRequest)
	return findSecretFromCsr(csr)
}
