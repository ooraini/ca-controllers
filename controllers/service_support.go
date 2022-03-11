package controllers

import (
	"context"
	"fmt"
	"strings"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
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
)

type ServiceSupportReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Config           *Config
	SecretReconciler *SecretReconciler
}

func NewServiceSupportReconciler(client client.Client, scheme *runtime.Scheme, config *Config) (*ServiceSupportReconciler, error) {
	return &ServiceSupportReconciler{
		Client:           client,
		Scheme:           scheme,
		Config:           config,
		SecretReconciler: NewSecretReconciler(client, scheme, config, ServiceSupportControllerName),
	}, nil
}

func (r *ServiceSupportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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

	// 3. Check support
	namespaceServiceSupport, ok := namespace.Annotations[ServiceSupportAnnotation]
	if ok && namespaceServiceSupport != ServiceSupportDisabled {
		log.V(1).Info("servicesupport disabled at namespace")
		return ctrl.Result{}, nil
	}

	// 4. Ensure finalizer
	result, err = r.SecretReconciler.ensureFinalizer(ctx, req)
	if result != nil || err != nil {
		return *result, err
	}

	// 5. Check number of resources
	serviceList := &corev1.ServiceList{}
	err = r.List(ctx, serviceList, client.InNamespace(req.Namespace), client.MatchingLabels{
		SecretNameMeta: req.Name,
	})

	if err != nil {
		log.Error(err, "unable to list services")
		return ctrl.Result{}, err
	}

	// 5.a No services
	if len(serviceList.Items) == 0 {
		log.V(1).Info("no service with reference to secret")
		return reconcile.Result{}, nil
	}

	// 5.b More than one service
	if len(serviceList.Items) > 1 {
		var names []string = nil
		for _, service := range serviceList.Items {
			names = append(names, service.Name)
		}
		log.Info(fmt.Sprintf("services: [%s] refer to the same secret, ignoring", strings.Join(names, ", ")))
		return reconcile.Result{}, nil
	}

	service := &serviceList.Items[0]

	clusterDomain := r.Config.ClusterDomain
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}

	var hosts = []string{
		service.Name,
		fmt.Sprintf("%s.%s", service.Name, service.Namespace),
		fmt.Sprintf("%s.%s.svc", service.Name, service.Namespace),
		fmt.Sprintf("%s.%s.svc.%s", service.Name, service.Namespace, clusterDomain),
	}

	if r.Config.ClusterExternalDomain != "" {
		hosts = append(hosts, fmt.Sprintf(
			"%s.%s.%s", service.Name, service.Namespace, r.Config.ClusterExternalDomain))
	}

	_, includeRoot := service.Annotations[IncludeRootCAAnnotation]

	return r.SecretReconciler.reconcileSecret(ctx, req, service, hosts, includeRoot)
}

func (r *ServiceSupportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Watches(
			&source.Kind{Type: &corev1.Service{}},
			handler.EnqueueRequestsFromMapFunc(r.findSecretFromService),
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
		Named("servicesupport").
		Complete(r)
}

func (r *ServiceSupportReconciler) findSecretFromService(object client.Object) []reconcile.Request {
	service := object.(*corev1.Service)

	name := service.Labels[SecretNameMeta]

	if name == "" {
		return nil
	}

	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      name,
				Namespace: service.Namespace,
			},
		},
	}
}

func (r *ServiceSupportReconciler) findSecretsInNamespace(object client.Object) []reconcile.Request {
	namespace := object.(*corev1.Namespace)

	signer, ok := namespace.Annotations[SignerNameAnnotation]

	if !ok || signer != r.Config.SignerName {
		return nil
	}

	serviceSupport, ok := namespace.Annotations[ServiceSupportAnnotation]

	if ok && serviceSupport == ServiceSupportDisabled {
		return nil
	}

	list := &corev1.ServiceList{}
	if err := r.List(context.Background(), list, client.InNamespace(namespace.Name), client.HasLabels{SecretNameMeta}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, len(list.Items))

	for _, service := range list.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      service.Labels[SecretNameMeta],
				Namespace: namespace.Name,
			},
		})
	}

	return requests
}

func (r *ServiceSupportReconciler) findSecretFromCsr(object client.Object) []reconcile.Request {
	csr := object.(*certv1.CertificateSigningRequest)
	return findSecretFromCsr(csr)
}
