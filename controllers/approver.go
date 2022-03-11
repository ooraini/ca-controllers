package controllers

import (
	"context"
	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

type ApproverReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Clientset *kubernetes.Clientset
	Config    *Config
}

func NewApproverReconciler(client client.Client, scheme *runtime.Scheme, clientset *kubernetes.Clientset, config *Config) (*ApproverReconciler, error) {

	return &ApproverReconciler{
		Client:    client,
		Scheme:    scheme,
		Clientset: clientset,
		Config:    config,
	}, nil
}

func (r *ApproverReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	csr := &certv1.CertificateSigningRequest{}
	err := r.Get(ctx, req.NamespacedName, csr)
	if err != nil {
		log.Error(err, "unable to fetch CertificateSigningRequest")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if csr.Status.Conditions == nil && csr.Status.Certificate == nil {
		condition := decide(csr)

		csr.Status.Conditions = append(csr.Status.Conditions, condition)

		if _, err = r.Clientset.CertificatesV1().CertificateSigningRequests().
			UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{}); err != nil {
			log.Error(err, "failed to update csr")
			return ctrl.Result{}, err
		}

		log.Info("csr processed", "Type", condition.Type)
		return ctrl.Result{}, nil
	}

	log.V(1).Info("already contains .status.certificate, ignoring")
	return ctrl.Result{}, nil
}

func decide(csr *certv1.CertificateSigningRequest) certv1.CertificateSigningRequestCondition {
	return certv1.CertificateSigningRequestCondition{
		Status: "True",
		Type:   "Approved",
	}
}

func (r *ApproverReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.CertificateSigningRequest{}).
		WithEventFilter(signerPredicate(r.Config.SignerName)).
		WithEventFilter(ignoreDeletesPredicate).
		Named("approver").
		Complete(r)
}
