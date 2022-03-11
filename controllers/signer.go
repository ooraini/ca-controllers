package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

type SignerReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Clientset *kubernetes.Clientset
	Config    *Config
}

func NewSignerReconciler(client client.Client, scheme *runtime.Scheme, clientset *kubernetes.Clientset, config *Config) (*SignerReconciler, error) {
	return &SignerReconciler{
		Client:    client,
		Scheme:    scheme,
		Clientset: clientset,
		Config:    config,
	}, nil
}

func isApproved(csrObject *certv1.CertificateSigningRequest) bool {
	for _, c := range csrObject.Status.Conditions {
		if c.Type == certv1.CertificateApproved {
			return true
		}
	}

	return false
}

func (r *SignerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	csrObject := &certv1.CertificateSigningRequest{}
	err := r.Get(ctx, req.NamespacedName, csrObject)
	if err != nil {
		log.Error(err, "unable to fetch CertificateSigningRequest")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !isApproved(csrObject) {
		log.V(1).Info("not approved, ignoring")
		return ctrl.Result{}, nil
	}

	if csrObject.Status.Certificate != nil {
		log.V(1).Info("already contains .status.certificate. Ignoring")
		return ctrl.Result{}, nil
	}

	csrPemBlock, _ := pem.Decode(csrObject.Spec.Request)
	if csrPemBlock == nil {
		panic(err)
	}

	csr, err := x509.ParseCertificateRequest(csrPemBlock.Bytes)

	if err != nil {
		panic(csrObject)
	}

	if err = csr.CheckSignature(); err != nil {
		log.Error(err, "invalid signature on csr")

		condition := certv1.CertificateSigningRequestCondition{
			Status: "True",
			Type:   "Failed",
			Reason: "InvalidSignature",
		}

		csrObject.Status.Conditions = append(csrObject.Status.Conditions, condition)

		if _, err = r.Clientset.CertificatesV1().CertificateSigningRequests().
			UpdateApproval(ctx, csrObject.Name, csrObject, metav1.UpdateOptions{}); err != nil {
			log.Error(err, "unable to update csr conditions")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	pemEncoded, err := createCertificate(csr, r.Config.CertificateDuration, r.Config.CaCert, r.Config.CaPrivateKey)
	if err != nil {
		log.Error(err, "failed to create certificate")
		return ctrl.Result{}, err
	}

	csrObject.Status.Certificate = pemEncoded

	if _, err = r.Clientset.CertificatesV1().CertificateSigningRequests().
		UpdateStatus(ctx, csrObject, metav1.UpdateOptions{}); err != nil {
		log.Error(err, "unable to update csr certificate")
		return ctrl.Result{}, err
	}

	log.Info("certificate issued")

	return ctrl.Result{}, nil
}

func (r *SignerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certv1.CertificateSigningRequest{}).
		WithEventFilter(signerPredicate(r.Config.SignerName)).
		WithEventFilter(ignoreDeletesPredicate).
		Named("signer").
		Complete(r)
}
