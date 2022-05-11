package controllers

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/jmespath/go-jmespath"
	certv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"regexp"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"strings"
	"time"
	"unicode/utf8"
)

//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=create;get;list;watch;update;patch;delete
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
	KeyType    string
	GvkConfigs []GvkConfig
}

type GvkConfig struct {
	schema.GroupVersionKind
	*jmespath.JMESPath
	NamespaceSupportAnnotation string
	DefaultObjectSupport       ObjectSupport
}

func isTracked(config GvkConfig, namespace, object client.Object) bool {

	reg := regexp.MustCompile("\\s")
	kind := object.GetObjectKind().GroupVersionKind().Kind
	kindSupport := config.DefaultObjectSupport

	nsSupport := ""
	if v, ok := namespace.GetAnnotations()[config.NamespaceSupportAnnotation]; ok {
		nsSupport = v
	}

	for _, item := range reg.Split(nsSupport, -1) {
		split := strings.Split(item, ":")
		if len(split) == 2 && (split[0] == kind || split[0] == "*") {
			if ObjectSupport(split[1]).IsValid() == nil {
				kindSupport = ObjectSupport(split[1])
				break
			}
		}
	}

	// No annotation => Disabled
	// Annotation with empty value => Enabled
	// Annotation with valid ObjectSupport => use the value
	resourceSupport := ObjectSupportDisabled
	if v, ok := object.GetAnnotations()[ObjectSupportAnnotation]; ok {
		resourceSupport = ObjectSupportEnabled
		s := ObjectSupport(v)
		if s.IsValid() == nil && s != ObjectSupportAnnotation {
			resourceSupport = s
		}
	}

	if kindSupport == ObjectSupportDisabled {
		return false
	} else if kindSupport == ObjectSupportEnabled {
		return true
	} else { // ObjectSupportWhenAnnotated
		return resourceSupport == ObjectSupportEnabled
	}
}

const (
	DefaultKeyType              = "EC"
	DefaultClusterDomain        = "cluster.local"
	FinalizerName               = "ca-controllers.io/finalizer"
	SignerNameAnnotation        = "ca-controllers.io/signerName"
	IncludeRootCAAnnotation     = "ca-controllers.io/include-root-ca"
	NameAnnotation              = "ca-controllers.io/metadata.name"
	NamespaceAnnotation         = "ca-controllers.io/metadata.namespace"
	ControllerGroupAnnotation   = "ca-controllers.io/group"
	ControllerVersionAnnotation = "ca-controllers.io/version"
	ControllerKindAnnotation    = "ca-controllers.io/kind"
	ObjectSupportAnnotation     = "ca-controllers.io/support"
	ManagedByLabelKey           = "app.kubernetes.io/managed-by"
	ManagedByLabelValue         = "ca-controllers"
)

type ObjectSupport string

func (receiver ObjectSupport) String() string {
	return string(receiver)
}
func (receiver ObjectSupport) IsValid() error {
	switch receiver {
	case ObjectSupportEnabled, ObjectSupportDisabled, ObjectSupportWhenAnnotated:
		return nil
	}
	return fmt.Errorf("invliad ObjectSupport '%s'", receiver.String())
}

const (
	ObjectSupportWhenAnnotated ObjectSupport = "WhenAnnotated"
	ObjectSupportEnabled       ObjectSupport = "Enabled"
	ObjectSupportDisabled      ObjectSupport = "Disabled"
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

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// https://gist.github.com/chmike/d4126a3247a6d9a70922fc0e8b4f4013
// checkDomain returns an error if the domain name is not valid
// See https://tools.ietf.org/html/rfc1034#section-3.5 and
// https://tools.ietf.org/html/rfc1123#section-2.
func checkDomain(name string) error {
	switch {
	case len(name) == 0:
		return nil // an empty domain name will result in a cookie without a domain restriction
	case len(name) > 255:
		return fmt.Errorf("cookie domain: name length is %d, can't exceed 255", len(name))
	}
	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			// check domain labels validity
			switch {
			case i == l:
				return fmt.Errorf("cookie domain: invalid character '%c' at offset %d: label can't begin with a period", b, i)
			case i-l > 63:
				return fmt.Errorf("cookie domain: byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("cookie domain: label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("cookie domain: label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}
		// test label character validity, note: tests are ordered by decreasing validity frequency
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 'A' && b <= 'Z') {
			// show the printable unicode character starting at byte offset i
			c, _ := utf8.DecodeRuneInString(name[i:])
			if c == utf8.RuneError {
				return fmt.Errorf("cookie domain: invalid rune at offset %d", i)
			}
			return fmt.Errorf("cookie domain: invalid character '%c' at offset %d", c, i)
		}
	}
	// check top level domain validity
	switch {
	case l == len(name):
		return fmt.Errorf("cookie domain: missing top level domain, domain can't end with a period")
	case len(name)-l > 63:
		return fmt.Errorf("cookie domain: byte length of top level domain '%s' is %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d begins with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}
	return nil
}
