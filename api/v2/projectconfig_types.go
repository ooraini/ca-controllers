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

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cfg "sigs.k8s.io/controller-runtime/pkg/config/v1alpha1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ProjectConfigSpec defines the desired state of ProjectConfig
type ProjectConfigSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of ProjectConfig. Edit projectconfig_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

//+kubebuilder:object:root=true

// ProjectConfig is the Schema for the projectconfigs API
type ProjectConfig struct {
	metav1.TypeMeta                        `json:",inline"`
	metav1.ObjectMeta                      `json:"metadata,omitempty"`
	cfg.ControllerManagerConfigurationSpec `json:",inline"`

	CaCertPath            string          `json:"caCertPath"`
	CaKeyPath             string          `json:"caKeyPath"`
	SignerName            string          `json:"signerName"`
	RootCA                []byte          `json:"rootCA"`
	KeyType               string          `json:"keyType"`
	CertificateDuration   metav1.Duration `json:"certificateDuration"`
	ClusterDomain         string          `json:"clusterDomain"`
	ClusterExternalDomain string          `json:"clusterExternalDomain"`
	GvkConfigs            []GvkConfig     `json:"gvkConfigs,omitempty"`
	SignerEnabled         bool            `json:"signerEnabled"`
	ApproverEnabled       bool            `json:"approverEnabled"`
}

type GvkConfig struct {
	Group                string `json:"group"`
	Version              string `json:"version"`
	Kind                 string `json:"kind"`
	ObjectSupportDefault string `json:"objectSupportDefault"`
	Jmes                 string `json:"jmes"`
}

func init() {
	SchemeBuilder.Register(&ProjectConfig{})
}
