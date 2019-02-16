/*
Copyright 2017 The Kubernetes Authors.

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

package phases

import (
	"fmt"
	"github.com/pkg/errors"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	"k8s.io/kubernetes/cmd/kubeadm/app/cmd/phases/workflow"
	cmdutil "k8s.io/kubernetes/cmd/kubeadm/app/cmd/util"
	kubeadmconstants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	certsphase "k8s.io/kubernetes/cmd/kubeadm/app/phases/certs"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
	"k8s.io/kubernetes/pkg/util/normalizer"
)

var (
	saKeyLongDesc = fmt.Sprintf(normalizer.LongDesc(`
		Generates the private key for signing service account tokens along with its public key, and saves them into
		%s and %s files.
		If both files already exist, kubeadm skips the generation step and existing files will be used.
		`+cmdutil.AlphaDisclaimer), kubeadmconstants.ServiceAccountPrivateKeyName, kubeadmconstants.ServiceAccountPublicKeyName)

	genericLongDesc = normalizer.LongDesc(`
		Generates the %[1]s, and saves them into %[2]s.cert and %[2]s.key files.%[3]s

		If both files already exist, kubeadm skips the generation step and existing files will be used.
		` + cmdutil.AlphaDisclaimer)
)

var (
	csrOnly bool
	csrDir  string
)

// certsData defines the behavior that a runtime data struct passed to the certs phase should
// have. Please note that we are using an interface in order to make this phase reusable in different workflows
// (and thus with different runtime data struct, all of them requested to be compliant to this interface)
type certsData interface {
	Cfg() *kubeadmapi.InitConfiguration
	ExternalCA() bool
	CertificateDir() string
	CertificateWriteDir() string
}

// NewCertsPhase returns the phase for the certs
func NewKubeletCerts() workflow.Phase {
	return workflow.Phase{
		Name:  "kubelet-certs",
		Short: "Kubelet certificate generation",
		Phases: []workflow.Phase{
			{
				Name: "all",
				Short: "Prepares kubelet server certificates",
			},
		},
		Run:  runCerts,
		Long: cmdutil.MacroCommandLongDescription,
	}
}

func runCerts(c workflow.RunData) error {
	data, ok := c.(certsData)
	if !ok {
		return errors.New("certs phase invoked with an invalid data struct")
	}

	fmt.Printf("[certs] Using certificateDir folder %q\n", data.CertificateWriteDir())
	return nil
}

func runCAPhase(ca *certsphase.KubeadmCert) func(c workflow.RunData) error {
	return func(c workflow.RunData) error {
		data, ok := c.(certsData)
		if !ok {
			return errors.New("certs phase invoked with an invalid data struct")
		}

		// TODO(EKF): can we avoid loading these certificates every time?
		if _, err := pkiutil.TryLoadCertFromDisk(data.CertificateDir(), ca.BaseName); err == nil {
			if _, err := pkiutil.TryLoadKeyFromDisk(data.CertificateDir(), ca.BaseName); err == nil {
				fmt.Printf("[certs] Using existing %s certificate authority\n", ca.BaseName)
				return nil
			}
			fmt.Printf("[certs] Using existing %s keyless certificate authority", ca.BaseName)
			return nil
		}

		// if using external etcd, skips etcd certificate authority generation
		if data.Cfg().Etcd.External != nil && ca.Name == "etcd-ca" {
			fmt.Printf("[certs] External etcd mode: Skipping %s certificate authority generation\n", ca.BaseName)
			return nil
		}

		// if dryrunning, write certificates authority to a temporary folder (and defer restore to the path originally specified by the user)
		cfg := data.Cfg()
		cfg.CertificatesDir = data.CertificateWriteDir()
		defer func() { cfg.CertificatesDir = data.CertificateDir() }()

		// create the new certificate authority (or use existing)
		return certsphase.CreateCACertAndKeyFiles(ca, cfg)
	}
}

func runCertPhase(cert *certsphase.KubeadmCert, caCert *certsphase.KubeadmCert) func(c workflow.RunData) error {
	return func(c workflow.RunData) error {
		data, ok := c.(certsData)
		if !ok {
			return errors.New("certs phase invoked with an invalid data struct")
		}

		// TODO(EKF): can we avoid loading these certificates every time?
		if certData, _, err := pkiutil.TryLoadCertAndKeyFromDisk(data.CertificateDir(), cert.BaseName); err == nil {
			caCertData, err := pkiutil.TryLoadCertFromDisk(data.CertificateDir(), caCert.BaseName)
			if err != nil {
				return errors.Wrapf(err, "couldn't load CA certificate %s", caCert.Name)
			}

			if err := certData.CheckSignatureFrom(caCertData); err != nil {
				return errors.Wrapf(err, "[certs] certificate %s not signed by CA certificate %s", cert.BaseName, caCert.BaseName)
			}

			fmt.Printf("[certs] Using existing %s certificate and key on disk\n", cert.BaseName)
			return nil
		}

		if csrOnly {
			fmt.Printf("[certs] Generating CSR for %s instead of certificate\n", cert.BaseName)
			if csrDir == "" {
				csrDir = data.CertificateWriteDir()
			}

			return certsphase.CreateCSR(cert, data.Cfg(), csrDir)
		}

		// if using external etcd, skips etcd certificates generation
		if data.Cfg().Etcd.External != nil && cert.CAName == "etcd-ca" {
			fmt.Printf("[certs] External etcd mode: Skipping %s certificate authority generation\n", cert.BaseName)
			return nil
		}

		// if dryrunning, write certificates to a temporary folder (and defer restore to the path originally specified by the user)
		cfg := data.Cfg()
		cfg.CertificatesDir = data.CertificateWriteDir()
		defer func() { cfg.CertificatesDir = data.CertificateDir() }()

		// create the new certificate (or use existing)
		return certsphase.CreateCertAndKeyFilesWithCA(cert, caCert, cfg)
	}
}
