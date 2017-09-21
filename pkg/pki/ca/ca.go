// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/golang/glog"
	"istio.io/auth/pkg/pki"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	apiv1 "k8s.io/client-go/pkg/api/v1"
)

const (
	// IstioSecretType is the Istio secret annotation type.
	IstioSecretType = "istio.io/key-and-cert"

	// CACertChainID is the CA certificate chain file.
	CACertChainID = "ca-cert.pem"
	// CAPrivateKeyID is the private key file of CA.
	CAPrivateKeyID = "ca-key.pem"
	// RootCertID is the root certificate file.
	RootCertID = "root-cert.pem"

	// CASecret stores the key/cert of self-signed CA for persistency purpose.
	CASecret = "istio-ca-secret"

	// The size of a private key for a self-signed Istio CA.
	caKeySize = 2048
)

// CertificateAuthority contains methods to be supported by a CA.
type CertificateAuthority interface {
	Sign(csrPEM []byte) ([]byte, error)
	GetRootCertificate() []byte
}

// IstioCAOptions holds the configurations for creating an Istio CA.
type IstioCAOptions struct {
	CertChainBytes   []byte
	CertTTL          time.Duration
	Namespace        string
	Org              string
	SigningCertBytes []byte
	SigningKeyBytes  []byte
	RootCertBytes    []byte
}

// IstioCA generates keys and certificates for Istio identities.
type IstioCA struct {
	certTTL     time.Duration
	signingCert *x509.Certificate
	signingKey  crypto.PrivateKey

	certChainBytes []byte
	rootCertBytes  []byte
}

// NewSelfSignedIstioCA returns a new IstioCA instance using self-signed certificate.
func NewSelfSignedIstioCA(caCertTTL, certTTL time.Duration, org string, namespace string,
	core corev1.CoreV1Interface) (*IstioCA, error) {

	caSecret, err := core.Secrets(namespace).Get(CASecret, metav1.GetOptions{})
	opts := &IstioCAOptions{
		CertTTL:          certTTL,
		Namespace:        namespace,
	}
	if err != nil {
		glog.Warningf("Failed to get secret (error: %s), will create one", err)

		now := time.Now()
		options := CertOptions{
			NotBefore:    now,
			NotAfter:     now.Add(caCertTTL),
			Org:          org,
			IsCA:         true,
			IsSelfSigned: true,
			RSAKeySize:   caKeySize,
		}
		pemCert, pemKey := GenCert(options)

		opts.SigningCertBytes = pemCert
		opts.SigningKeyBytes = pemKey
		opts.RootCertBytes = pemCert

		// Rewrite the key/cert back to secret so they will be persistent when CA restarts.
		secret := &apiv1.Secret{
			Data: map[string][]byte{
				CACertChainID:  pemCert,
				CAPrivateKeyID: pemKey,
				RootCertID:     pemCert,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:        CASecret,
				Namespace:   namespace,
			},
			Type: IstioSecretType,
		}
		_, err := core.Secrets(opts.Namespace).Create(secret)
		if err != nil {
			glog.Errorf("Failed to create secret (error: %s)", err)
			return nil, err
		}
	} else {
		// Reuse existing key/cert in secrets.
		opts.SigningCertBytes = caSecret.Data[CACertChainID]
		opts.SigningKeyBytes = caSecret.Data[CAPrivateKeyID]
		opts.RootCertBytes = caSecret.Data[RootCertID]
	}

	return NewIstioCA(opts)
}

// NewIstioCA returns a new IstioCA instance.
func NewIstioCA(opts *IstioCAOptions) (*IstioCA, error) {
	ca := &IstioCA{certTTL: opts.CertTTL}

	ca.certChainBytes = copyBytes(opts.CertChainBytes)
	ca.rootCertBytes = copyBytes(opts.RootCertBytes)

	var err error
	ca.signingCert, err = pki.ParsePemEncodedCertificate(opts.SigningCertBytes)
	if err != nil {
		return nil, err
	}

	ca.signingKey, err = pki.ParsePemEncodedKey(opts.SigningKeyBytes)
	if err != nil {
		return nil, err
	}

	if err := ca.verify(); err != nil {
		return nil, err
	}

	return ca, nil
}

// GetRootCertificate returns the PEM-encoded root certificate.
func (ca *IstioCA) GetRootCertificate() []byte {
	return copyBytes(ca.rootCertBytes)
}

// Sign takes a PEM-encoded certificate signing request and returns a signed
// certificate.
func (ca *IstioCA) Sign(csrPEM []byte) ([]byte, error) {
	csr, err := pki.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	tmpl := ca.generateCertificateTemplate(csr)

	bytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca.signingCert, csr.PublicKey, ca.signingKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bytes,
	}
	cert := pem.EncodeToMemory(block)

	// Also append intermediate certs into the chain.
	chain := append(cert, ca.certChainBytes...)

	return chain, nil
}

func (ca *IstioCA) generateCertificateTemplate(request *x509.CertificateRequest) *x509.Certificate {
	exts := append(request.Extensions, request.ExtraExtensions...)
	now := time.Now()

	return &x509.Certificate{
		SerialNumber: genSerialNum(),
		Subject:      request.Subject,
		NotAfter:     now.Add(ca.certTTL),
		NotBefore:    now,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:         false,
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
		DNSNames:              request.DNSNames,
		EmailAddresses:        request.EmailAddresses,
		IPAddresses:           request.IPAddresses,
		SignatureAlgorithm:    request.SignatureAlgorithm,
	}
}

// verify that the cert chain, root cert and signing key/cert match.
func (ca *IstioCA) verify() error {
	// Create another CertPool to hold the root.
	rcp := x509.NewCertPool()
	rcp.AppendCertsFromPEM(ca.rootCertBytes)

	icp := x509.NewCertPool()
	icp.AppendCertsFromPEM(ca.certChainBytes)

	opts := x509.VerifyOptions{
		Intermediates: icp,
		Roots:         rcp,
	}

	chains, err := ca.signingCert.Verify(opts)
	if len(chains) == 0 || err != nil {
		return errors.New(
			"invalid parameters: cannot verify the signing cert with the provided root chain and cert pool")
	}
	return nil
}

func copyBytes(src []byte) []byte {
	bs := make([]byte, len(src))
	copy(bs, src)
	return bs
}
