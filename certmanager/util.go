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

package certmanager

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/golang/glog"
)

const (
	// The GCE metadata service URI to get identity token.
	identityUri = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

// Get the GCE VM identity jwt token from its metadata server.
// Note: this function only works in a GCE VM environment.
func GetIdentityToken(aud string) ([]byte, error) {
	req, err := http.NewRequest("GET", identityUri + aud, nil)
	if err != nil {
		glog.Errorf("Fail to construct the http request: %s", err)
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		glog.Errorf("Http call failed: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("Failed to parse response: %s", err)
		return nil, err
	}
	return body, err
}

// ParsePemEncodedCertificate constructs a `x509.Certificate` object using the
// given a PEM-encoded certificate,
func ParsePemEncodedCertificate(certBytes []byte) *x509.Certificate {
	cb, _ := pem.Decode(certBytes)
	if cb == nil {
		glog.Fatalf("Invalid PEM encoding for the certificate: %s", certBytes)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		glog.Fatalf("Failed to parse X.509 certificate (error: %s)", err)
	}
	return cert
}

// Given a PEM-encoded key, parse the bytes into a `crypto.PrivateKey`
// according to the provided `x509.PublicKeyAlgorithm`.
func parsePemEncodedKey(algo x509.PublicKeyAlgorithm, keyBytes []byte) crypto.PrivateKey {
	kb, _ := pem.Decode(keyBytes)
	if kb == nil {
		glog.Fatalf("Invalid PEM encoding for the key: %s", keyBytes)
	}

	switch algo {
	case x509.RSA:
		key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			glog.Fatalf("Failed to parse the RSA private key (error: %s)", err)
		}
		return key
	case x509.ECDSA:
		key, err := x509.ParseECPrivateKey(kb.Bytes)
		if err != nil {
			glog.Fatalf("Failed to parse the ECDSA private key (error: %s)", err)
		}
		return key
	default:
		glog.Fatalf("Unknown public key algorithm: %d", algo)
	}

	return nil
}
