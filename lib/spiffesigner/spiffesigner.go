package spiffesigner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/ahmedtd/mesh-example/lib/localca"
	"github.com/ahmedtd/mesh-example/lib/signercontroller"
	certsv1alpha1 "k8s.io/api/certificates/v1alpha1"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const Name = "row-major.net/spiffe"

const CTBPrefix = "row-major.net:spiffe:"

type Impl struct {
	spiffeTrustDomain string
	caPool            *localca.Pool
}

func NewImpl(spiffeTrustDomain string, caPool *localca.Pool) *Impl {
	return &Impl{
		spiffeTrustDomain: spiffeTrustDomain,
		caPool:            caPool,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) SignerName() string {
	return Name
}

// TODO: We need to write multiple trust bundles, labeled by trust domain, so
// that federation between different trust domains is possible.
func (h *Impl) DesiredClusterTrustBundles() []*certsv1beta1.ClusterTrustBundle {
	name := CTBPrefix + "primary-bundle"

	wantTrustBundle := bytes.Buffer{}
	for _, ca := range h.caPool.CAs {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.RootCertificate.Raw,
		})
		_, _ = wantTrustBundle.Write(block)
	}

	wantCTB := &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"spiffe.row-major.net/canarying":    "live",
				"spiffe.row-major.net/trust-domain": h.spiffeTrustDomain,
			},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  Name,
			TrustBundle: wantTrustBundle.String(),
		},
	}

	return []*certsv1beta1.ClusterTrustBundle{
		wantCTB,
	}
}

func (h *Impl) CAPool() *localca.Pool {
	return h.caPool
}

func (h *Impl) MakeCert(ctx context.Context, notBefore, notAfter time.Time, pcr *certsv1alpha1.PodCertificateRequest) ([]*x509.Certificate, error) {
	spiffeURI := &url.URL{
		Scheme: "spiffe",
		Host:   h.spiffeTrustDomain,
		Path:   path.Join("ns", pcr.ObjectMeta.Namespace, "sa", pcr.Spec.ServiceAccountName),
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{spiffeURI},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	subjectPublicKey, err := x509.ParsePKIXPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		return nil, fmt.Errorf("while parsing subject public key: %w", err)
	}

	subjectCertDER, err := x509.CreateCertificate(rand.Reader, template, h.caPool.CAs[0].RootCertificate, subjectPublicKey, h.caPool.CAs[0].SigningKey)
	if err != nil {
		return nil, fmt.Errorf("while signing subject cert: %w", err)
	}

	leafCert, err := x509.ParseCertificate(subjectCertDER)
	if err != nil {
		return nil, fmt.Errorf("while parsing leaf cert: %w", err)
	}

	ret := []*x509.Certificate{leafCert}
	ret = append(ret, h.caPool.CAs[0].IntermediateCertificates...)

	return ret, nil
}
