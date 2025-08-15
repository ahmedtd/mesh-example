package spiffesigner

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
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
				"row-major.net/spiffe/canarying":    "live",
				"row-major.net/spiffe/trust-domain": h.spiffeTrustDomain,
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

func (h *Impl) MakeCert(ctx context.Context, notBefore, notAfter time.Time, pcr *certsv1alpha1.PodCertificateRequest) (*x509.Certificate, error) {
	spiffeURI := &url.URL{
		Scheme: "spiffe",
		Host:   h.spiffeTrustDomain,
		Path:   path.Join("ns", pcr.ObjectMeta.Namespace, "sa", pcr.Spec.ServiceAccountName),
	}

	return &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{spiffeURI},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}, nil
}
