package servicednssigner

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/ahmedtd/mesh-example/lib/localca"
	"github.com/ahmedtd/mesh-example/lib/signercontroller"
	certsv1alpha1 "k8s.io/api/certificates/v1alpha1"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const Name = "row-major.net/service-dns"

const CTBPrefix = "row-major.net:service-dns:"

type Impl struct {
	kc     kubernetes.Interface
	caPool *localca.Pool
}

func NewImpl(kc kubernetes.Interface, caPool *localca.Pool) *Impl {
	return &Impl{
		kc:     kc,
		caPool: caPool,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) SignerName() string {
	return Name
}

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
				"row-major.net/service-dns/canarying": "live",
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
	// TODO: Switch from live reads to indexer

	svcs, err := h.kc.CoreV1().Services(pcr.ObjectMeta.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("while listing services: %w", err)
	}

	// TODO: Looping over every service isn't great.  Maintain an index of pod
	// to covering services.

	dnsNames := []string{}
	for _, svc := range svcs.Items {
		switch svc.Spec.Type {
		case corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort, corev1.ServiceTypeLoadBalancer:
			// ok
		default:
			// This service type doesn't select pods using a label selector.
			continue
		}

		// Find the set of pods that the service selects.
		matchedPods, err := h.kc.CoreV1().Pods(pcr.ObjectMeta.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector}),
		})
		if err != nil {
			return nil, fmt.Errorf("while selecting pods for service %q: %w", pcr.ObjectMeta.Namespace+"/"+svc.ObjectMeta.Name, err)
		}

		for _, matchedPod := range matchedPods.Items {
			if matchedPod.ObjectMeta.Name == pcr.Spec.PodName && matchedPod.ObjectMeta.UID == pcr.Spec.PodUID {
				// TODO: I'm making some assumptions about the DNS names that
				// resolve to a given Service.  I know at least one
				// configuration that I suspect doesn't match these assumptions
				// --- GKE with VPC-scoped Cloud DNS [1].
				//
				// [1] https://cloud.google.com/kubernetes-engine/docs/how-to/cloud-dns#vpc_scope_dns
				name := fmt.Sprintf("%s.%s.svc", svc.ObjectMeta.Name, svc.ObjectMeta.Namespace)
				dnsNames = append(dnsNames, name)
			}
		}
	}

	// TODO: Encode the OIDC issuer of the cluster into the certificate.

	return &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}, nil
}
