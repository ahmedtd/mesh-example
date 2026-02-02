package acmesigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ahmedtd/mesh-example/lib/signercontroller"
	"golang.org/x/crypto/acme"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

const (
	Name = "row-major.net/acme"

	OrderAnnotation   = "acme.row-major.net/order-url"
	CertURLAnnotation = "acme.row-major.net/cert-url"
)

type namespaceName struct {
	namespace string
	name      string
}

type Impl struct {
	kc kubernetes.Interface
	ac *acme.Client

	clock clock.PassiveClock

	// The domains for which the signer will run pre-authorization.
	domains []string
	// URLs for account contact.
	contactURLs []string

	lock sync.Mutex
	// Maps PodCertificateRequests to order URLs
	orders map[namespaceName]string
}

func NewImpl(clock clock.PassiveClock, kc kubernetes.Interface, acmeAccountKey crypto.Signer, contactURLs []string, domains []string) *Impl {
	return &Impl{
		kc: kc,
		ac: &acme.Client{
			// Use the staging environment.  Prod LetsEncrypt has rate limits
			// that make Pod Certificates a bad fit for it.  In particular, only
			// 5 certificates for the same hostname can be issued every 7 days.
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Key:          acmeAccountKey,
		},
		clock:       clock,
		contactURLs: contactURLs,
		domains:     domains,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) Register(ctx context.Context) error {
	var acct *acme.Account
	var err error
	acct, err = h.ac.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		acct, err = h.ac.Register(ctx, &acme.Account{Contact: h.contactURLs}, acme.AcceptTOS)
		if err != nil {
			return fmt.Errorf("while registering new account: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("while fetching account: %w", err)
	}
	slog.InfoContext(ctx, "Got account", slog.String("account", acct.URI))

	return nil
}

func (h *Impl) SignerName() string {
	return Name
}

func (h *Impl) DesiredClusterTrustBundles() []*certsv1beta1.ClusterTrustBundle {
	return nil
}

func (h *Impl) MakeCert(ctx context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	pkcs10Req, err := x509.ParseCertificateRequest(pcr.Spec.UnverifiedPKCS10Request)
	if err != nil {
		return fmt.Errorf("while parsing spec.unverifiedPKCS10Request: %w", err)
	}

	// Look up the order we already created for this PCR, or create one now.
	var order *acme.Order
	if pcr.ObjectMeta.Annotations[OrderAnnotation] != "" {
		order, err = h.ac.GetOrder(ctx, pcr.ObjectMeta.Annotations[OrderAnnotation])
		if err != nil {
			return fmt.Errorf("while fetching existing order for PodCertificateRequest: %w", err)
		}
	} else {
		// TODO: Handle MaxExpirationSeconds?

		order, err = h.ac.AuthorizeOrder(ctx, acme.DomainIDs(pkcs10Req.DNSNames...))
		if err != nil {
			return fmt.Errorf("while creating order: %w", err)
		}

		pcrCopy := pcr.DeepCopy()
		if pcrCopy.ObjectMeta.Annotations == nil {
			pcrCopy.ObjectMeta.Annotations = map[string]string{}
		}
		pcrCopy.ObjectMeta.Annotations[OrderAnnotation] = order.URI
		_, err = h.kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).Update(ctx, pcrCopy, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("while updating PodCertificateRequest with order annotation: %w", err)
		}
	}

	if order.Status == acme.StatusPending {
		for _, authzURL := range order.AuthzURLs {
			authz, err := h.ac.GetAuthorization(ctx, authzURL)
			if err != nil {
				return fmt.Errorf("while fetching authorization: %w", err)
			}

			if authz.Status != acme.StatusPending {
				slog.InfoContext(ctx, "Authorization is not pending", slog.String("authorization", authzURL))
				continue
			}

			for _, challenge := range authz.Challenges {
				if challenge.Type != "dns-01" {
					continue
				}

				dnsRecord, err := h.ac.DNS01ChallengeRecord(challenge.Token)
				if err != nil {
					return fmt.Errorf("while constructing DNS record for challenge: %w", err)
				}

				_, err = h.ac.Accept(ctx, challenge)
				if err != nil {
					return fmt.Errorf("while accepting challenge: %w", err)
				}

				evt := &eventsv1.Event{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:    pcr.ObjectMeta.Namespace,
						GenerateName: "evt-",
					},
					EventTime:           metav1.NewMicroTime(h.clock.Now()),
					ReportingController: "mesh-controller",
					ReportingInstance:   "abc",
					Regarding: corev1.ObjectReference{
						APIVersion: "core/v1",
						Kind:       "Pod",
						Namespace:  pcr.ObjectMeta.Namespace,
						Name:       pcr.Spec.PodName,
					},
					Type:   "Normal",
					Action: "DNS01Challenge",
					Reason: "DNS01Challenge",
					Note:   fmt.Sprintf("Add a DNS-01 challenge TXT record to the issued domain for %s, value %q", authz.Identifier.Value, dnsRecord),
				}
				_, err = h.kc.EventsV1().Events(pcr.ObjectMeta.Namespace).Create(ctx, evt, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("while creating event: %w", err)
				}

				slog.InfoContext(ctx, "DNS-01 challenge; add a TXT record", slog.String("key", "_acme-challenge."+authz.Identifier.Value), slog.String("value", dnsRecord))
			}
		}
		return fmt.Errorf("waiting on authorization of order")
	} else if order.Status == acme.StatusReady {
		chainDER, refetchURL, err := h.ac.CreateOrderCert(ctx, order.FinalizeURL, pcr.Spec.UnverifiedPKCS10Request, true)
		if err != nil {
			return fmt.Errorf("while finalizing order: %w", err)
		}

		leafDER := chainDER[0]
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			return fmt.Errorf("while parsing issued leaf certificate: %w", err)
		}

		pcrCopy := pcr.DeepCopy()
		if pcrCopy.ObjectMeta.Annotations == nil {
			pcrCopy.ObjectMeta.Annotations = map[string]string{}
		}
		pcrCopy.ObjectMeta.Annotations[CertURLAnnotation] = refetchURL
		_, err = h.kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).Update(ctx, pcrCopy, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("while updating PodCertificateRequest with order annotation: %w", err)
		}

		chainPEM := &bytes.Buffer{}
		for _, certDER := range chainDER {
			err = pem.Encode(chainPEM, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certDER,
			})
			if err != nil {
				return fmt.Errorf("while encoding certificate to PEM: %w", err)
			}
		}

		pcr = pcr.DeepCopy()
		pcr.Status.Conditions = []metav1.Condition{
			{
				Type:               certsv1beta1.PodCertificateRequestConditionTypeIssued,
				Status:             metav1.ConditionTrue,
				Reason:             "Reason",
				Message:            "Issued",
				LastTransitionTime: metav1.NewTime(h.clock.Now()),
			},
		}
		pcr.Status.CertificateChain = chainPEM.String()
		pcr.Status.NotBefore = ptr.To(metav1.NewTime(leafCert.NotBefore))
		pcr.Status.BeginRefreshAt = ptr.To(metav1.NewTime(leafCert.NotAfter.Add(-30 * 24 * time.Hour)))
		pcr.Status.NotAfter = ptr.To(metav1.NewTime(leafCert.NotAfter))

		_, err = h.kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("while updating PodCertificateRequest: %w", err)
		}

		return nil
	} else if order.Status == acme.StatusInvalid {

		pcrCopy := pcr.DeepCopy()
		pcrCopy.Status.Conditions = append(pcr.Status.Conditions, metav1.Condition{
			Type:               certsv1beta1.PodCertificateRequestConditionTypeFailed,
			Status:             metav1.ConditionTrue,
			Reason:             "ACMEOrderInvalid",
			Message:            fmt.Sprintf("ACME Order is invalid: %#v", order.Error),
			LastTransitionTime: metav1.NewTime(h.clock.Now()),
		})
		_, err := h.kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).UpdateStatus(ctx, pcrCopy, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("while moving PodCertificateRequest to failed state: %w", err)
		}

		// We are done with this PCR.
		return fmt.Errorf("PodCertificateRequest moved to failed state")
	} else {

		return fmt.Errorf("order in unhandled status: %v", order.Status)
	}
}
