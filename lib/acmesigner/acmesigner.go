package acmesigner

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ahmedtd/mesh-example/lib/localca"
	"github.com/ahmedtd/mesh-example/lib/signercontroller"
	"golang.org/x/crypto/acme"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
)

const Name = "row-major.net/acme"

type Impl struct {
	kc kubernetes.Interface
	ac *acme.Client

	// The domains for which the signer will run pre-authorization.
	domains []string
	// URLs for account contact.
	contactURLs []string
}

func NewImpl(acmeAccountKey crypto.Signer, contactURLs []string, domains []string) *Impl {
	return &Impl{
		ac: &acme.Client{
			// Use the staging environment.  Prod LetsEncrypt has rate limits
			// that make Pod Certificates a bad fit for it.  In particular, only
			// 5 certificates for the same hostname can be issued every 7 days.
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Key:          acmeAccountKey,
		},
		contactURLs: contactURLs,
		domains:     domains,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) PreAuthorize(ctx context.Context) error {
	slog.InfoContext(ctx, "Begining PreAuthorize")

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

	for _, domain := range h.domains {
		authz, err := h.ac.Authorize(ctx, domain)
		if err != nil {
			return fmt.Errorf("while authorizing %q: %w", domain, err)
		}

		// If the domain is already authorized, nothing to do.
		if authz.Status == acme.StatusValid {
			continue
		}

		for _, challenge := range authz.Challenges {
			// For now, only support dns-01 challenges, and just print the token
			// for the operator to manually create the challenge entry.
			//
			// Other challenge types are going to require ingress into the
			// cluster.
			if challenge.Type == "dns-01" {
				slog.InfoContext(ctx, "dns-01 challenge for domain", slog.String("domain", domain), slog.String("token", challenge.Token))

				_, err := h.ac.Accept(ctx, challenge)
				if err != nil {
					return fmt.Errorf("while accepting challenge: %w", err)
				}
			}
		}

		_, err = h.ac.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return fmt.Errorf("while waiting for authorization for domain %q: %w", domain, err)
		}
	}

	return nil
}

func (h *Impl) SignerName() string {
	return Name
}

func (h *Impl) DesiredClusterTrustBundles() []*certsv1beta1.ClusterTrustBundle {
	return nil
}

func (h *Impl) CAPool() *localca.Pool {
	return nil
}

func (h *Impl) MakeCert(ctx context.Context, notBefore, notAfter time.Time, pcr *certsv1beta1.PodCertificateRequest) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("unimplemented")
}
