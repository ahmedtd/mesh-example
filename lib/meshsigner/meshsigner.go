package meshsigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/ahmedtd/mesh-example/lib/signers"
	certsv1alpha1 "k8s.io/api/certificates/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	certinformersv1alpha1 "k8s.io/client-go/informers/certificates/v1alpha1"
	"k8s.io/client-go/kubernetes"
	certlistersv1alpha1 "k8s.io/client-go/listers/certificates/v1alpha1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

// Controller is an in-memory signing controller for PodCertificateRequests.
type Controller struct {
	clock clock.PassiveClock

	kc          kubernetes.Interface
	pcrInformer cache.SharedIndexInformer
	pcrQueue    workqueue.TypedRateLimitingInterface[string]

	caKeys  []crypto.PrivateKey
	caCerts [][]byte
}

// New creates a new Controller.
func New(clock clock.PassiveClock, caKeys []crypto.PrivateKey, caCerts [][]byte, kc kubernetes.Interface) *Controller {
	pcrInformer := certinformersv1alpha1.NewFilteredPodCertificateRequestInformer(kc, metav1.NamespaceAll, 24*time.Hour, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(opts *metav1.ListOptions) {
		},
	)

	sc := &Controller{
		clock:       clock,
		kc:          kc,
		pcrInformer: pcrInformer,
		pcrQueue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		caKeys:      caKeys,
		caCerts:     caCerts,
	}

	sc.pcrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		UpdateFunc: func(old, new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		DeleteFunc: func(old any) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(old)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
	})

	return sc
}

func (c *Controller) Run(ctx context.Context) {
	defer c.pcrQueue.ShutDown()
	go c.pcrInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.pcrInformer.HasSynced) {
		return
	}

	go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	<-ctx.Done()
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	key, quit := c.pcrQueue.Get()
	if quit {
		return false
	}
	defer c.pcrQueue.Done(key)

	klog.InfoS("Processing PCR", "key", key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		klog.ErrorS(err, "Error while splitting key into namespace and name", "key", key)
		return true
	}

	pcr, err := certlistersv1alpha1.NewPodCertificateRequestLister(c.pcrInformer.GetIndexer()).PodCertificateRequests(namespace).Get(name)
	if k8serrors.IsNotFound(err) {
		c.pcrQueue.Forget(key)
		return true
	} else if err != nil {
		klog.ErrorS(err, "Error while retrieving PodCertificateRequest", "key", key)
		return true
	}

	err = c.handlePCR(ctx, pcr)
	if err != nil {
		klog.ErrorS(err, "Error while handling PodCertificateRequest", "key", key)
		c.pcrQueue.AddRateLimited(key)
		return true
	}

	c.pcrQueue.Forget(key)
	return true
}

func (c *Controller) handlePCR(ctx context.Context, pcr *certsv1alpha1.PodCertificateRequest) error {
	switch pcr.Spec.SignerName {
	case signers.SPIFFEMesh, signers.ServiceTLS, signers.PodIdentity:
	default:
		// Return nil, since we are not going to magically start supporting this
		// signer name by retaining the cert in the workqueue.
		return nil
	}

	// PodCertificateRequests don't have an approval stage, and the node
	// restriction / isolation check is handled by kube-apiserver.

	// If our signer had a policy about which pods are allowed to request
	// certificates, it would be implemented here.

	// Proceed to signing.  Our toy signer will make a SPIFFE cert encoding the
	// namespace and name of the pod's service account.

	// Is the PCR already signed?
	if pcr.Status.CertificateChain != "" {
		return nil
	}

	subjectPublicKey, err := x509.ParsePKIXPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		return fmt.Errorf("while parsing subject public key: %w", err)
	}

	// If our signer had an opinion on which key types were allowable, it would
	// check subjectPublicKey, and deny the PCR with a SuggestedKeyType
	// condition on it.

	lifetime := 24 * time.Hour
	requestedLifetime := time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
	if requestedLifetime < lifetime {
		lifetime = requestedLifetime
	}

	notBefore := c.clock.Now().Add(-2 * time.Minute)
	notAfter := notBefore.Add(lifetime)
	beginRefreshAt := notAfter.Add(-30 * time.Minute)

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	switch pcr.Spec.SignerName {
	case signers.SPIFFEMesh:
		spiffeURI := &url.URL{
			Scheme: "spiffe",
			Host:   "cluster.local",
			Path:   path.Join("ns", pcr.ObjectMeta.Namespace, "sa", pcr.Spec.ServiceAccountName),
		}
		template.URIs = []*url.URL{spiffeURI}
	case signers.ServiceTLS:
		if err := c.fillTemplateForServiceSigner(ctx, pcr, template); err != nil {
			return fmt.Errorf("while filling template for service signer: %w", err)
		}
	case signers.PodIdentity:
	default:
		// Should have already returned nil at the beginning of this function.
		return nil
	}

	signingCert, err := x509.ParseCertificate(c.caCerts[len(c.caCerts)-1])
	if err != nil {
		return fmt.Errorf("while parsing signing certificate: %w", err)
	}

	subjectCertDER, err := x509.CreateCertificate(rand.Reader, template, signingCert, subjectPublicKey, c.caKeys[len(c.caKeys)-1])
	if err != nil {
		return fmt.Errorf("while signing subject cert: %w", err)
	}

	// Compose the certificate chain
	chainPEM := &bytes.Buffer{}
	err = pem.Encode(chainPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: subjectCertDER,
	})
	if err != nil {
		return fmt.Errorf("while encoding leaf certificate to PEM: %w", err)
	}
	for i := 0; i < len(c.caCerts)-1; i++ {
		err = pem.Encode(chainPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.caCerts[len(c.caCerts)-1-i],
		})
		if err != nil {
			return fmt.Errorf("while encoding intermediate certificate to PEM: %w", err)
		}
	}

	// Don't modify the copy in the informer cache.
	pcr = pcr.DeepCopy()
	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               certsv1alpha1.PodCertificateRequestConditionTypeIssued,
			Status:             metav1.ConditionTrue,
			Reason:             "Reason",
			Message:            "Issued",
			LastTransitionTime: metav1.NewTime(c.clock.Now()),
		},
	}
	pcr.Status.CertificateChain = chainPEM.String()
	pcr.Status.NotBefore = ptr.To(metav1.NewTime(notBefore))
	pcr.Status.BeginRefreshAt = ptr.To(metav1.NewTime(beginRefreshAt))
	pcr.Status.NotAfter = ptr.To(metav1.NewTime(notAfter))

	_, err = c.kc.CertificatesV1alpha1().PodCertificateRequests(pcr.ObjectMeta.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("while updating PodCertificateRequest: %w", err)
	}

	return nil
}

func (c *Controller) fillTemplateForServiceSigner(ctx context.Context, pcr *certsv1alpha1.PodCertificateRequest, tpl *x509.Certificate) error {
	// TODO: Switch from live reads to indexer

	svcs, err := c.kc.CoreV1().Services(pcr.ObjectMeta.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("while listing services: %w", err)
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
		matchedPods, err := c.kc.CoreV1().Pods(pcr.ObjectMeta.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector}),
		})
		if err != nil {
			return fmt.Errorf("while selecting pods for service %q: %w", pcr.ObjectMeta.Namespace+"/"+svc.ObjectMeta.Name, err)
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

	tpl.DNSNames = dnsNames

	return nil
}
