package meshpublisher

import (
	"bytes"
	"context"
	"encoding/pem"
	"time"

	"github.com/ahmedtd/mesh-example/lib/signers"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

// Controller is an in-memory ClusterTrustBundle controller.
type Controller struct {
	clock clock.PassiveClock

	kc kubernetes.Interface

	caCertsDER [][]byte
}

// New creates a new Controller.
func New(clock clock.PassiveClock, caCertsDER [][]byte, kc kubernetes.Interface) *Controller {
	sc := &Controller{
		clock:      clock,
		kc:         kc,
		caCertsDER: caCertsDER,
	}

	return sc
}

func (c *Controller) Run(ctx context.Context) {
	go wait.JitterUntilWithContext(ctx, c.ensureV1Bundle, 1*time.Minute, 1.0, true)
	<-ctx.Done()
}

func (c *Controller) ensureV1Bundle(ctx context.Context) {
	name := signers.ServiceTLSCTBPrefix + "v1"

	wantTrustBundle := bytes.Buffer{}
	for _, anchor := range c.caCertsDER {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: anchor,
		})
		_, _ = wantTrustBundle.Write(block)
	}

	wantCTB := &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"meshtool.row-major.net/trust-tag": "live",
			},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  signers.ServiceTLS,
			TrustBundle: wantTrustBundle.String(),
		},
	}

	ctb, err := c.kc.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = c.kc.CertificatesV1beta1().ClusterTrustBundles().Create(ctx, wantCTB, metav1.CreateOptions{})
		if err != nil {
			klog.ErrorS(err, "while creating ClusterTrustBundle", "key", name)
			return
		}
		return
	} else if err != nil {
		klog.ErrorS(err, "while getting ClusterTrustBundle", "key", name)
		return
	}

	if apiequality.Semantic.DeepEqual(wantCTB.Labels, ctb.Labels) && apiequality.Semantic.DeepEqual(wantCTB.Spec, ctb.Spec) {
		klog.InfoS("ClusterTrustBundle already in correct state", "key", name)
	}

	ctb = ctb.DeepCopy()
	ctb.ObjectMeta.Labels = wantCTB.Labels
	ctb.Spec.TrustBundle = wantCTB.Spec.TrustBundle

	_, err = c.kc.CertificatesV1beta1().ClusterTrustBundles().Update(ctx, ctb, metav1.UpdateOptions{})
	if err != nil {
		klog.ErrorS(err, "while updating ClusterTrustBundle", "key", name)
	}
}
