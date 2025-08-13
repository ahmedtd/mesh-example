package meshpublisher

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"time"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	certinformersv1beta1 "k8s.io/client-go/informers/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	certlistersv1beta1 "k8s.io/client-go/listers/certificates/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

// Controller is an in-memory ClusterTrustBundle controller.
type Controller struct {
	clock clock.PassiveClock

	signerName string

	kc          kubernetes.Interface
	ctbInformer cache.SharedIndexInformer
	ctbQueue    workqueue.TypedRateLimitingInterface[string]

	caCertsDER [][]byte
}

// New creates a new Controller.
func New(clock clock.PassiveClock, signerName string, caCertsDER [][]byte, kc kubernetes.Interface) *Controller {
	ctbInformer := certinformersv1beta1.NewFilteredClusterTrustBundleInformer(kc, 24*time.Hour, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("spec.signerName", signerName).String()
		},
	)

	sc := &Controller{
		clock:       clock,
		signerName:  signerName,
		kc:          kc,
		ctbInformer: ctbInformer,
		ctbQueue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		caCertsDER:  caCertsDER,
	}

	sc.ctbInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.ctbQueue.Add(key)
		},
		UpdateFunc: func(old, new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.ctbQueue.Add(key)
		},
		DeleteFunc: func(old any) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(old)
			if err != nil {
				return
			}
			sc.ctbQueue.Add(key)
		},
	})

	return sc
}

func (c *Controller) Run(ctx context.Context) {
	defer c.ctbQueue.ShutDown()
	go c.ctbInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.ctbInformer.HasSynced) {
		return
	}

	go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	go wait.JitterUntilWithContext(ctx, c.ensureV1Bundle, 1*time.Minute, 1.0, true)
	<-ctx.Done()
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	key, quit := c.ctbQueue.Get()
	if quit {
		return false
	}
	defer c.ctbQueue.Done(key)

	klog.InfoS("Processing CTB", "key", key)

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		klog.ErrorS(err, "Error while splitting key into namespace and name", "key", key)
		return true
	}

	ctb, err := certlistersv1beta1.NewClusterTrustBundleLister(c.ctbInformer.GetIndexer()).Get(name)
	if k8serrors.IsNotFound(err) {
		c.ctbQueue.Forget(key)
		return true
	} else if err != nil {
		klog.ErrorS(err, "Error while retrieving PodCertificateRequest", "key", key)
		return true
	}

	err = c.handlePCR(ctx, ctb)
	if err != nil {
		klog.ErrorS(err, "Error while handling PodCertificateRequest", "key", key)
		c.ctbQueue.AddRateLimited(key)
		return true
	}

	c.ctbQueue.Forget(key)
	return true
}

func (c *Controller) handlePCR(ctx context.Context, ctb *certsv1beta1.ClusterTrustBundle) error {
	if ctb.ObjectMeta.Name != "meshtool.row-major.net:main:v1" {
		klog.InfoS("Deleting unrecognized ClusterTrustBundle", "key", ctb.ObjectMeta.Name)
		err := c.kc.CertificatesV1beta1().ClusterTrustBundles().Delete(ctx, ctb.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID: ptr.To(ctb.ObjectMeta.UID),
			},
		})
		if err != nil {
			return fmt.Errorf("while deleting unmanaged ClusterTrustBundle %q: %w", ctb.ObjectMeta.Name, err)
		}
	}

	return nil
}

func (c *Controller) ensureV1Bundle(ctx context.Context) {
	wantTrustBundle := bytes.Buffer{}
	for _, anchor := range c.caCertsDER {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: anchor,
		})
		_, _ = wantTrustBundle.Write(block)
	}

	name := "meshtool.row-major.net:main:v1"
	signerName := "meshtool.row-major.net/main"

	wantCTB := &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"meshtool.row-major.net/trust-tag": "live",
			},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  signerName,
			TrustBundle: wantTrustBundle.String(),
		},
	}

	ctb, err := certlistersv1beta1.NewClusterTrustBundleLister(c.ctbInformer.GetIndexer()).Get(name)
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
