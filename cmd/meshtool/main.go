package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ahmedtd/mesh-example/lib/meshpublisher"
	"github.com/ahmedtd/mesh-example/lib/meshsigner"
	"github.com/google/subcommands"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/utils/clock"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&ControllerCommand{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

type ControllerCommand struct {
	inCluster  bool
	kubeConfig string
}

var _ subcommands.Command = (*ControllerCommand)(nil)

func (*ControllerCommand) Name() string {
	return "controller"
}

func (*ControllerCommand) Synopsis() string {
	return "Run the controller"
}

func (*ControllerCommand) Usage() string {
	return ``
}

func (c *ControllerCommand) SetFlags(f *flag.FlagSet) {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}

	f.StringVar(&c.kubeConfig, "kubeconfig", kubeConfigDefault, "absolute path to the kubeconfig file")
	f.BoolVar(&c.inCluster, "in-cluster", false, "Is the controller running in the cluster it should connect to?")
}

func (c *ControllerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *ControllerCommand) do(ctx context.Context) error {
	var kconfig *rest.Config
	var err error
	if c.inCluster {
		kconfig, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("while creating in-cluster config: %w", err)
		}
	} else {
		// use the current context in kubeconfig
		kconfig, err = clientcmd.BuildConfigFromFlags("", c.kubeConfig)
		if err != nil {
			return fmt.Errorf("while reading kubeconfig: %w", err)
		}
	}

	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("while creating Kubernetes client: %w", err)
	}

	caKeys, caCerts, err := GenerateCAHierarchy(0)
	if err != nil {
		return fmt.Errorf("while generating CA hierarchy: %w", err)
	}

	controller := meshsigner.New(clock.RealClock{}, "meshtool.row-major.net/main", caKeys, caCerts, kc)
	go controller.Run(ctx)

	publisher := meshpublisher.New(clock.RealClock{}, "meshtool.row-major.net/main", caCerts, kc)
	go publisher.Run(ctx)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	<-signalCh

	return nil
}

// GenerateCAHierarchy makes a CA hierarchy, possibly with intermediates.  The
// outputs can be used with Controller.
func GenerateCAHierarchy(numIntermediates int) ([]crypto.PrivateKey, [][]byte, error) {
	caKeys := []crypto.PrivateKey{}
	caCerts := [][]byte{}

	rootPubKey, rootPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("while generating root key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	rootTemplate := &x509.Certificate{
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPubKey, rootPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("while generating root certificate: %w", err)
	}

	caKeys = append(caKeys, rootPrivKey)
	caCerts = append(caCerts, rootDER)

	for i := 0; i < numIntermediates; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("while generating intermediate key: %w", err)
		}

		template := &x509.Certificate{
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}

		signingCert, err := x509.ParseCertificate(caCerts[len(caCerts)-1])
		if err != nil {
			return nil, nil, fmt.Errorf("while parsing previous cert: %w", err)
		}

		intermediateDER, err := x509.CreateCertificate(rand.Reader, template, signingCert, pubKey, caKeys[len(caCerts)-1])
		if err != nil {
			return nil, nil, fmt.Errorf("while signing intermediate certificate: %w", err)
		}

		caKeys = append(caKeys, privKey)
		caCerts = append(caCerts, intermediateDER)
	}

	return caKeys, caCerts, nil
}
