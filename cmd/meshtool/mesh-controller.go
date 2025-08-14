package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ahmedtd/mesh-example/lib/meshpublisher"
	"github.com/ahmedtd/mesh-example/lib/meshsigner"
	"github.com/google/subcommands"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/utils/clock"
)

type MeshControllerCommand struct {
	inCluster  bool
	kubeConfig string
}

var _ subcommands.Command = (*MeshControllerCommand)(nil)

func (*MeshControllerCommand) Name() string {
	return "controller"
}

func (*MeshControllerCommand) Synopsis() string {
	return "Run the controller"
}

func (*MeshControllerCommand) Usage() string {
	return ``
}

func (c *MeshControllerCommand) SetFlags(f *flag.FlagSet) {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}

	f.StringVar(&c.kubeConfig, "kubeconfig", kubeConfigDefault, "absolute path to the kubeconfig file")
	f.BoolVar(&c.inCluster, "in-cluster", false, "Is the controller running in the cluster it should connect to?")
}

func (c *MeshControllerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *MeshControllerCommand) do(ctx context.Context) error {
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

	controller := meshsigner.New(clock.RealClock{}, caKeys, caCerts, kc)
	go controller.Run(ctx)

	publisher := meshpublisher.New(clock.RealClock{}, caCerts, kc)
	go publisher.Run(ctx)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	<-signalCh

	return nil
}
