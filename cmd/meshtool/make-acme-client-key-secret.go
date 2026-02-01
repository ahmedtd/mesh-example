package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/google/subcommands"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type MakeACMEClientKeySecretCommand struct {
	kubeConfig string

	namespace string
	name      string
}

var _ subcommands.Command = (*MakeACMEClientKeySecretCommand)(nil)

func (*MakeACMEClientKeySecretCommand) Name() string {
	return "make-acme-client-key-secret"
}

func (*MakeACMEClientKeySecretCommand) Synopsis() string {
	return "Make a new secret that contains an ED25519 private key to be used as an ACME client key"
}

func (*MakeACMEClientKeySecretCommand) Usage() string {
	return ""
}

func (c *MakeACMEClientKeySecretCommand) SetFlags(f *flag.FlagSet) {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}

	f.StringVar(&c.kubeConfig, "kubeconfig", kubeConfigDefault, "absoluate path the kubeconfig file")
	f.StringVar(&c.namespace, "namespace", "", "Create the secret in this namespace")
	f.StringVar(&c.name, "name", "", "Create the secret with this name")
}

func (c *MakeACMEClientKeySecretCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		slog.ErrorContext(ctx, "Error: ", slog.String("err", err.Error()))
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *MakeACMEClientKeySecretCommand) do(ctx context.Context) error {
	// use the current context in kubeconfig
	kconfig, err := clientcmd.BuildConfigFromFlags("", c.kubeConfig)
	if err != nil {
		return fmt.Errorf("while reading kubeconfig: %w", err)
	}

	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("while creating Kubernetes client: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("while generating ed25519 key: %w", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("while marshaling key: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      c.name,
		},
		Data: map[string][]byte{
			"client-private-key.pkcs8": pkcs8Bytes,
		},
	}

	_, err = kc.CoreV1().Secrets(c.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("while uploading key to secret: %w", err)
	}

	return nil
}
