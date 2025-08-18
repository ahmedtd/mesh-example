# Kubernetes Pod Certificate Signers

Kubernetes 1.34 shipped Pod Certificates, a new feature that streamlines issuing
X.509 certificates to pods.  This repository specifies a few example signers to
show how Pod Certificates and Cluster Trust Bundles can be used together to
enable easy TLS and mTLS between workloads running in the same (or different)
clusters.

## Getting Started (Kind)

Pod Certificates and Cluster Trust Bundles are not enabled by default, so the
easiest way to test them out is to create a local test cluster using
[Kind](https://kind.sigs.k8s.io/).

`kind/kind-config.yaml` is a cluster configuration that enables all the necessary flags to use Pod Certificates and Cluster Trust Bundles.
```
kind create cluster --image=kindest/node:latest --config=kind/kind-config.yaml
```

You can then deploy the signer controller:
```
kubectl apply -f controller-manifests
```

The signer controller will crashloop until you create the root certificates and
keys for each of the signers:
```
go run ./cmd/meshtool make-ca-pool-secret --namespace mesh-controller --name service-dns-ca-pool --ca-id 1
go run ./cmd/meshtool make-ca-pool-secret --namespace mesh-controller --name spiffe-ca-pool --ca-id 1
```

If you like, you can now deploy some example applications that use certificates
issued by the signer controller in different configurations.
```
kubectl apply -f example-manifests/
```

## Signers

### row-major.net/service-dns

This signer issues "standard" server TLS certificates for the DNS names of all
Services the pod is part of.  Note that the set of Services that a pod is part
of can change over time as Services are added and deleted, or their label
selectors are changed.  These updates will not be reflected until the next time
the certificate is refreshed.

This signer distributes its trust anchors using signer-linked
ClusterTrustBundles.  Use the label selector
`service-dns.row-major.net/canarying=live`.

Clients do not need any special certificate validation logic, beyond configuring
the proper trust bundle.  If they connect to a Service via the DNS name
`<service>.<namespace>.svc`, then standard TLS certificate validation will work.

The certificates issued by this signer have the following properties:
* The Subject field is entirely empty
* For each Service that the Pod is part of at the time the certificate is
  issued, there is one DNS Subject Alternate Name of the form
  `<service-name>.<service-namespace>.svc`.
* There are no other Subject Alternate Names.
* The maximum lifetime is 24 hours.
* The certificates are backdated by an unspecified amount sufficient to cover
  reasonable clock skew.

These certificates cannot meaningfully be used as client certificates.

### row-major.net/spiffe

This signer issues SPIFFE certificates to pods, with SPIFFE identities of the form `spiffe://<trust-domain>/ns/<pod-namespace>/sa/<pod-service-account>`.
* `trust-domain` is a configurable value for the SPIFFE trust domain.  In the
  demo, it defaults to `cluster.local`, but in a real deployment you will need
  to choose a value that makes sense, especially if you are expecting
  communication across multiple clusters.
* `pod-namespace` is the namespace of the Pod that the certificate was issued to.
* `pod-service-account` is the name of the ServiceAccount that the Pod is running as.

This signer distributes its trust anchors using signer-linked
ClusterTrustBundles.  Use the label selectors
`spiffe.row-major.net/canarying=live` and
`spiffe.row-major.net/trust-domain=<trust-domain>`.

### row-major.net/pod-identity

TODO

## Examples

In namespace `service-dns-unauth-client`, you'll find a client-server pair where
the server uses a certificate issued by `row-major.net/service-dns`,
and the client is configured to verify the server certificate using standard TLS
validation.  The client doesn't send any credentials to the server.

In namespace `service-dns-spiffe-client`, you'll find a client-server pair where
the server uses a certificate issued by `row-major.net/service-dns`,
and the client is configured to verify the server certificate using standard TLS
validation.  The client uses a certificate issued by
`row-major.net/spiffe` as its credentials, and the server is configured
to verify the certificate, extract the SPIFFE identity, and echo it back in the
response.

## Open Problems

Right now, `row-major.net/spiffe` assumes that all communication is
happening within one trust domain.  SPIFFE allows federation between multiple
trust domains.  These trust domains do not necessarily align with clusters --
multiple clusters could be part of the same trust domain.  We need to figure out
a way to distribute trust anchors for trust domains you have federated with.
This will probably consist of creating ClusterTrustBundles with particular
labels.

`row-major.net/service-dns` does the pod-to-service lookup in a pretty
dumb, brute-force way right now.  It should use informers to maintain a mapping
from pods to services, and also allow pods to specify which services should be
included in the certificate.  We also need to support a suffix on the DNS names,
for cross-cluster communication when the clusters share a common DNS server.

We need a "full SPIFFE" example, where both the client and server use SPIFFE
certificates.

Each cluster already has a configurable OIDC issuer --- we should probably also
embed this URL into the certificates we issue, so that it's possible to tell
which cluster issued a certificate.  You could even imagine extending OIDC so
that we also serve the CA trust anchors at a well-known URL below the issuer
URL.

All of the clients and servers need to be updated to seamlessly handle
certificate refresh.

