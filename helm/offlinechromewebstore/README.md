# Helm deployment

The chart already supports the three components. Version 0.2 adds an explicit
air-gapped profile, offline runtime egress denial, private-registry credentials
for the builder Job, read-only store mounts, TLS references, common scheduling
values and values-schema validation.

```sh
helm lint helm/offlinechromewebstore
helm template cws helm/offlinechromewebstore \
  -f helm/offlinechromewebstore/values-airgapped.yaml -f your-reviewed-values.yaml
```

Inspect the rendered manifests before installing. This repository does not
install them automatically. In your air-gapped cluster:

1. Preload/mirror tested images and select explicit image tags. The chart does
   not publish images or promise that `latest` contains current source changes.
2. Keep `cwssync.enabled=false`. No ExtensionTotal key belongs in this cluster.
3. Populate the artifacts PVC with the full completed snapshot, including
   metadata/blocklist sidecars, before running/re-running the builder hook Job.
   The Job writes both assets and `artifacts/extensions_info.json`.
4. Use the air-gapped profile. `pullPolicy: Never` requires images on every
   scheduled node. For a private registry, override pull policies deliberately
   and reference existing secrets with `imagePullSecrets`.
5. `networkPolicy.offlineRuntime=true` denies **all pod egress** for build/store,
   including DNS, but leaves inbound store access and online sync unchanged.
   It requires an enforcing CNI. Kubernetes network policies are additive:
   another policy that allows egress for these pods defeats this deny-only
   intent. Audit all matching policies and verify actual network behavior.
   Image pulls happen at node level and are not constrained by this policy.
6. With default ReadWriteOnce PVCs, schedule all components onto the same node
   (use `nodeSelector`/`affinity`), or use ReadWriteMany storage. ReadWriteOncePod
   is not suitable when multiple enabled components share the PVC.
7. Store artifact/assets mounts are read-only; builder/sync keep necessary write
   access. Never share live-changing snapshots across a transfer boundary.

For HTTPS ingress, set `cwsstore.ingress.enabled=true`, the intended host/class,
and `cwsstore.ingress.tls` to entries with `hosts` and an existing `secretName`.
No private keys or API keys belong in values files. Configure client trust.
Use `/admin` to generate policy for the actual client-reachable HTTPS origin.

Local validation (requires Helm):

```sh
HELM_BIN=helm python -m pytest -q tests/test_helm.py
```

Helm lint/template tests are not a live-cluster acceptance result. Verify the
PVC lifecycle, scheduling, CNI egress behavior, ingress/TLS and Chrome installation
and update on your own target cluster before rollout.

NetworkPolicy semantics:
https://kubernetes.io/docs/concepts/services-networking/network-policies/
