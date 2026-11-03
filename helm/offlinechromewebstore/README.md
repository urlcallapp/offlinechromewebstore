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

## OpenShift profile (chart 0.3)

The opt-in profile targets OpenShift's restricted-style SCC admission without
creating or changing an SCC, granting `anyuid`, adding cluster RBAC, or pinning a
namespace-specific UID, GID, fsGroup or SELinux label. It does not select an
OpenShift version for you. Cluster policy and storage compatibility must be
checked on your actual version. Standard Kubernetes defaults are unchanged.

Offline manifest review, with no cluster connection:

```sh
helm lint helm/offlinechromewebstore \
  -f helm/offlinechromewebstore/values-openshift.yaml \
  --set openshift.route.enabled=false
helm template cws helm/offlinechromewebstore \
  -f helm/offlinechromewebstore/values-openshift.yaml \
  -f helm/offlinechromewebstore/values-airgapped.yaml \
  --api-versions route.openshift.io/v1 \
  -f your-reviewed-values.yaml
```

`helm lint` has no `--api-versions` option, so lint the restricted pod profile
with Route disabled, then render Route separately as above. On a real Helm
installation API discovery supplies `route.openshift.io/v1`; enabling Route on
a cluster without that API fails explicitly. Route and Ingress are mutually
exclusive. Route requires the store to be enabled. For internal-only service
access set `openshift.enabled=true` and `openshift.route.enabled=false`.

### Security and filesystem

For all enabled components, the profile sets non-root execution, RuntimeDefault
seccomp, no privilege escalation, drops all capabilities, disables service
account token automount, and uses a read-only container root filesystem with a
writable `emptyDir` mounted at `/tmp`. Port 8005 is unprivileged. SCC admission
must supply an allowed arbitrary UID, fsGroup and SELinux context. No root
init-container, `chown`, hostPath, host network, or privileged escape is added.
The app source/dependencies only need read access; builder/sync write to their
mounted PVCs, and build staging uses the assets PVC. Store PVC mounts stay
read-only. Python bytecode cache is optional and not a required write path.

**PVC contents do not inherit image permissions.** The CSI/storage provider
must support the SCC-assigned groups/SELinux labels and grant builder/sync read,
write, create and rename access to the artifacts/assets directories. Imported
files must be readable by the store. Prepare permissions in the approved data
transfer process, not with a privileged init-container. Root-squashed NFS,
pre-populated ownership, and drivers that ignore fsGroup can require storage
administrator work. Do not fix these by granting `anyuid` or mode 0777. Preserve
the existing RWO same-node or RWX scheduling requirements. The chart still
creates retained PVCs; do not assume an upgrade can change an existing PVC's
storage class or access mode.

### Route and TLS

The profile enables a `route.openshift.io/v1` Route targeting the store Service's
named `http` port. It uses **edge termination** and redirects HTTP to HTTPS by
default (`None` is available to disable insecure traffic). The store backend is
HTTP; passthrough and reencrypt are deliberately not offered. Edge TLS encrypts
the client-to-router connection, not router-to-pod traffic.

`openshift.route.host` may be empty for an assigned ingress-domain hostname, or
set to a DNS name the router can admit. Optional `openshift.route.annotations`
are rendered verbatim. The Route uses the router's default serving certificate;
no private key is placed in Helm values and Kubernetes Ingress `tls.secretName`
is not a Route secret reference. A custom hostname must be covered by the
router certificate, DNS and client trust. Custom per-route certificates and
backend TLS are not implemented in this increment. Obtain the admitted hostname
with `oc get route <release>-offlinechromewebstore-cwsstore` and use its actual
HTTPS origin in `/admin` exports. A rendered Route is not evidence of admission.

### Cluster acceptance checklist

No live OpenShift cluster has been used to validate this profile. Before rollout:

1. Mirror/build and pin the tested image digests/tags. Published `latest` images
   are not assumed to match this source. Check SCC admission and the actual
   generated pod security contexts without broadening service-account grants.
2. Verify arbitrary-UID runtime startup and writable PVC create/rename/delete for
   sync/build, read-only store access and `/tmp` scratch. Re-run the builder hook
   after loading a completed snapshot. Check pod/job logs for permission errors.
3. Confirm storage binding, SELinux behavior, scheduling and retained-PVC upgrade
   behavior on your CSI driver. No storage migration is performed by this chart.
4. Verify Route admission, DNS, serving certificate/client trust, `/json`, `/crx`,
   package download, and actual Chrome install/update via the admitted hostname.
5. Compose `values-airgapped.yaml` for disconnected clusters: OpenShift alone
   does **not** disable online cwssync. Review image pulls and optional runtime
   egress-deny policy separately. An existing ingress-deny policy must permit
   router-to-store traffic; this chart does not change it. Check the actual CNI
   and all additive NetworkPolicies. Node image pulls are outside pod egress.

References:
- [Red Hat arbitrary-UID image guidance](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/images/creating-images)
- [Red Hat SCC guidance](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/authentication_and_authorization/managing-pod-security-policies)
- [Red Hat Route and edge TLS guidance](https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/networking/configuring-routes)
