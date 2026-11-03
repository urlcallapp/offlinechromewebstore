"""Helm rendering tests. Set HELM_BIN or install helm to run these locally."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

HELM = os.environ.get('HELM_BIN') or shutil.which('helm')
ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / 'helm/offlinechromewebstore'
pytestmark = pytest.mark.skipif(not HELM, reason='helm binary not installed')


def render(*args):
    return subprocess.run([HELM, 'template', 'test', str(CHART), *args], text=True, capture_output=True)


def test_default_and_airgapped():
    default = render();assert default.returncode == 0, default.stderr
    assert 'name: cwssync' in default.stdout
    result=render('-f',str(CHART/'values-airgapped.yaml'))
    assert result.returncode == 0, result.stderr
    assert 'name: cwssync' not in result.stdout
    assert 'kind: NetworkPolicy' in result.stdout
    assert 'egress: []' in result.stdout
    assert 'values: [cwsbuild, cwsstore]' in result.stdout
    assert result.stdout.count('imagePullPolicy: Never') == 2
    assert result.stdout.count('readOnly: true') == 2


def test_private_registry_secrets_and_tls():
    result=render('--set','imagePullSecrets[0].name=registry-login','--set','cwsstore.ingress.enabled=true',
                  '--set','cwsstore.ingress.tls[0].secretName=store-tls','--set','nodeSelector.disk=ssd')
    assert result.returncode == 0,result.stderr
    assert result.stdout.count('name: registry-login') == 3
    assert 'secretName: store-tls' in result.stdout
    assert result.stdout.count('disk: ssd') == 3


@pytest.mark.parametrize('assignment',['networkPolicy.offlineRuntime=wrong','persistence.accessMode=invalid','cwsstore.replicaCount=0','cwsstore.image.pullPolicy=Sometimes'])
def test_schema_refuses_invalid_values(assignment):
    assert render('--set',assignment).returncode != 0


OPENSHIFT = str(CHART / 'values-openshift.yaml')


def openshift(*args):
    return render('-f', OPENSHIFT, '--api-versions', 'route.openshift.io/v1', *args)


def test_openshift_restricted_profile_and_route():
    result = openshift()
    assert result.returncode == 0, result.stderr
    text = result.stdout
    assert 'kind: Route' in text and 'targetPort: http' in text
    assert 'termination: edge' in text
    assert 'insecureEdgeTerminationPolicy: Redirect' in text
    assert text.count('runAsNonRoot: true') == 3
    assert text.count('automountServiceAccountToken: false') == 3
    assert text.count('type: RuntimeDefault') == 3
    assert text.count('allowPrivilegeEscalation: false') == 3
    assert text.count('readOnlyRootFilesystem: true') == 3
    assert text.count('drop: [ALL]') == 3
    assert text.count('mountPath: /tmp') == 3
    assert text.count('emptyDir: {}') == 3
    for forbidden in ['runAsUser:', 'runAsGroup:', 'fsGroup:', 'seLinuxOptions:',
                      'kind: SecurityContextConstraints', 'kind: ClusterRoleBinding',
                      'privileged: true', 'initContainers:', 'kind: Ingress', 'host:']:
        assert forbidden not in text
    assert text.count('readOnly: true') == 2


def test_openshift_disconnected_composition():
    result = openshift('-f', str(CHART / 'values-airgapped.yaml'))
    assert result.returncode == 0, result.stderr
    assert 'kind: Route' in result.stdout
    assert 'name: cwssync' not in result.stdout
    assert 'egress: []' in result.stdout
    assert result.stdout.count('imagePullPolicy: Never') == 2
    assert result.stdout.count('runAsNonRoot: true') == 2


def test_openshift_route_requires_api_and_consistent_values():
    result = render('-f', OPENSHIFT)
    assert result.returncode != 0 and 'Route API' in result.stderr
    for assignment in ['openshift.enabled=false', 'cwsstore.enabled=false',
                       'cwsstore.ingress.enabled=true']:
        assert openshift('--set', assignment).returncode != 0


def test_openshift_route_host_annotations_and_policy():
    result = openshift('--set', 'openshift.route.host=store.apps.example.test',
                       '--set-string', 'openshift.route.annotations.test=value',
                       '--set-string', 'openshift.route.insecureEdgeTerminationPolicy=None')
    assert result.returncode == 0, result.stderr
    assert 'host: "store.apps.example.test"' in result.stdout
    assert 'test: value' in result.stdout
    assert 'insecureEdgeTerminationPolicy: None' in result.stdout
    for assignment in ['openshift.enabled=wrong', 'openshift.route.enabled=wrong',
                       'openshift.route.insecureEdgeTerminationPolicy=Allow',
                       'openshift.route.termination=passthrough']:
        assert openshift('--set', assignment).returncode != 0


def test_openshift_route_optional_and_kubernetes_unchanged():
    ordinary = render()
    assert ordinary.returncode == 0
    assert 'kind: Route' not in ordinary.stdout
    assert 'runAsNonRoot:' not in ordinary.stdout
    assert 'emptyDir:' not in ordinary.stdout
    result = render('--set', 'openshift.enabled=true')
    assert result.returncode == 0, result.stderr  # internal-only, no Route API needed
    assert 'kind: Route' not in result.stdout
    assert 'runAsNonRoot: true' in result.stdout


def test_openshift_lint():
    result = subprocess.run([HELM, 'lint', str(CHART), '-f', OPENSHIFT,
                             '--set', 'openshift.route.enabled=false'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout


AUTH_ARGS=['--set','auth.enabled=true','--set','auth.origin=https://store.test','--set','auth.existingConfigMap=store-auth','--set','auth.existingSecret=store-secrets']


def test_auth_gateway_routes_and_offline_boundary():
    result=render(*AUTH_ARGS,'--set','auth.access=users-only','--set','cwsstore.ingress.enabled=true','--set','networkPolicy.offlineRuntime=true')
    assert result.returncode==0,result.stderr
    text=result.stdout
    assert 'name: test-offlinechromewebstore-cwsauth' in text
    assert 'auth_gateway.main:create_app' in text
    assert '--no-proxy-headers' in text and '--no-access-log' in text
    assert 'value: "users-only"' in text
    assert 'value: /auth-secret/gateway-secret' in text
    assert 'items:' in text
    assert 'values: [cwsbuild, cwsstore]' in text # auth not in zero-egress pod set
    assert 'ldap-bind-password' in text
    assert 'path: /crx' in text
    assert 'path: /auth/health' in text


@pytest.mark.parametrize('args',[['--set','auth.enabled=true'],['--set','auth.access=users-only'],AUTH_ARGS+['--set','cwsstore.enabled=false'],AUTH_ARGS+['--set','auth.origin=http://store.test']])
def test_auth_invalid_chart_settings(args):
    assert render(*args).returncode!=0


def test_openshift_auth_profile():
    result=openshift(*AUTH_ARGS)
    assert result.returncode==0,result.stderr
    assert result.stdout.count('runAsNonRoot: true')==4
    assert result.stdout.count('readOnlyRootFilesystem: true')==4
    assert 'name: test-offlinechromewebstore-cwsauth' in result.stdout
    assert 'termination: edge' in result.stdout
