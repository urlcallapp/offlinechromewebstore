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
