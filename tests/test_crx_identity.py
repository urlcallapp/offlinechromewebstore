"""Offline identity consistency, not signature verification or authenticity."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import zipfile

import pytest
import cwsbuild
from conftest import FIXTURE_CRX_DIR, TAMPERMONKEY_ID, TRANSLATE_ID
from crx_helpers import KEY, crx3, crx3_header, field, key_id, varint


def archive(version='1.0', manifest_extra=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as package:
        package.writestr('manifest.json', json.dumps({
            'name': 'Internal tool', 'version': version, **(manifest_extra or {}),
        }))
    return stream.getvalue()


def write(tmp_path, contents, name='Internal Tool.crx'):
    path = tmp_path / name
    path.write_bytes(contents)
    return path


@pytest.mark.parametrize('extension_id', [TAMPERMONKEY_ID, TRANSLATE_ID])
def test_real_crx3_identity(extension_id):
    assert cwsbuild.read_crx_id(Path(FIXTURE_CRX_DIR) / f'{extension_id}.crx') == extension_id


def test_arbitrary_filename_builds_and_preserves_bytes(tmp_path):
    artifacts = tmp_path / 'artifacts'
    packages = artifacts / 'extensions' / 'internal'
    packages.mkdir(parents=True)
    original = (Path(FIXTURE_CRX_DIR) / f'{TAMPERMONKEY_ID}.crx').read_bytes()
    path = write(packages, original)
    index = cwsbuild.build_index(artifacts_dir=str(artifacts), dest_folder=str(tmp_path / 'assets'))
    assert index[0]['extension_id'] == TAMPERMONKEY_ID
    assert index[0]['name'] == 'Tampermonkey'
    assert index[0]['versions'][0]['path_url'] == 'artifacts/extensions/internal/Internal Tool.crx'
    assert path.read_bytes() == original


def test_filename_mismatch_rejected_before_assets(tmp_path, caplog):
    packages = tmp_path / 'extensions'
    packages.mkdir()
    shutil.copy(Path(FIXTURE_CRX_DIR) / f'{TAMPERMONKEY_ID}.crx', packages / f'{TRANSLATE_ID}_Fake_1.crx')
    assets = tmp_path / 'assets'
    assert cwsbuild.build_index(artifacts_dir=str(tmp_path), dest_folder=str(assets)) == []
    assert 'does not match CRX ID' in caplog.text
    assert not assets.exists()


def test_blocklist_uses_extracted_id_with_arbitrary_name(tmp_path):
    packages = tmp_path / 'extensions'
    packages.mkdir()
    shutil.copy(Path(FIXTURE_CRX_DIR) / f'{TAMPERMONKEY_ID}.crx', packages / 'tool.crx')
    (tmp_path / 'malicious_extensions.json').write_text(json.dumps([TAMPERMONKEY_ID]))
    assert cwsbuild.build_index(artifacts_dir=str(tmp_path), dest_folder=str(tmp_path / 'assets')) == []


def test_metadata_uses_extracted_id(tmp_path):
    packages = tmp_path / 'extensions'
    packages.mkdir()
    write(packages, crx3(archive()))
    (tmp_path / 'extension_metadata.json').write_text(json.dumps({key_id(): {'origin': 'in-house', 'tags': ['internal']}}))
    index = cwsbuild.build_index(artifacts_dir=str(tmp_path), dest_folder=str(tmp_path / 'assets'))
    assert index[0]['origin'] == 'in-house'
    assert index[0]['tags'] == ['internal']


def test_crx2_key_identity(tmp_path):
    signature = b'structural fixture only'
    package = b'Cr24' + struct.pack('<III', 2, len(KEY), len(signature)) + KEY + signature + archive()
    assert cwsbuild.read_crx_id(write(tmp_path, package)) == key_id()


def test_manifest_key_never_overrides_header(tmp_path):
    assert cwsbuild.read_crx_id(write(tmp_path, crx3(archive(manifest_extra={'key': 'different'})))) == key_id()


def test_additional_publisher_proof_and_unknown_fields(tmp_path):
    extra_proof = field(1, b'publisher') + field(2, b'publisher signature')
    extra = field(3, extra_proof) + field(42, b'unknown') + varint(43 << 3) + varint(123)
    assert cwsbuild.read_crx_id(write(tmp_path, crx3(archive(), extra=extra))) == key_id()


def test_ecdsa_developer_proof(tmp_path):
    header = field(3, field(1, KEY) + field(2, b'signature')) + field(10000, field(1, hashlib.sha256(KEY).digest()[:16]))
    package = b'Cr24' + struct.pack('<II', 3, len(header)) + header + archive()
    assert cwsbuild.read_crx_id(write(tmp_path, package)) == key_id()


@pytest.mark.parametrize('header', [
    b'', b'\x00', b'\x80' * 11, b'\x0b', b'\x0a\x05x',
    field(10000, field(1, b'short')),
    field(10000, field(1, b'x' * 16)),  # no developer proof
    crx3_header(raw_id=b'x' * 16),  # key/hash mismatch
    crx3_header(extra=field(10000, field(1, b'x' * 16))),  # duplicate signed data
    field(10000, field(1, b'x' * 16) + field(1, b'y' * 16)),
    crx3_header(proof=field(1, KEY)),  # no signature bytes
    crx3_header(proof=field(1, KEY) + field(1, KEY) + field(2, b'sig')),
    crx3_header(extra=varint(2 << 3) + varint(1)),  # wrong proof wire type
])
def test_invalid_crx3_header_rejected(tmp_path, header):
    package = b'Cr24' + struct.pack('<II', 3, len(header)) + header + archive()
    with pytest.raises(ValueError):
        cwsbuild.read_crx_id(write(tmp_path, package))


@pytest.mark.parametrize('contents', [
    b'', b'not crx', archive(),
    b'Cr24' + struct.pack('<II', 99, 1),
    b'Cr24' + struct.pack('<II', 3, cwsbuild.MAX_CRX_HEADER_SIZE + 1),
    b'Cr24' + struct.pack('<II', 3, 100) + b'short',
    b'Cr24' + struct.pack('<II', 2, 1),
    b'Cr24' + struct.pack('<III', 2, 0, 1) + b'x',
    b'Cr24' + struct.pack('<III', 2, 1, 0) + b'x',
    b'Cr24' + struct.pack('<III', 2, cwsbuild.MAX_CRX_HEADER_SIZE, 1),
    b'Cr24' + struct.pack('<III', 2, 10, 10) + b'x',
    crx3(b'not a zip'),
])
def test_invalid_package_never_falls_back_to_filename(tmp_path, contents, caplog):
    packages = tmp_path / 'extensions'
    packages.mkdir()
    write(packages, contents, key_id() + '.crx')
    assert cwsbuild.build_index(artifacts_dir=str(tmp_path), dest_folder=str(tmp_path / 'assets')) == []
    assert 'Skipping CRX with invalid identity' in caplog.text


def test_invalid_id_trailing_newline():
    assert not cwsbuild.is_valid_extension_id('a' * 32 + '\n')


def test_header_check_is_explicitly_not_signature_verification(tmp_path):
    # Synthetic, non-DER key and fake signature are intentionally accepted by
    # structural parsing. Never advertise this result as cryptographic trust.
    assert cwsbuild.read_crx_id(write(tmp_path, crx3(archive()))) == key_id()


def test_same_key_versions_merge_and_new_key_changes_identity(tmp_path):
    packages = tmp_path / 'extensions'
    packages.mkdir()
    write(packages, crx3(archive('1.0')), 'Internal_v1.crx')
    write(packages, crx3(archive('2.0')), 'Internal_v2.crx')
    write(packages, crx3(archive('3.0'), key=b'rotated key'), 'Rotated.crx')
    index = cwsbuild.build_index(artifacts_dir=str(tmp_path), dest_folder=str(tmp_path / 'assets'))
    by_id = {entry['extension_id']: entry for entry in index}
    assert set(by_id) == {key_id(), key_id(b'rotated key')}
    assert [v['version'] for v in by_id[key_id()]['versions']] == ['2.0', '1.0']


def test_matching_conventional_filename_still_works(tmp_path):
    packages = tmp_path / 'extensions'
    packages.mkdir()
    write(packages, crx3(archive()), key_id() + '_Tool_1.0.crx')
    index = cwsbuild.build_index(artifacts_dir=str(tmp_path), dest_folder=str(tmp_path / 'assets'))
    assert index[0]['extension_id'] == key_id()
    assert index[0]['versions'][0]['version'] == '1.0'
