"""Shared fixtures for the controlscript tests."""

# Fixtures that use other fixtures necessarily shadow their names.
# pylint: disable=redefined-outer-name,unused-argument

import shutil
import subprocess
import types

import pytest

import letsencrypt_mgmt_profile_with_cloudflare_dns as script
from tests.fakes import FakeAcme, FakeCloudflare, FakeNetwork

TOKEN = "test-token"


def make_csr(directory, common_name=None, sans=(), key_type="rsa:2048"):
    """Create a CSR with openssl and return its PEM text.

    key_type is "rsa:<bits>" or "ec:<openssl curve name>"."""
    key, csr = directory / "domain.key", directory / "domain.csr"
    algorithm, size = key_type.split(":")
    cmd = ["openssl", "req", "-new", "-nodes", "-newkey", algorithm]
    if algorithm == "rsa":
        cmd += ["-pkeyopt", f"rsa_keygen_bits:{size}"]
    else:
        cmd += ["-pkeyopt", f"ec_paramgen_curve:{size}"]
    cmd += ["-keyout", str(key), "-out", str(csr)]
    cmd += ["-subj", f"/CN={common_name}" if common_name else "/O=Test"]
    if sans:
        cmd += ["-addext", "subjectAltName=" + ",".join(sans)]
    subprocess.run(cmd, check=True, capture_output=True)
    return csr.read_text()


@pytest.fixture(scope="session")
def rsa_key(tmp_path_factory):
    """One 2048-bit RSA account key shared by all tests (fast)."""
    path = tmp_path_factory.mktemp("keys") / "account.key"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(path), "2048"],
        check=True,
        capture_output=True,
    )
    return path


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    """Keep every test away from /tmp/letsencrypt.key, real time and the
    zone cache of other tests."""
    monkeypatch.setattr(
        script, "ACCOUNT_KEY_PATH", str(tmp_path / "letsencrypt.key")
    )
    script._CF_ZONE_CACHE.clear()  # pylint: disable=protected-access
    clock = types.SimpleNamespace(now=1000.0, sleeps=[])

    def sleep(seconds):
        clock.sleeps.append(seconds)
        clock.now += seconds

    monkeypatch.setattr(
        script,
        "time",
        types.SimpleNamespace(time=lambda: clock.now, sleep=sleep),
    )
    return clock


@pytest.fixture
def account_key(rsa_key):
    """Put the shared RSA key where the script expects its account key."""
    shutil.copy(rsa_key, script.ACCOUNT_KEY_PATH)
    return script.ACCOUNT_KEY_PATH


@pytest.fixture
def cloudflare():
    """A fake Cloudflare account with the zone example.com."""
    return FakeCloudflare(token=TOKEN)


@pytest.fixture
def acme(cloudflare, account_key):
    """A fake ACME server that knows the account key's thumbprint."""
    server = FakeAcme(cloudflare)
    _, server.thumbprint = script._account_jwk()  # pylint: disable=W0212
    return server


@pytest.fixture
def network(monkeypatch, acme, cloudflare):
    """Route the script's urlopen() calls to the fake services."""
    net = FakeNetwork(acme, cloudflare)
    monkeypatch.setattr(script, "urlopen", net.urlopen)
    return net


@pytest.fixture
def kwargs():
    """Minimal valid controlscript parameters."""
    return {
        "directory_url": "https://acme.test/directory",
        "cloudflare_api_token": TOKEN,
    }
