"""Tests for the ACME client, CSR and account-key handling, and the full
certificate_request() flow."""

# pylint: disable=protected-access,missing-function-docstring
# pylint: disable=redefined-outer-name,unused-argument
# Tests request many fixtures.
# pylint: disable=too-many-arguments,too-many-positional-arguments

import os
import stat
from pathlib import Path

import pytest

import letsencrypt_mgmt_profile_with_cloudflare_dns as script
from tests.conftest import make_csr
from tests.fakes import ACME, CERT_PEM, b64decode

S = script


class TestAccountKey:
    """_ensure_account_key() and _account_jwk()."""

    def test_reuses_existing_key(self, account_key, capsys):
        before = Path(account_key).read_text(encoding="utf-8")
        S._ensure_account_key(debug=True)
        assert Path(account_key).read_text(encoding="utf-8") == before
        assert "Reusing account key" in capsys.readouterr().out

    def test_generates_private_key(self, capsys):
        S._ensure_account_key(debug=False)
        mode = stat.S_IMODE(os.stat(S.ACCOUNT_KEY_PATH).st_mode)
        assert mode == 0o600
        jwk, _ = S._account_jwk()
        # 4096-bit modulus
        assert len(b64decode(jwk["n"])) == 512
        assert "Generating account key" in capsys.readouterr().out

    def test_jwk_matches_key(self, account_key):
        jwk, thumbprint = S._account_jwk()
        assert jwk["kty"] == "RSA"
        assert b64decode(jwk["e"]) == b"\x01\x00\x01"  # 65537
        assert len(b64decode(jwk["n"])) == 256  # 2048 bits
        assert len(b64decode(thumbprint)) == 32  # SHA-256

    def test_odd_length_exponent_is_padded(self, monkeypatch):
        # Exponent 3 is "3" in hex, which must be padded to "03".
        out = b"modulus:\n    00:ab:cd\npublicExponent: 3 (0x3)\n"
        monkeypatch.setattr(S, "_cmd", lambda *a, **k: out)
        jwk, _ = S._account_jwk()
        assert b64decode(jwk["e"]) == b"\x03"
        assert b64decode(jwk["n"]) == b"\xab\xcd"

    def test_unparseable_key(self, monkeypatch):
        monkeypatch.setattr(S, "_cmd", lambda *a, **k: b"EC Private-Key")
        with pytest.raises(S.LetsEncryptError, match="RSA account key"):
            S._account_jwk()


def csr_text(tmp_path, csr):
    (tmp_path / "x.csr").write_text(csr)
    return S._csr_text(str(tmp_path / "x.csr"))


class TestCsrDomains:
    """_csr_domains(): read the CN and DNS SANs."""

    def test_cn_and_sans(self, tmp_path):
        csr = make_csr(
            tmp_path,
            "www.example.com",
            ["DNS:www.example.com", "DNS:example.com", "IP:192.0.2.1"],
        )
        assert S._csr_domains(csr_text(tmp_path, csr)) == [
            "example.com",
            "www.example.com",
        ]

    def test_cn_only(self, tmp_path):
        csr = make_csr(tmp_path, "a.example.com")
        assert S._csr_domains(csr_text(tmp_path, csr)) == ["a.example.com"]

    def test_sans_only(self, tmp_path):
        csr = make_csr(tmp_path, None, ["DNS:b.example.com"])
        assert S._csr_domains(csr_text(tmp_path, csr)) == ["b.example.com"]

    def test_invalid_csr(self, tmp_path):
        (tmp_path / "x.csr").write_text("not a csr")
        with pytest.raises(IOError, match="Error loading"):
            S._csr_text(str(tmp_path / "x.csr"))


class TestCheckCsrKey:
    """_check_csr_key(): reject keys Let's Encrypt won't sign."""

    @pytest.mark.parametrize(
        "key_type",
        ["rsa:2048", "rsa:3072", "rsa:4096", "ec:prime256v1", "ec:secp384r1"],
    )
    def test_supported(self, tmp_path, key_type):
        csr = make_csr(tmp_path, "a.example.com", key_type=key_type)
        S._check_csr_key(csr_text(tmp_path, csr))

    @pytest.mark.parametrize(
        "key_type, message",
        [
            ("rsa:1024", "uses an RSA 1024 bit key"),
            ("ec:secp521r1", "uses an ECDSA SECP521R1 key"),
        ],
    )
    def test_unsupported(self, tmp_path, key_type, message):
        csr = make_csr(tmp_path, "a.example.com", key_type=key_type)
        with pytest.raises(S.LetsEncryptError, match=message) as error:
            S._check_csr_key(csr_text(tmp_path, csr))
        assert "SECP384R1" in str(error.value)

    def test_old_openssl_rsa_format(self):
        out = (
            "Public Key Algorithm: rsaEncryption\n RSA Public Key: (1024 bit)"
        )
        with pytest.raises(S.LetsEncryptError, match="RSA 1024 bit"):
            S._check_csr_key(out)


@pytest.fixture
def client(network, account_key):
    jwk, thumbprint = S._account_jwk()
    return S.AcmeClient(f"{ACME}/directory", jwk, thumbprint)


class TestAcmeClient:
    """AcmeClient: talk to the (fake) ACME server."""

    def test_directory(self, client, capsys):
        assert client.directory["newOrder"] == f"{ACME}/new-order"
        assert client.account_url is None

    def test_register_new_account(self, client, acme, capsys):
        client.register(None)
        assert client.account_url == f"{ACME}/acct/1"
        path, protected, payload = acme.requests[0]
        assert path == "/new-acct"
        assert protected["jwk"] == client.jwk and "kid" not in protected
        assert protected["alg"] == "RS256"
        assert payload == {"termsOfServiceAgreed": True}
        assert "Registered!" in capsys.readouterr().out

    def test_register_existing_account_with_contact(
        self, client, acme, capsys
    ):
        acme.account_exists = True
        client.register(["mailto:a@example.com"])
        assert acme.contact == ["mailto:a@example.com"]
        # After registering, requests use the account URL ("kid").
        assert acme.requests[1][1]["kid"] == f"{ACME}/acct/1"
        out = capsys.readouterr().out
        assert "Already registered!" in out
        assert "Updated contact details:\nmailto:a@example.com" in out

    def test_signature_is_valid(self, client, acme, tmp_path):
        client.register(None)
        jws = acme.raw_requests[0]
        public = tmp_path / "pub.pem"
        public.write_bytes(
            S._cmd(["openssl", "rsa", "-in", S.ACCOUNT_KEY_PATH, "-pubout"])
        )
        signature = tmp_path / "sig"
        signature.write_bytes(b64decode(jws["signature"]))
        out = S._cmd(
            ["openssl", "dgst", "-sha256", "-verify", str(public)]
            + ["-signature", str(signature)],
            cmd_input=f"{jws['protected']}.{jws['payload']}".encode(),
        )
        assert out.strip() == b"Verified OK"

    def test_bad_nonce_is_retried(self, client, acme):
        acme.bad_nonce_count = 2
        client.register(None)
        assert [p for p, _, _ in acme.requests] == ["/new-acct"] * 3
        assert client.account_url == f"{ACME}/acct/1"

    def test_poll_until_not(self, client, acme, isolate):
        acme.pending_polls = 3
        result = client.poll_until_not(f"{ACME}/order/1", ["pending"], "Error")
        assert result["status"] == "valid"
        assert isolate.sleeps == [2, 2, 2]

    def test_poll_timeout(self, client, acme, isolate, monkeypatch):
        monkeypatch.setattr(S, "ACME_POLL_TIMEOUT", 10)
        acme.pending_polls = 10**6
        with pytest.raises(S.LetsEncryptError, match="Polling timeout"):
            client.poll_until_not(f"{ACME}/order/1", ["pending"], "Error")
        assert sum(isolate.sleeps) == S.ACME_POLL_TIMEOUT

    def test_failed_order(self, client, acme, tmp_path):
        client.register(None)
        acme.order_status = "invalid"
        (tmp_path / "x.csr").write_text(make_csr(tmp_path, "a.example.com"))
        order = {"finalize": f"{ACME}/finalize"}
        with pytest.raises(ValueError, match="Order failed"):
            client.finalize(order, f"{ACME}/order/1", str(tmp_path / "x.csr"))


@pytest.fixture
def csr(tmp_path):
    return make_csr(
        tmp_path, "www.example.com", ["DNS:www.example.com", "DNS:example.com"]
    )


class TestCertificateRequest:
    """certificate_request(): the Avi Controller entry point."""

    def test_issues_certificate(
        self, network, acme, cloudflare, kwargs, csr, isolate, capsys
    ):
        kwargs.update(debug="true", contact="admin@example.com")
        assert S.certificate_request(csr, "www.example.com", kwargs) == (
            CERT_PEM
        )
        # The right TXT value was published for each domain while the CA
        # validated it, and removed afterwards.
        assert acme.domains == ["example.com", "www.example.com"]
        for domain in acme.domains:
            assert acme.validated[domain] == [acme.expected_txt(domain)]
        assert cloudflare.records == {}
        assert acme.contact == ["mailto:admin@example.com"]
        # Waited for DNS propagation once per domain.
        assert isolate.sleeps.count(30) == 2
        out = capsys.readouterr().out
        assert "example.com verified!" in out
        assert "www.example.com verified!" in out
        assert "Certificate signed!" in out
        assert CERT_PEM in out

    def test_csr_temp_file_is_removed(self, network, kwargs, csr, monkeypatch):
        seen = []
        original = S.get_crt

        def get_crt(csr_path, settings, kw):
            seen.append(csr_path)
            assert Path(csr_path).read_text(encoding="utf-8") == csr
            return original(csr_path, settings, kw)

        monkeypatch.setattr(S, "get_crt", get_crt)
        S.certificate_request(csr, "www.example.com", kwargs)
        assert seen and not os.path.exists(seen[0])

    def test_csr_temp_file_is_removed_on_error(
        self, network, acme, kwargs, csr, monkeypatch
    ):
        seen = []

        def get_crt(csr_path, settings, kw):
            seen.append(csr_path)
            raise S.LetsEncryptError("boom")

        monkeypatch.setattr(S, "get_crt", get_crt)
        with pytest.raises(S.LetsEncryptError, match="boom"):
            S.certificate_request(csr, "www.example.com", kwargs)
        assert seen and not os.path.exists(seen[0])

    def test_letsencrypt_key_parameter(
        self, network, kwargs, csr, rsa_key, monkeypatch
    ):
        os.remove(S.ACCOUNT_KEY_PATH)
        kwargs["letsencrypt_key"] = rsa_key.read_text()
        S.certificate_request(csr, "www.example.com", kwargs)
        key = Path(S.ACCOUNT_KEY_PATH).read_text(encoding="utf-8")
        assert key == rsa_key.read_text()
        assert stat.S_IMODE(os.stat(S.ACCOUNT_KEY_PATH).st_mode) == 0o600

    def test_zone_cache_is_cleared_between_runs(
        self, network, acme, cloudflare, kwargs, csr
    ):
        S.certificate_request(csr, "www.example.com", kwargs)
        acme.reset()
        cloudflare.zones = {"example.com": "zone-2"}
        cloudflare.requests.clear()
        S.certificate_request(csr, "www.example.com", kwargs)
        assert ("GET", "/zones", {"name": "example.com"}) in (
            cloudflare.requests
        )

    def test_no_dns01_challenge(self, network, acme, kwargs, csr):
        acme.offer_dns01 = False
        with pytest.raises(S.LetsEncryptError, match="No dns-01 challenge"):
            S.certificate_request(csr, "www.example.com", kwargs)

    def test_unsupported_key_fails_before_any_request(
        self, network, acme, kwargs, tmp_path
    ):
        csr = make_csr(tmp_path, "a.example.com", key_type="ec:secp521r1")
        with pytest.raises(S.LetsEncryptError, match="SECP521R1"):
            S.certificate_request(csr, "a.example.com", kwargs)
        assert acme.domains == []
        assert not network.timeouts  # no HTTP request was made

    def test_failed_challenge_still_cleans_up(
        self, network, acme, cloudflare, kwargs, csr, capsys
    ):
        acme.challenge_status = "invalid"
        with pytest.raises(ValueError, match="Challenge did not pass"):
            S.certificate_request(csr, "www.example.com", kwargs)
        assert cloudflare.records == {}
        assert "Cleaning up..." in capsys.readouterr().out
