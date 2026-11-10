"""Tests for the generic helpers and parameter validation."""

# pylint: disable=protected-access,missing-function-docstring

import os
import stat
from urllib.error import URLError

import pytest

import letsencrypt_mgmt_profile_with_cloudflare_dns as script
from tests.fakes import FakeResponse, http_error

S = script


def test_b64_is_unpadded_urlsafe():
    assert S._b64(b"\xfb\xff") == "-_8"


@pytest.mark.parametrize(
    "value, expected",
    [("true", True), (" TRUE ", True), ("false", False), (None, False)],
)
def test_is_true(value, expected):
    assert S._is_true(value) is expected


@pytest.mark.parametrize("url", ["https://a.test/x", "http://a.test/x"])
def test_check_url_allows_http_and_https(url):
    assert S._check_url(url) == url


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://a.test/x"])
def test_check_url_rejects_other_schemes(url):
    with pytest.raises(S.LetsEncryptError, match="non-HTTP"):
        S._check_url(url)


def test_cmd_returns_stdout():
    assert S._cmd(["openssl", "version"]).startswith(b"OpenSSL")


def test_cmd_passes_input():
    out = S._cmd(["openssl", "dgst", "-sha256", "-r"], cmd_input=b"abc")
    assert out.startswith(b"ba7816bf")


def test_cmd_raises_with_stderr():
    with pytest.raises(IOError, match="Custom error"):
        S._cmd(
            ["openssl", "rsa", "-in", "/nonexistent/key"],
            err_msg="Custom error",
        )


def test_write_private_file_is_owner_only(tmp_path):
    path = tmp_path / "key"
    path.write_text("old contents that are longer")
    os.chmod(path, 0o644)
    S._write_private_file(str(path), "new")
    assert path.read_text() == "new"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


class TestDoRequest:
    """_do_request(): the ACME HTTP helper."""

    @staticmethod
    def respond(monkeypatch, result):
        def urlopen(request, context=None):
            assert context is not None
            assert request.get_header("Content-type") == (
                "application/jose+json"
            )
            if isinstance(result, Exception):
                raise result
            return result

        monkeypatch.setattr(S, "urlopen", urlopen)

    def test_json_response(self, monkeypatch):
        self.respond(monkeypatch, FakeResponse({"a": 1}, 201, {"H": "v"}))
        assert S._do_request("https://a.test") == ({"a": 1}, 201, {"H": "v"})

    def test_non_json_response_is_returned_as_text(self, monkeypatch):
        self.respond(monkeypatch, FakeResponse("PEM DATA"))
        assert S._do_request("https://a.test")[0] == "PEM DATA"

    def test_error_status_raises_value_error(self, monkeypatch):
        error = http_error("https://a.test", 403, {"type": "unauthorized"})
        self.respond(monkeypatch, error)
        with pytest.raises(ValueError, match=r"(?s)Oops:.*Response Code: 403"):
            S._do_request("https://a.test", err_msg="Oops")

    def test_bad_nonce_raises_index_error(self, monkeypatch):
        error = http_error("https://a.test", 400, {"type": S.ACME_BAD_NONCE})
        self.respond(monkeypatch, error)
        with pytest.raises(IndexError):
            S._do_request("https://a.test")

    def test_bad_nonce_gives_up_after_max_retries(self, monkeypatch):
        error = http_error("https://a.test", 400, {"type": S.ACME_BAD_NONCE})
        self.respond(monkeypatch, error)
        with pytest.raises(ValueError, match="Response Code: 400"):
            S._do_request("https://a.test", depth=S.ACME_MAX_NONCE_RETRIES)

    @pytest.mark.parametrize("body", ["not json", {"detail": "no type"}])
    def test_other_400_is_not_a_bad_nonce(self, monkeypatch, body):
        self.respond(monkeypatch, http_error("https://a.test", 400, body))
        with pytest.raises(ValueError, match="Response Code: 400"):
            S._do_request("https://a.test")

    def test_network_error_raises_value_error(self, monkeypatch):
        self.respond(monkeypatch, URLError("connection refused"))
        with pytest.raises(ValueError, match="Response Code: None"):
            S._do_request("https://a.test")

    def test_rejects_file_url(self):
        with pytest.raises(S.LetsEncryptError):
            S._do_request("file:///etc/passwd")


class TestSettings:
    """Settings.from_kwargs(): parameter validation."""

    def test_defaults(self, kwargs, capsys):
        del kwargs["directory_url"]
        settings = S.Settings.from_kwargs(kwargs)
        assert settings.directory_url == S.DEFAULT_DIRECTORY_URL
        assert settings.contact is None
        assert settings.debug is False
        out = capsys.readouterr().out
        assert "zone will be looked up" in out
        assert "dry_run is: False" in out

    def test_all_parameters(self, kwargs, capsys):
        kwargs.update(
            debug="true",
            dryrun="true",
            contact="admin@example.com",
            cloudflare_zone_id="zone-9",
        )
        settings = S.Settings.from_kwargs(kwargs)
        assert settings.debug is True
        # An explicit directory_url wins over dryrun.
        assert settings.directory_url == "https://acme.test/directory"
        assert settings.contact == ["mailto:admin@example.com"]
        out = capsys.readouterr().out
        assert "Debug enabled." in out
        assert "Using Cloudflare zone id zone-9" in out

    def test_dryrun_uses_staging(self, kwargs):
        del kwargs["directory_url"]
        kwargs["dryrun"] = "True"
        settings = S.Settings.from_kwargs(kwargs)
        assert settings.directory_url == S.DEFAULT_STAGING_DIRECTORY_URL

    @pytest.mark.parametrize("value", ["", None])
    def test_empty_values_mean_not_set(self, kwargs, value):
        kwargs.update(contact=value, cloudflare_zone_id=value)
        settings = S.Settings.from_kwargs(kwargs)
        assert settings.contact is None

    def test_contact_without_at_sign_is_ignored(self, kwargs, capsys):
        kwargs["contact"] = "not-an-email"
        assert S.Settings.from_kwargs(kwargs).contact is None
        assert "Ignoring contact 'not-an-email'" in capsys.readouterr().out

    @pytest.mark.parametrize("token", [None, ""])
    def test_cloudflare_token_required(self, kwargs, token):
        kwargs["cloudflare_api_token"] = token
        with pytest.raises(S.LetsEncryptError, match="cloudflare_api_token"):
            S.Settings.from_kwargs(kwargs)
