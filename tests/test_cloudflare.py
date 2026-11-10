"""Tests for the Cloudflare DNS functions."""

# pylint: disable=protected-access,missing-function-docstring
# pylint: disable=redefined-outer-name,unused-argument

import json
from urllib.error import URLError

import pytest

import letsencrypt_mgmt_profile_with_cloudflare_dns as script
from tests.fakes import FakeResponse, http_error

S = script
NAME = "_acme-challenge.www.example.com"


@pytest.fixture
def cf_kwargs(network):
    """Parameters for the Cloudflare functions, with the fake network."""
    return {"cloudflare_api_token": "test-token"}


class TestCloudflareApiError:
    """CloudflareApiError: readable messages from Cloudflare errors."""

    def test_dict_errors(self):
        error = S.CloudflareApiError(
            "POST", "/x", 400, [{"code": 81058, "message": "Identical"}]
        )
        assert error.error_codes == [81058]
        assert str(error) == (
            "Cloudflare API POST /x failed with HTTP 400: 81058: Identical"
        )

    def test_non_dict_errors(self):
        error = S.CloudflareApiError("GET", "/x", 500, ["boom"])
        assert error.error_codes == []
        assert str(error).endswith("HTTP 500: boom")

    def test_no_errors(self):
        error = S.CloudflareApiError("GET", "/x", 500, [])
        assert str(error).endswith("no error details")


class TestCfRequest:
    """_cf_request(): call the Cloudflare API."""

    def test_requires_token(self):
        with pytest.raises(S.LetsEncryptError, match="cloudflare_api_token"):
            S._cf_request("/zones", {})

    def test_get_with_params(self, cf_kwargs, cloudflare, network, capsys):
        cf_kwargs["debug"] = "true"
        result = S._cf_request("/zones", cf_kwargs, params={"name": "a b"})
        assert result == []
        assert cloudflare.requests == [("GET", "/zones", {"name": "a b"})]
        assert network.timeouts == [30]
        assert (
            "DEBUG: Cloudflare API GET "
            "https://api.cloudflare.com/client/v4/zones?name=a+b"
        ) in capsys.readouterr().out

    def test_post_payload(self, cf_kwargs, cloudflare):
        record = S._cf_request(
            "/zones/zone-1/dns_records",
            cf_kwargs,
            method="POST",
            payload={"name": NAME, "content": "v", "ttl": 1, "comment": ""},
        )
        assert cloudflare.records[record["id"]]["content"] == "v"

    def test_http_error_with_json(self, cf_kwargs):
        cf_kwargs["cloudflare_api_token"] = "wrong"
        with pytest.raises(S.CloudflareApiError) as error:
            S._cf_request("/zones", cf_kwargs)
        assert error.value.status == 403
        assert error.value.error_codes == [10000]

    @pytest.mark.parametrize(
        "response",
        [
            http_error("https://api.cloudflare.com", 502, "<html>Bad</html>"),
            FakeResponse("<html>OK?</html>", 200),
        ],
    )
    def test_non_json_body(self, monkeypatch, response):
        def urlopen(request, context=None, timeout=None):
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(S, "urlopen", urlopen)
        with pytest.raises(S.CloudflareApiError, match="<html>"):
            S._cf_request("/zones", {"cloudflare_api_token": "t"})

    @pytest.mark.parametrize(
        "body", [{"success": False}, {"success": False, "errors": None}, {}]
    )
    def test_success_false(self, monkeypatch, body):
        monkeypatch.setattr(
            S,
            "urlopen",
            lambda request, context=None, timeout=None: FakeResponse(body),
        )
        with pytest.raises(S.CloudflareApiError, match="no error details"):
            S._cf_request("/zones", {"cloudflare_api_token": "t"})


class TestZoneLookup:
    """_cf_get_zone_id(): find the zone for a record."""

    def test_zone_id_parameter_wins(self, cf_kwargs, cloudflare):
        cf_kwargs["cloudflare_zone_id"] = "zone-9"
        assert S._cf_get_zone_id(NAME, cf_kwargs) == "zone-9"
        assert cloudflare.requests == []

    def test_walks_up_and_caches(self, cf_kwargs, cloudflare, capsys):
        cf_kwargs["debug"] = "true"
        assert S._cf_get_zone_id(NAME, cf_kwargs) == "zone-1"
        assert [q["name"] for _, _, q in cloudflare.requests] == [
            "www.example.com",
            "example.com",
        ]
        assert "Using Cloudflare zone 'example.com' (zone-1)" in (
            capsys.readouterr().out
        )
        # Both candidates are cached: no further API calls.
        assert S._cf_get_zone_id(NAME, cf_kwargs) == "zone-1"
        assert len(cloudflare.requests) == 2

    def test_no_zone(self, cf_kwargs, cloudflare):
        with pytest.raises(S.LetsEncryptError, match="Zone:Read"):
            S._cf_get_zone_id("_acme-challenge.www.other.org", cf_kwargs)
        # The TLD alone is never looked up.
        assert [q["name"] for _, _, q in cloudflare.requests] == [
            "www.other.org",
            "other.org",
        ]


def test_find_txt_records_ignores_quotes(cf_kwargs, cloudflare):
    cloudflare.add_record(NAME, '"value"')
    cloudflare.add_record(NAME, "value")
    cloudflare.add_record(NAME, "other")
    cloudflare.add_record("_acme-challenge.example.com", "value")
    records = S._cf_find_txt_records("zone-1", NAME, cf_kwargs, "value")
    assert [r["id"] for r in records] == ["rec-1", "rec-2"]


@pytest.mark.parametrize(
    "value, expected",
    [(None, 30), ("0", 0), (5, 5), ("soon", 30), ([], 30)],
)
def test_dns_propagation_wait(value, expected):
    kwargs = {} if value is None else {"dns_propagation_wait": value}
    assert S._dns_propagation_wait(kwargs) == expected


class TestAddRecord:
    """add_dns_text_record()."""

    def test_adds_and_waits(self, cf_kwargs, cloudflare, isolate, capsys):
        S.add_dns_text_record("digest", NAME + ".", cf_kwargs)
        (record,) = cloudflare.records.values()
        assert record["name"] == NAME  # trailing dot removed
        assert record["content"] == "digest"
        assert record["ttl"] == S.CLOUDFLARE_TXT_TTL
        assert "ACME DNS-01 challenge" in record["comment"]
        assert isolate.sleeps == [30]
        out = capsys.readouterr().out
        assert f"Added DNS txt record {NAME} (id rec-1)" in out
        assert "Waiting 30 seconds" in out

    def test_no_wait(self, cf_kwargs, isolate, capsys):
        cf_kwargs["dns_propagation_wait"] = "0"
        S.add_dns_text_record("digest", NAME, cf_kwargs)
        assert isolate.sleeps == []
        assert "Waiting" not in capsys.readouterr().out

    def test_reuses_identical_record(self, cf_kwargs, cloudflare, capsys):
        cloudflare.add_record(NAME, "digest")
        S.add_dns_text_record("digest", NAME, cf_kwargs)
        assert len(cloudflare.records) == 1
        assert "already exists, reusing it" in capsys.readouterr().out

    def test_other_cloudflare_error(self, cf_kwargs, cloudflare, isolate):
        cloudflare.fail = (
            "POST",
            "/zones/zone-1/dns_records",
            400,
            {"success": False, "errors": [{"code": 9005, "message": "bad"}]},
        )
        with pytest.raises(S.LetsEncryptError, match="9005: bad") as error:
            S.add_dns_text_record("digest", NAME, cf_kwargs)
        assert isinstance(error.value.__cause__, S.CloudflareApiError)
        assert isolate.sleeps == []

    def test_network_error(self, monkeypatch):
        def urlopen(request, context=None, timeout=None):
            raise URLError("no route")

        monkeypatch.setattr(S, "urlopen", urlopen)
        with pytest.raises(S.LetsEncryptError, match="no route"):
            S.add_dns_text_record(
                "d",
                NAME,
                {"cloudflare_api_token": "t", "cloudflare_zone_id": "z"},
            )


class TestRemoveRecord:
    """remove_dns_text_record()."""

    def test_deletes_matching_records(self, cf_kwargs, cloudflare, capsys):
        keep = cloudflare.add_record(NAME, "someone-elses-value")
        cloudflare.add_record(NAME, "digest")
        cloudflare.add_record(NAME, '"digest"')
        S.remove_dns_text_record("digest", NAME + ".", cf_kwargs)
        assert list(cloudflare.records) == [keep]
        out = capsys.readouterr().out
        assert "Deleted DNS txt record" in out and "(id rec-2)" in out
        assert "(id rec-3)" in out

    def test_nothing_to_delete(self, cf_kwargs, capsys):
        S.remove_dns_text_record("digest", NAME, cf_kwargs)
        assert "nothing to delete" in capsys.readouterr().out

    def test_errors_are_printed_not_raised(
        self, cf_kwargs, cloudflare, capsys
    ):
        cloudflare.add_record(NAME, "digest")
        cloudflare.fail = (
            "DELETE",
            "/zones/zone-1/dns_records/",
            500,
            json.dumps({"success": False, "errors": []}),
        )
        S.remove_dns_text_record("digest", NAME, cf_kwargs)
        assert len(cloudflare.records) == 1
        assert "Error deleting DNS txt record" in capsys.readouterr().out
