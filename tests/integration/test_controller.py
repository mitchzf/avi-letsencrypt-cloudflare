"""End-to-end dry-run tests against a real Avi Controller.

The tests create everything they need on the Controller, and delete it
again afterwards:

1. a temporary copy of the local controlscript (ControlScript),
2. a temporary Certificate Management Profile that runs it, with
   dryrun=true (Let's Encrypt staging) and the Cloudflare API token,
3. a CSR certificate (sslkeyandcertificate) that uses the profile.

They then check that the certificate is signed, renew it and check that
the certificate changed. Let's Encrypt staging CA certificates that the
script imports stay on the Controller (they are shared with other
certificates).

Settings are read from these files (each is optional, but together they
must provide every required field):
    avicontroller-credentials.json   controller, username, password
                                     (project root, see the .example)
    cloudflare.ini                   cloudflare_api_token, from its
                                     dns_cloudflare_api_token line
                                     (project root, see the .example)
    tests/integration/integration-credentials.json
                                     any field below; its values win
                                     (copy the .example; or name another
                                     file in $AVI_INTEGRATION_CREDENTIALS)
The fields:
    controller            Avi Controller address
    username, password    Avi user that may create ControlScripts,
                          Certificate Management Profiles and certificates
    tenant                Avi tenant (optional, default admin)
    cloudflare_api_token  Cloudflare API token for the profile (Zone - DNS -
                          Edit, plus Zone - Zone - Read without a zone id)
    cloudflare_zone_id    Cloudflare zone id (optional; empty means the zone
                          is looked up from the common name)
    common_name           CN of the test certificate, in a Cloudflare zone
                          the token can edit

The tests only run when AVI_INTEGRATION=1 is set:

    AVI_INTEGRATION=1 poetry run pytest tests/integration --no-cov -v

(--no-cov, because these tests do not import the script, so the coverage
requirement of the unit tests cannot be met by them.)

The renewal waits AVI_RENEW_WAIT seconds (default 150) after issuing. That
must be longer than the TTL of the challenge TXT records
(CLOUDFLARE_TXT_TTL in the script, 120 seconds): otherwise a DNS resolver
of Let's Encrypt can still return the first challenge's TXT value, and the
renewal fails with "Incorrect TXT record". For the same reason, wait that
long between two runs of these tests.
"""

# pylint: disable=redefined-outer-name,missing-function-docstring

import json
import os
import time
import warnings
from pathlib import Path

import pytest
from avi.sdk.avi_api import ApiSession

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCRIPT = ROOT / "letsencrypt_mgmt_profile_with_cloudflare_dns.py"
AVI_CREDENTIALS_FILE = ROOT / "avicontroller-credentials.json"
CLOUDFLARE_INI = ROOT / "cloudflare.ini"
CREDENTIALS_FILE = Path(
    os.environ.get(
        "AVI_INTEGRATION_CREDENTIALS", HERE / "integration-credentials.json"
    )
)
RENEW_WAIT = int(os.environ.get("AVI_RENEW_WAIT", "150"))
# Name of the temporary ControlScript and Certificate Management Profile.
TEMP_NAME = "letsencrypt-cloudflare-integration-test"
# Issuing runs the controlscript (DNS propagation wait, ACME polling).
TIMEOUT = 600
REQUIRED_SETTINGS = (
    "controller",
    "username",
    "password",
    "cloudflare_api_token",
    "common_name",
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("AVI_INTEGRATION") != "1",
        reason="set AVI_INTEGRATION=1 to run against a real Controller",
    ),
]


def read_json(path):
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def read_cloudflare_ini(path):
    """Return {"cloudflare_api_token": ...} from a certbot-style ini."""
    if not path.is_file():
        return {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "dns_cloudflare_api_token" and value.strip():
            return {"cloudflare_api_token": value.strip()}
    return {}


@pytest.fixture(scope="module")
def settings():
    values = {}
    avi = read_json(AVI_CREDENTIALS_FILE)
    values.update(
        {k: avi[k] for k in ("controller", "username", "password") if k in avi}
    )
    values.update(read_cloudflare_ini(CLOUDFLARE_INI))
    # Empty values in the integration file mean "not set".
    values.update({k: v for k, v in read_json(CREDENTIALS_FILE).items() if v})
    missing = [k for k in REQUIRED_SETTINGS if not values.get(k)]
    if missing:
        pytest.fail(
            f"Missing integration settings: {', '.join(missing)}. See the "
            "docstring of tests/integration/test_controller.py."
        )
    return values


@pytest.fixture(scope="module")
def session(settings):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # verify=False and IPv6 notices
        return ApiSession(
            settings["controller"],
            settings["username"],
            settings["password"],
            tenant=settings.get("tenant") or "admin",
            timeout=TIMEOUT,
        )


def find(session, path, name):
    """Return the object named name, or None."""
    rsp = session.get(path, params={"name": name})
    assert rsp.status_code == 200, rsp.text
    results = rsp.json().get("results", [])
    return results[0] if results else None


def delete(session, path, name):
    """Delete the object named name, if it exists. Only ever called with
    the names of the tests' own objects (e.g. ones left over by an
    interrupted run)."""
    obj = find(session, path, name)
    if obj is not None:
        rsp = session.delete(f"{path}/{obj['uuid']}")
        assert rsp.status_code == 204, rsp.text


def create(session, path, data):
    rsp = session.post(path, data=data, timeout=TIMEOUT)
    assert rsp.status_code == 201, rsp.text
    return rsp.json()


@pytest.fixture(scope="module")
def cert_name(settings):
    return f"{settings['common_name']}-integration-test"


@pytest.fixture(scope="module")
def controlscript(session, cert_name):
    """A temporary copy of the local controlscript."""
    # Leftovers of an interrupted run, in dependency order.
    delete(session, "sslkeyandcertificate", cert_name)
    delete(session, "certificatemanagementprofile", TEMP_NAME)
    delete(session, "alertscriptconfig", TEMP_NAME)
    script = create(
        session,
        "alertscriptconfig",
        {
            "name": TEMP_NAME,
            "action_script": SCRIPT.read_text(encoding="utf-8"),
        },
    )
    yield script
    delete(session, "alertscriptconfig", TEMP_NAME)


@pytest.fixture(scope="module")
def profile(session, settings, controlscript):
    """A temporary Certificate Management Profile using Let's Encrypt
    staging."""
    params = [
        ("cloudflare_api_token", settings["cloudflare_api_token"], True),
        ("dryrun", "true", False),
    ]
    if settings.get("cloudflare_zone_id"):
        params.append(
            ("cloudflare_zone_id", settings["cloudflare_zone_id"], False)
        )
    prof = create(
        session,
        "certificatemanagementprofile",
        {
            "name": TEMP_NAME,
            "run_script_ref": controlscript["url"],
            "script_params": [
                {
                    "name": name,
                    "value": value,
                    "is_sensitive": sensitive,
                    "is_dynamic": False,
                }
                for name, value, sensitive in params
            ],
        },
    )
    yield prof
    delete(session, "certificatemanagementprofile", TEMP_NAME)


@pytest.fixture(scope="module")
def issued_cert(session, settings, profile, cert_name):
    """Create the CSR certificate, which runs the controlscript."""
    cert = create(
        session,
        "sslkeyandcertificate",
        {
            "name": cert_name,
            "type": "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE",
            "certificate_management_profile_ref": profile["url"],
            "key_params": {
                "algorithm": "SSL_KEY_ALGORITHM_EC",
                "ec_params": {"curve": "SSL_KEY_EC_CURVE_SECP256R1"},
            },
            "certificate": {
                "self_signed": False,
                "subject": {
                    "common_name": settings["common_name"],
                    "organization": "Integration Testing",
                    "organization_unit": "Certificate Automation",
                    "locality": "Raleigh",
                    "state": "North Carolina",
                    "country": "US",
                },
            },
        },
    )
    yield cert
    delete(session, "sslkeyandcertificate", cert_name)


def assert_signed_by_staging(cert, common_name):
    assert cert["status"] == "SSL_CERTIFICATE_FINISHED"
    details = cert["certificate"]
    assert details["certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert details["subject"]["common_name"] == common_name
    assert details["issuer"]["common_name"].startswith("(STAGING)")


def test_create_csr_is_signed(settings, issued_cert):
    assert_signed_by_staging(issued_cert, settings["common_name"])


def test_renew_replaces_certificate(session, settings, issued_cert):
    time.sleep(RENEW_WAIT)
    rsp = session.post(
        f"sslkeyandcertificate/{issued_cert['uuid']}/renew",
        data={},
        timeout=TIMEOUT,
    )
    assert rsp.status_code == 200, rsp.text
    rsp = session.get(f"sslkeyandcertificate/{issued_cert['uuid']}")
    assert rsp.status_code == 200, rsp.text
    renewed = rsp.json()
    assert_signed_by_staging(renewed, settings["common_name"])
    before, after = issued_cert["certificate"], renewed["certificate"]
    assert after["certificate"] != before["certificate"]
    assert after["serial_number"] != before["serial_number"]
    assert after["fingerprint"] != before["fingerprint"]
