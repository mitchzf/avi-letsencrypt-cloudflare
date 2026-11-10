"""
###
# Name: letsencrypt_mgmt_profile_with_cloudflare_dns.py
# Version: 0.1
# License: MIT
#
# Description -
#     This is a python script used for automatically requesting and renewing
#     certificates from Let's Encrypt using a DNS-01 Challenge.
#     To complete DNS-01 challenge, a DNS txt record needs to be added under
#     the domain name for which certificate has to be issued.
#     There are two functions provided,
#     add_dns_text_record(key_digest_64, txt_record_name, kwargs) and
#     remove_dns_text_record(key_digest_64, txt_record_name, kwargs), to add
#     and remove DNS txt record with name txt_record_name and value
#     key_digest_64 respectively.
#     All configuration information required by both the above functions can
#     be provided as sensitive parameter to the script.
#     This version adds and removes the DNS txt record in a Cloudflare hosted
#     zone using the Cloudflare v4 API
#     (https://developers.cloudflare.com/api/resources/dns/).
# Setup -
#     1. Import this script into the Avi Controller as a ControlScript at
#        <<Templates - Scripts - ControlScripts>>.
#     2. Create a Certificate Management Profile at
#        <<Templates - Security - Certificate Management>> and select the
#        ControlScript created in step 1 as its Control Script.
#     3. In the profile, create at least the following script param:
#        cloudflare_api_token (sensitive).
#        The script does not use the Avi Controller API, so no Avi
#        credentials are needed.
#     4. Go to <<Templates - Security - SSL/TLS Certificates>>, click on
#        <<Create>> and then <<Application Certificate>>.
#     5. Specify a suitable name to identify this certificate in Avi
#        Controller. (Like sub.domain.tld RSA or sub.domain2.tld ECDSA)
#     6. Change <<Type>> to <<CSR>>
#     7. Set <<Common Name>> to the domain to which the certificate should be
#        issued to and select the Certificate Management Profile created in
#        step 2.
#     8. Save and wait a few seconds for the certificate to be requested and
#        imported.
#
# Note -
#     1. This script can issue RSA and ECDSA certificates, as specified when
#        creating an application certificate (CSR) via UI.
#        Let's Encrypt only signs RSA 2048, 3072 and 4096 bit keys and
#        ECDSA SECP256R1 and SECP384R1 keys. The script rejects a CSR with
#        an RSA 1024 bit or ECDSA SECP521R1 key (which Avi can create)
#        before contacting Let's Encrypt.
#     2. No Virtual Service is needed: the domains are validated with
#        DNS-01 challenges in Cloudflare only. The CN and SANs of the CSR
#        are used as they are; a domain that is not in a Cloudflare zone
#        the token can edit fails at the Cloudflare API calls.
#
# Parameters -
#     dryrun                - True/False. If True Let's Encrypt's staging
#                             server will be used. (Default: False)
#                             Main purpose is not to get ratelimited by
#                             LetsEncrypt during testing.
#     contact               - E-mail address sent to letsencrypt for account
#                             creation. (Default: None.)
#                             (set this only once until updated, otherwise an
#                             update request will be sent every time.)
#     directory_url         - Change ACME server, e.g. for using in-house
#                             ACME server. (Default: Let's Encrypt Production)
#     letsencrypt_key       - Lets Encrypt Account Key (Default: None)
#     debug                 - True/False. Print debug output. (Default: False)
#     cloudflare_api_token  - Cloudflare API token (sensitive). Required.
#                             Required token permissions: Zone - DNS - Edit.
#                             If cloudflare_zone_id is not set,
#                             Zone - Zone - Read is also required so the zone
#                             can be discovered from the domain name.
#                             Scope the token to only the zone(s) used for
#                             certificates.
#     cloudflare_zone_id    - ID of the Cloudflare zone where DNS challenges
#                             should be published (Default: None)
#                             Optional. If not set, the zone is looked up
#                             automatically from the domain name.
#                             Set it explicitly only if all domains in the CSR
#                             are in the same zone.
#     dns_propagation_wait  - Seconds to wait after creating the TXT record
#                             before asking Let's Encrypt to validate it.
#                             (Default: 30)
#
# Useful links -
#     Ratelimiting - https://letsencrypt.org/docs/rate-limits/
#
# Source -
#     https://github.com/avinetworks/devops/blob/master/cert_mgmt/
#     letsencrypt_mgmt_profile.py
#
# Authors/Credits -
#     acme-tiny, modified for Avi Controller
#     <https://github.com/diafygi/acme-tiny>
#     acme-tiny-dns <https://github.com/Trim/acme-dns-tiny>
###
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import ssl

# Only used to run the openssl CLI with fixed, list-form arguments.
import subprocess  # nosec B404
import time
import urllib.parse
from dataclasses import dataclass
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen

VERSION = "0.1"

DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
DEFAULT_STAGING_DIRECTORY_URL = (
    "https://acme-staging-v02.api.letsencrypt.org/directory"
)
# The Avi controlscript sandbox keeps /tmp between runs, which lets the
# account key be reused. The file is written with mode 0600.
ACCOUNT_KEY_PATH = "/tmp/letsencrypt.key"  # nosec B108
CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4"
# Seconds. Cloudflare minimum is 60 (30 for Enterprise), 1 means "automatic".
CLOUDFLARE_TXT_TTL = 120
# Cloudflare error code for "An identical record already exists."
CLOUDFLARE_IDENTICAL_RECORD = 81058
DEFAULT_DNS_PROPAGATION_WAIT = 30  # seconds
ACME_BAD_NONCE = "urn:ietf:params:acme:error:badNonce"
ACME_MAX_NONCE_RETRIES = 100
ACME_POLL_TIMEOUT = 3600  # seconds
# CSR key types that Avi can create but Let's Encrypt refuses to sign.
# Let's Encrypt accepts RSA 2048/3072/4096 and ECDSA P-256/P-384.
LE_UNSUPPORTED_RSA_BITS = frozenset({1024})
# openssl curve name -> name shown in the Avi UI
LE_UNSUPPORTED_EC_CURVES = {"secp521r1": "SECP521R1"}
LE_SUPPORTED_KEYS = (
    "RSA 2048, 3072 or 4096 bit, or ECDSA SECP256R1 or SECP384R1"
)

# Candidate zone name -> Cloudflare zone id (or None if not a zone), so that
# zone lookups are done once per run. Cleared by certificate_request().
_CF_ZONE_CACHE: Dict[str, Optional[str]] = {}


class LetsEncryptError(Exception):
    """Raised when a certificate cannot be requested or issued."""


class CloudflareApiError(LetsEncryptError):
    """Raised when a Cloudflare API call fails."""

    def __init__(self, method, path, status, errors):
        self.status = status
        self.errors = errors
        self.error_codes = [
            e.get("code") for e in errors if isinstance(e, dict)
        ]
        messages = (
            "; ".join(
                (
                    f'{e.get("code")}: {e.get("message")}'
                    if isinstance(e, dict)
                    else str(e)
                )
                for e in errors
            )
            or "no error details"
        )
        super().__init__(
            f"Cloudflare API {method} {path} failed with HTTP {status}: "
            f"{messages}"
        )


@dataclass
class Settings:
    """Validated script parameters."""

    directory_url: str
    contact: Optional[List[str]]
    debug: bool

    @classmethod
    def from_kwargs(cls, kwargs) -> Settings:
        """Validate the controlscript parameters and build Settings."""
        debug = _is_true(kwargs.get("debug"))
        if debug:
            print("Debug enabled.")

        if not kwargs.get("cloudflare_api_token"):
            raise LetsEncryptError(
                "Script parameter 'cloudflare_api_token' is required"
            )
        if kwargs.get("cloudflare_zone_id"):
            print(f"Using Cloudflare zone id {kwargs['cloudflare_zone_id']}")
        else:
            print(
                "cloudflare_zone_id not set, "
                "zone will be looked up from the domain name"
            )

        dry_run = _is_true(kwargs.get("dryrun"))
        print(f"dry_run is: {dry_run}")

        directory_url = kwargs.get("directory_url") or (
            DEFAULT_STAGING_DIRECTORY_URL if dry_run else DEFAULT_DIRECTORY_URL
        )
        print(f"directory_url is {directory_url}")

        contact = kwargs.get("contact")
        if contact and "@" in contact:
            # contact must be an array as of the ACME RFC
            contact = [f"mailto:{contact}"]
            print(f"Contact set to: {contact}")
        else:
            if contact:
                print(f"Warning: Ignoring contact '{contact}', not an e-mail")
            contact = None

        return cls(
            directory_url=directory_url,
            contact=contact,
            debug=debug,
        )


# --------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    """Base64url-encode without padding, as required by the JOSE spec."""
    return base64.urlsafe_b64encode(data).decode("utf8").replace("=", "")


def _is_true(value) -> bool:
    """Interpret a controlscript parameter ("true"/"false") as a bool."""
    return str(value).strip().lower() == "true"


def _check_url(url: str) -> str:
    """Only allow http(s) URLs to be opened (no file:// or custom schemes)."""
    if urllib.parse.urlparse(url).scheme not in ("https", "http"):
        raise LetsEncryptError(f"Refusing to open non-HTTP(S) URL '{url}'")
    return url


def _cmd(cmd_list, cmd_input=None, err_msg="Command Line Error") -> bytes:
    """Run an external command (openssl) and return its stdout."""
    # Only called with fixed openssl argument lists, never through a shell.
    proc = subprocess.run(  # nosec B603
        cmd_list, input=cmd_input, capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise IOError(f"{err_msg}\n{proc.stderr}")
    return proc.stdout


def _write_private_file(path: str, text: str) -> None:
    """Write text to path, readable and writable by the owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # also tighten a pre-existing file
    with os.fdopen(fd, "w", encoding="utf-8") as key_file:
        key_file.write(text)


def _do_request(
    url, data=None, err_msg="Error", depth=0
) -> Tuple[Any, Optional[int], Any]:
    """Make an ACME HTTP request and parse a JSON response if possible.

    Returns (response data, HTTP status code, response headers). Raises
    IndexError for a bad nonce, so the caller can retry."""
    request = Request(
        _check_url(url),
        data=data,
        headers={
            "Content-Type": "application/jose+json",
            "User-Agent": f"avi-letsencrypt-cloudflare/{VERSION}",
        },
    )
    resp_data: Any
    try:
        # The URL scheme was checked by _check_url() above.
        with urlopen(  # nosec B310
            request, context=ssl.create_default_context()
        ) as resp:
            resp_data = resp.read().decode("utf8")
            code, headers = resp.getcode(), resp.headers
    except HTTPError as e:
        resp_data, code, headers = e.read().decode("utf8"), e.code, e.headers
    except OSError as e:  # e.g. URLError: DNS failure, connection refused
        resp_data, code, headers = str(e), None, {}
    try:
        resp_data = json.loads(resp_data)
    except ValueError:
        pass  # not JSON, e.g. the PEM certificate chain
    if (
        depth < ACME_MAX_NONCE_RETRIES
        and code == 400
        and isinstance(resp_data, dict)
        and resp_data.get("type") == ACME_BAD_NONCE
    ):
        raise IndexError(resp_data)
    if code not in (200, 201, 204):
        raise ValueError(
            f"{err_msg}:\nUrl: {url}\nData: {data}\n"
            f"Response Code: {code}\nResponse: {resp_data}"
        )
    return resp_data, code, headers


# --------------------------------------------------------------------------
# Cloudflare DNS
# --------------------------------------------------------------------------


def _cf_request(path, kwargs, method="GET", params=None, payload=None) -> Any:
    """Call the Cloudflare v4 API and return the "result" of the response."""
    api_token = kwargs.get("cloudflare_api_token")
    if not api_token:
        raise LetsEncryptError(
            "Script parameter 'cloudflare_api_token' is required"
        )
    url = f"{CLOUDFLARE_API_URL}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    data = None if payload is None else json.dumps(payload).encode("utf8")
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
        "User-Agent": f"avi-letsencrypt-cloudflare/{VERSION}",
    }
    if _is_true(kwargs.get("debug")):
        print(f"DEBUG: Cloudflare API {method} {url}")
    try:
        # The URL always starts with CLOUDFLARE_API_URL (https).
        with urlopen(  # nosec B310
            Request(url, data=data, headers=headers, method=method),
            context=ssl.create_default_context(),
            timeout=30,
        ) as resp:
            code, body = resp.getcode(), resp.read().decode("utf8")
    except HTTPError as e:
        code, body = e.code, e.read().decode("utf8")
    try:
        result = json.loads(body)
    except ValueError:
        result = {
            "success": False,
            "errors": [{"code": None, "message": body}],
        }
    if code >= 300 or not result.get("success", False):
        raise CloudflareApiError(
            method, path, code, result.get("errors") or []
        )
    return result.get("result")


def _cf_get_zone_id(record_name, kwargs):
    """Find the Cloudflare zone id responsible for a record name."""
    zone_id = kwargs.get("cloudflare_zone_id")
    if zone_id:
        return zone_id
    # Walk up the labels of the name (e.g. _acme-challenge.a.b.example.com
    # -> a.b.example.com -> b.example.com -> example.com) until a zone in the
    # account matches.
    labels = record_name.split(".")
    for i in range(1, len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate not in _CF_ZONE_CACHE:
            zones = _cf_request("/zones", kwargs, params={"name": candidate})
            _CF_ZONE_CACHE[candidate] = zones[0]["id"] if zones else None
        zone_id = _CF_ZONE_CACHE[candidate]
        if zone_id:
            if _is_true(kwargs.get("debug")):
                print(
                    f"DEBUG: Using Cloudflare zone '{candidate}' ({zone_id}) "
                    f"for {record_name}"
                )
            return zone_id
    raise LetsEncryptError(
        f"Could not find a Cloudflare zone for {record_name}. Check that the "
        "API token has Zone:Read permission or set the 'cloudflare_zone_id' "
        "parameter."
    )


def _cf_find_txt_records(zone_id, record_name, kwargs, value):
    """List the TXT records with a given name and value."""
    records = _cf_request(
        f"/zones/{zone_id}/dns_records",
        kwargs,
        params={"type": "TXT", "name": record_name, "per_page": 100},
    )
    # Cloudflare may return the content with or without surrounding quotes
    return [r for r in records if r.get("content", "").strip('"') == value]


def _dns_propagation_wait(kwargs) -> int:
    """Return the dns_propagation_wait parameter in seconds."""
    try:
        return int(
            kwargs.get("dns_propagation_wait", DEFAULT_DNS_PROPAGATION_WAIT)
        )
    except (TypeError, ValueError):
        return DEFAULT_DNS_PROPAGATION_WAIT


def add_dns_text_record(key_digest_64, txt_record_name, kwargs):
    """Add a dns txt record named txt_record_name with value key_digest_64,
    then wait for it to propagate."""
    record_name = txt_record_name.rstrip(".")
    try:
        zone_id = _cf_get_zone_id(record_name, kwargs)
        payload = {
            "type": "TXT",
            "name": record_name,
            "content": key_digest_64,
            "ttl": CLOUDFLARE_TXT_TTL,
            "comment": "ACME DNS-01 challenge "
            "(Avi Let's Encrypt controlscript)",
        }
        try:
            record = _cf_request(
                f"/zones/{zone_id}/dns_records",
                kwargs,
                method="POST",
                payload=payload,
            )
            print(f"Added DNS txt record {record_name} (id {record['id']})")
        except CloudflareApiError as e:
            # e.g. left over from an earlier run
            if CLOUDFLARE_IDENTICAL_RECORD not in e.error_codes:
                raise
            print(
                f"Identical DNS txt record {record_name} already exists, "
                "reusing it"
            )
    except Exception as e:
        raise LetsEncryptError(
            f"Error adding DNS txt record {record_name}: {e}"
        ) from e

    # Cloudflare has no change-status API like Route 53's INSYNC; changes
    # usually reach all Cloudflare authoritative servers within seconds.
    # Wait before asking the CA to validate.
    wait = _dns_propagation_wait(kwargs)
    if wait > 0:
        print(f"Waiting {wait} seconds for DNS propagation...")
        time.sleep(wait)


def remove_dns_text_record(key_digest_64, txt_record_name, kwargs):
    """Remove the DNS txt record(s) named txt_record_name with value
    key_digest_64. Errors are printed, not raised."""
    record_name = txt_record_name.rstrip(".")
    try:
        zone_id = _cf_get_zone_id(record_name, kwargs)
        records = _cf_find_txt_records(
            zone_id, record_name, kwargs, key_digest_64
        )
        if not records:
            print(
                f"No DNS txt record {record_name} with the challenge value "
                "found, nothing to delete"
            )
        for record in records:
            _cf_request(
                f"/zones/{zone_id}/dns_records/{record['id']}",
                kwargs,
                method="DELETE",
            )
            print(f"Deleted DNS txt record {record_name} (id {record['id']})")
    # Do not raise: this runs in a finally block and must not mask the
    # original error.
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error deleting DNS txt record {record_name}: {e}")


# --------------------------------------------------------------------------
# ACME (Let's Encrypt)
# --------------------------------------------------------------------------


def _ensure_account_key(debug: bool) -> None:
    """Create a Let's Encrypt account key if there is none yet."""
    if os.path.exists(ACCOUNT_KEY_PATH):
        if debug:
            print("DEBUG: Reusing account key.")
        return
    print("Account key not found. Generating account key...")
    out = _cmd(["openssl", "genrsa", "4096"], err_msg="OpenSSL Error")
    _write_private_file(ACCOUNT_KEY_PATH, out.decode("utf-8"))


def _account_jwk() -> Tuple[Dict[str, str], str]:
    """Return the account key's public JWK and its thumbprint."""
    out = _cmd(
        ["openssl", "rsa", "-in", ACCOUNT_KEY_PATH, "-noout", "-text"],
        err_msg="OpenSSL Error",
    )
    match = re.search(
        r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode("utf8"),
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise LetsEncryptError("Could not parse the RSA account key")
    pub_hex, pub_exp = match.groups()
    pub_exp = f"{int(pub_exp):x}"
    pub_exp = f"0{pub_exp}" if len(pub_exp) % 2 else pub_exp
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(
            binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))
        ),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    return jwk, thumbprint


def _csr_text(csr_path: str) -> str:
    """Return the openssl text dump of the CSR at csr_path."""
    return _cmd(
        ["openssl", "req", "-in", csr_path, "-noout", "-text"],
        err_msg=f"Error loading {csr_path}",
    ).decode("utf8")


def _check_csr_key(out: str) -> None:
    """Reject CSR keys that Avi can create but Let's Encrypt won't sign.

    out is the openssl text dump of the CSR."""
    rsa = re.search(
        r"Public Key Algorithm: rsaEncryption\s+(?:RSA )?"
        r"Public[- ]Key: \((\d+) bit\)",
        out,
    )
    curve = re.search(r"ASN1 OID: (\w+)", out)
    if rsa and int(rsa.group(1)) in LE_UNSUPPORTED_RSA_BITS:
        key = f"an RSA {rsa.group(1)} bit"
    elif curve and curve.group(1) in LE_UNSUPPORTED_EC_CURVES:
        key = f"an ECDSA {LE_UNSUPPORTED_EC_CURVES[curve.group(1)]}"
    else:
        return
    raise LetsEncryptError(
        f"The CSR uses {key} key, which Let's Encrypt does not support. "
        f"Recreate the certificate with an {LE_SUPPORTED_KEYS} key."
    )


def _csr_domains(out: str) -> List[str]:
    """Return the CN and DNS SANs of a CSR, sorted.

    out is the openssl text dump of the CSR."""
    domains = set()
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(
        r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n",
        out,
        re.MULTILINE | re.DOTALL,
    )
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    return sorted(domains)


class AcmeClient:
    """A minimal ACME v2 client (based on acme-tiny)."""

    def __init__(self, directory_url: str, jwk: Dict[str, str], thumbprint):
        self.jwk, self.thumbprint = jwk, thumbprint
        self.account_url: Optional[str] = None
        print("Getting directory...")
        self.directory, _, _ = _do_request(
            directory_url, err_msg="Error getting directory"
        )
        print("Directory found!")

    def signed_request(self, url, payload, err_msg, depth=0):
        """Send a JWS-signed request, retrying bad nonces."""
        payload64 = (
            "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
        )
        new_nonce = _do_request(self.directory["newNonce"])[2]["Replay-Nonce"]
        protected: Dict[str, Any] = {
            "url": url,
            "alg": "RS256",
            "nonce": new_nonce,
        }
        if self.account_url is None:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.account_url
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _cmd(
            ["openssl", "dgst", "-sha256", "-sign", ACCOUNT_KEY_PATH],
            cmd_input=f"{protected64}.{payload64}".encode("utf8"),
            err_msg="OpenSSL Error",
        )
        data = json.dumps(
            {
                "protected": protected64,
                "payload": payload64,
                "signature": _b64(signature),
            }
        )
        try:
            return _do_request(
                url, data=data.encode("utf8"), err_msg=err_msg, depth=depth
            )
        except IndexError:  # bad nonce
            return self.signed_request(url, payload, err_msg, depth + 1)

    def poll_until_not(self, url, pending_statuses, err_msg):
        """Poll url until its status is not one of pending_statuses."""
        start = time.time()
        while True:
            result, _, _ = self.signed_request(url, None, err_msg)
            if result["status"] not in pending_statuses:
                return result
            if time.time() - start >= ACME_POLL_TIMEOUT:
                raise LetsEncryptError(f"Polling timeout: {url}")
            time.sleep(2)

    def register(self, contact: Optional[List[str]]) -> None:
        """Create (or find) the account and update its contact details."""
        print("Registering account...")
        _, code, headers = self.signed_request(
            self.directory["newAccount"],
            {"termsOfServiceAgreed": True},
            "Error registering",
        )
        self.account_url = headers["Location"]
        print("Registered!" if code == 201 else "Already registered!")
        if contact is not None:
            account, _, _ = self.signed_request(
                self.account_url,
                {"contact": contact},
                "Error updating contact details",
            )
            contact_list = "\n".join(account["contact"])
            print(f"Updated contact details:\n{contact_list}")

    def new_order(self, domains: List[str]):
        """Create an order. Returns (order, order URL)."""
        print("Creating new order...")
        order, _, headers = self.signed_request(
            self.directory["newOrder"],
            {"identifiers": [{"type": "dns", "value": d} for d in domains]},
            "Error creating new order",
        )
        print("Order created!")
        return order, headers["Location"]

    def finalize(self, order, order_url: str, csr_path: str) -> str:
        """Finalize the order with the CSR and download the certificate."""
        print("Signing certificate...")
        csr_der = _cmd(
            ["openssl", "req", "-in", csr_path, "-outform", "DER"],
            err_msg="DER Export Error",
        )
        self.signed_request(
            order["finalize"], {"csr": _b64(csr_der)}, "Error finalizing order"
        )
        order = self.poll_until_not(
            order_url,
            ["pending", "processing", "ready"],
            "Error checking order status",
        )
        if order["status"] != "valid":
            raise ValueError(f"Order failed: {order}")
        certificate_pem, _, _ = self.signed_request(
            order["certificate"], None, "Certificate download failed"
        )
        print("Certificate signed!")
        return certificate_pem


def _complete_authorization(acme, auth_url, kwargs):
    """Complete the DNS-01 challenge of one ACME authorization."""
    debug = _is_true(kwargs.get("debug"))
    if debug:
        print(f"DEBUG: Authorization URL is: {auth_url}")
    authorization, _, _ = acme.signed_request(
        auth_url, None, "Error getting challenges"
    )
    domain = authorization["identifier"]["value"]
    print(f"Verifying {domain}...")

    challenge = next(
        (c for c in authorization["challenges"] if c["type"] == "dns-01"),
        None,
    )
    if challenge is None:
        raise LetsEncryptError(f"No DNS-01 challenge offered for {domain}")
    token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
    keydigest64 = _b64(
        hashlib.sha256(f"{token}.{acme.thumbprint}".encode("utf8")).digest()
    )
    txt_record_name = f"_acme-challenge.{domain}."
    if debug:
        print(f"DEBUG: Validation Record is : {txt_record_name}")

    try:
        print(f"Install DNS TXT resource for domain: {domain}")
        add_dns_text_record(keydigest64, txt_record_name, kwargs)

        print("Challenge completed, notifying LetsEncrypt")
        acme.signed_request(
            challenge["url"], {}, f"Error submitting challenges: {domain}"
        )
        authorization = acme.poll_until_not(
            auth_url,
            ["pending"],
            f"Error checking challenge status for {domain}",
        )
        if authorization["status"] != "valid":
            raise ValueError(
                f"Challenge did not pass for {domain}: {authorization}"
            )
        print("Challenge passed")
    finally:
        print("Cleaning up...")
        remove_dns_text_record(keydigest64, txt_record_name, kwargs)
    print(f"{domain} verified!")


def get_crt(csr_path: str, settings: Settings, kwargs) -> str:
    """Request a certificate for the CSR at csr_path from Let's Encrypt."""
    # Check the CSR first, so an unsupported key fails before any request.
    print("Parsing CSR...")
    csr_text = _csr_text(csr_path)
    _check_csr_key(csr_text)
    domains = _csr_domains(csr_text)
    print(f"Found domains: {', '.join(domains)}")

    _ensure_account_key(settings.debug)

    print("Parsing account key...")
    jwk, thumbprint = _account_jwk()

    acme = AcmeClient(settings.directory_url, jwk, thumbprint)
    acme.register(settings.contact)
    order, order_url = acme.new_order(domains)
    for auth_url in order["authorizations"]:
        _complete_authorization(acme, auth_url, kwargs)
    return acme.finalize(order, order_url, csr_path)


def certificate_request(csr, common_name, kwargs):
    """Avi Controller entry point: return a signed certificate for csr.

    common_name is part of the controlscript interface; the domains are
    read from the CSR itself."""
    # pylint: disable=unused-argument
    print(f"Running version {VERSION}")
    _CF_ZONE_CACHE.clear()
    settings = Settings.from_kwargs(kwargs)

    letsencrypt_key = kwargs.get("letsencrypt_key")
    if letsencrypt_key:
        _write_private_file(ACCOUNT_KEY_PATH, letsencrypt_key)

    with NamedTemporaryFile(
        mode="w", suffix=".csr", delete=False, encoding="utf-8"
    ) as csr_file:
        csr_file.write(csr)
    try:
        signed_crt = get_crt(csr_file.name, settings, kwargs)
    finally:
        os.remove(csr_file.name)

    print(signed_crt)
    return signed_crt
