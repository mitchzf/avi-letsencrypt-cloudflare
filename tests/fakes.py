"""In-memory fakes of the services the controlscript talks to.

* FakeAcme       - an ACME v2 server (Let's Encrypt)
* FakeCloudflare - the Cloudflare v4 DNS API
* FakeNetwork    - a replacement for urllib.request.urlopen that routes
                   requests to FakeAcme / FakeCloudflare by host name
"""

# The fakes implement only what the script uses.
# pylint: disable=too-few-public-methods

import base64
import email.message
import hashlib
import io
import json
import urllib.parse
from urllib.error import HTTPError, URLError

ACME_HOST = "acme.test"
ACME = f"https://{ACME_HOST}"
CF_HOST = "api.cloudflare.com"
CF_PREFIX = "/client/v4"
CERT_PEM = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"


def b64decode(text):
    """Decode unpadded base64url."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64encode(data):
    """Encode unpadded base64url."""
    return base64.urlsafe_b64encode(data).decode().replace("=", "")


class FakeResponse:
    """Stands in for the object returned by urlopen()."""

    def __init__(self, body, code=200, headers=None):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        self._body = body.encode() if isinstance(body, str) else body
        self._code = code
        self.headers = headers or {}

    def read(self):
        """Return the response body."""
        return self._body

    def getcode(self):
        """Return the HTTP status code."""
        return self._code

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(url, code, body, headers=None):
    """Build the HTTPError that urlopen() raises for a 4xx/5xx status."""
    if not isinstance(body, (bytes, str)):
        body = json.dumps(body)
    if isinstance(body, str):
        body = body.encode()
    message = email.message.Message()
    for name, value in (headers or {}).items():
        message[name] = value
    return HTTPError(url, code, "error", message, io.BytesIO(body))


class FakeAcme:  # pylint: disable=too-many-instance-attributes
    """A small ACME v2 server: one account, one order, dns-01 only.

    The attributes are knobs for tests to set up failure modes."""

    def __init__(self, cloudflare=None):
        self.cloudflare = cloudflare
        self.thumbprint = ""  # set by tests that check the TXT value
        self.account_exists = False
        self.bad_nonce_count = 0  # how many requests get a badNonce first
        self.challenge_status = "valid"
        self.order_status = "valid"
        self.offer_dns01 = True
        self.pending_polls = 1  # how many polls stay "pending" first
        self.requests = []  # (path, protected header, payload)
        self.raw_requests = []  # the JWS bodies as sent
        self.contact = None
        self.domains = []
        self.validated = {}  # domain -> TXT value seen at validation time
        self._polls = {}

    def handle(self, request):
        """Handle one HTTP request to the fake ACME server."""
        path = urllib.parse.urlparse(request.full_url).path
        if path == "/directory":
            return FakeResponse(
                {
                    "newNonce": f"{ACME}/nonce",
                    "newAccount": f"{ACME}/new-acct",
                    "newOrder": f"{ACME}/new-order",
                }
            )
        if path == "/nonce":
            return FakeResponse(b"", 204, {"Replay-Nonce": "nonce"})
        jws = json.loads(request.data)
        self.raw_requests.append(jws)
        protected = json.loads(b64decode(jws["protected"]))
        payload = (
            json.loads(b64decode(jws["payload"])) if jws["payload"] else None
        )
        self.requests.append((path, protected, payload))
        if self.bad_nonce_count:
            self.bad_nonce_count -= 1
            raise http_error(
                request.full_url,
                400,
                {"type": "urn:ietf:params:acme:error:badNonce"},
            )
        return self._route(path, payload)

    def _route(self, path, payload):  # pylint: disable=R0911
        if path == "/new-acct":
            code = 200 if self.account_exists else 201
            return FakeResponse({}, code, {"Location": f"{ACME}/acct/1"})
        if path == "/acct/1":
            self.contact = payload["contact"]
            return FakeResponse({"contact": payload["contact"]})
        if path == "/new-order":
            self.domains = [i["value"] for i in payload["identifiers"]]
            order = {
                "authorizations": [f"{ACME}/authz/{d}" for d in self.domains],
                "finalize": f"{ACME}/finalize",
            }
            return FakeResponse(order, 201, {"Location": f"{ACME}/order/1"})
        if path.startswith("/authz/"):
            return self._authz(path.split("/")[-1])
        if path.startswith("/chal/"):
            self._validate(path.split("/")[-1])
            return FakeResponse({})
        if path == "/finalize":
            return FakeResponse({})
        if path == "/order/1":
            return FakeResponse(self._poll("order", self.order_status))
        if path == "/cert":
            return FakeResponse(CERT_PEM)
        raise AssertionError(f"unexpected ACME path {path}")

    def _authz(self, domain):
        challenges = [{"type": "http-01", "token": "h", "url": "x"}]
        if self.offer_dns01:
            challenges.append(
                {
                    "type": "dns-01",
                    "token": self.token(domain),
                    "url": f"{ACME}/chal/{domain}",
                }
            )
        authz = {"identifier": {"value": domain}, "challenges": challenges}
        if domain in self.validated:
            authz.update(self._poll(domain, self.challenge_status))
        else:
            authz["status"] = "pending"
        return FakeResponse(authz)

    @staticmethod
    def token(domain):
        """The (base64url, like a real one) challenge token for domain."""
        return b64encode(f"token-{domain}".encode())

    def reset(self):
        """Forget all orders, as if this were a new day."""
        self.validated.clear()
        self._polls.clear()

    def _validate(self, domain):
        """Record the TXT value the fake Cloudflare serves right now."""
        assert self.cloudflare is not None
        name = f"_acme-challenge.{domain}"
        values = [
            r["content"]
            for r in self.cloudflare.records.values()
            if r["name"] == name
        ]
        self.validated[domain] = values

    def _poll(self, key, final_status):
        """Return "pending" for the first pending_polls polls."""
        count = self._polls.get(key, 0)
        self._polls[key] = count + 1
        if count < self.pending_polls:
            return {"status": "pending"}
        status = {"status": final_status}
        if key == "order":
            status["certificate"] = f"{ACME}/cert"
        return status

    def expected_txt(self, domain):
        """The TXT value a correct client publishes for domain."""
        key_authorization = f"{self.token(domain)}.{self.thumbprint}"
        return b64encode(hashlib.sha256(key_authorization.encode()).digest())


class FakeCloudflare:
    """The parts of the Cloudflare v4 API the script uses."""

    def __init__(self, zones=None, token="test-token"):
        self.token = token
        self.zones = zones or {"example.com": "zone-1"}
        self.records = {}  # id -> record
        self.requests = []  # (method, path, query)
        self.fail = ()  # (method, path prefix, status, body) to inject
        self._next_id = 1

    def add_record(self, name, content, zone_id="zone-1"):
        """Create a TXT record directly (as if made by someone else)."""
        record_id = f"rec-{self._next_id}"
        self._next_id += 1
        self.records[record_id] = {
            "id": record_id,
            "zone_id": zone_id,
            "type": "TXT",
            "name": name,
            "content": content,
        }
        return record_id

    def handle(self, request):
        """Handle one HTTP request to the fake Cloudflare API."""
        url = urllib.parse.urlparse(request.full_url)
        path = url.path[len(CF_PREFIX) :]
        query = dict(urllib.parse.parse_qsl(url.query))
        method = request.get_method()
        self.requests.append((method, path, query))
        if request.get_header("Authorization") != f"Bearer {self.token}":
            raise http_error(
                request.full_url,
                403,
                {"success": False, "errors": [{"code": 10000}]},
            )
        if self.fail and method == self.fail[0]:
            if path.startswith(self.fail[1]):
                raise http_error(request.full_url, self.fail[2], self.fail[3])
        result = self._route(method, path, query, request)
        if isinstance(result, Exception):
            raise result
        return FakeResponse({"success": True, "errors": [], "result": result})

    def _route(self, method, path, query, request):
        parts = path.strip("/").split("/")
        if path == "/zones":
            zone_id = self.zones.get(query["name"])
            return [{"id": zone_id, "name": query["name"]}] if zone_id else []
        if len(parts) == 3 and method == "GET":
            return [
                r
                for r in self.records.values()
                if r["zone_id"] == parts[1]
                and r["type"] == query["type"]
                and r["name"] == query["name"]
            ]
        if len(parts) == 3 and method == "POST":
            body = json.loads(request.data)
            for record in self.records.values():
                if (record["name"], record["content"]) == (
                    body["name"],
                    body["content"],
                ):
                    return http_error(
                        request.full_url,
                        400,
                        {
                            "success": False,
                            "errors": [
                                {
                                    "code": 81058,
                                    "message": "An identical record "
                                    "already exists.",
                                }
                            ],
                        },
                    )
            record_id = self.add_record(
                body["name"], body["content"], parts[1]
            )
            self.records[record_id].update(
                ttl=body["ttl"], comment=body["comment"]
            )
            return self.records[record_id]
        if len(parts) == 4 and method == "DELETE":
            del self.records[parts[3]]
            return {"id": parts[3]}
        raise AssertionError(f"unexpected Cloudflare call {method} {path}")


class FakeNetwork:
    """Replacement for urlopen() that routes to the fake services."""

    def __init__(self, acme, cloudflare):
        self.acme = acme
        self.cloudflare = cloudflare
        self.timeouts = []

    def urlopen(self, request, context=None, timeout=None):
        """Route a urllib Request to a fake service."""
        assert context is not None, "TLS context must always be passed"
        self.timeouts.append(timeout)
        host = urllib.parse.urlparse(request.full_url).netloc
        if host == ACME_HOST:
            return self.acme.handle(request)
        if host == CF_HOST:
            return self.cloudflare.handle(request)
        raise URLError(f"unknown host {host}")
