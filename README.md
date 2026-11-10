# Avi Let's Encrypt Certificates with Cloudflare DNS

An Avi Controller ControlScript for a Certificate Management Profile. It
requests and renews certificates from Let's Encrypt (or any other ACME v2
server) and proves domain ownership with **DNS-01 challenges** published in
**Cloudflare** DNS.

The script is `letsencrypt_mgmt_profile_with_cloudflare_dns.py`. It is a
single file, uses only the Python standard library and `openssl`, and is
based on [acme-tiny](https://github.com/diafygi/acme-tiny) and Avi's
[letsencrypt_mgmt_profile.py](https://github.com/avinetworks/devops/blob/master/cert_mgmt/letsencrypt_mgmt_profile.py).

## How it works

When a CSR certificate that uses the profile is created or renewed, the
Controller runs the script with the CSR. The script then:

1. Reads the domains from the CSR (Common Name and DNS Subject Alternative
   Names) and rejects key types Let's Encrypt won't sign (RSA 1024 bit,
   ECDSA SECP521R1) before contacting Let's Encrypt.
2. Loads or creates the Let's Encrypt account key and registers the account.
3. Creates an ACME order. For each domain it creates the
   `_acme-challenge.<domain>` TXT record in Cloudflare, waits for DNS
   propagation, asks Let's Encrypt to validate, and deletes the record
   again.
4. Finalizes the order and returns the signed certificate (with its chain)
   to the Controller, which imports it.

The script does not call the Avi Controller API, and no Virtual Service is
needed. Only the Cloudflare and ACME servers have to be reachable from the
Controller.

Supported keys: RSA 2048, 3072 or 4096 bit, and ECDSA SECP256R1 or
SECP384R1.

## Configuration

### CLI arguments and environment variables

The script is not run from a shell, so it has **no command-line arguments
and reads no environment variables**. The Controller calls its entry point,
`certificate_request(csr, common_name, kwargs)`, and all configuration comes
from the profile's script parameters (`kwargs`), listed below.

### Script parameters

Set these in the Certificate Management Profile. Parameter values are
strings, and booleans are the text `true` or `false`.

| Parameter | Required | Sensitive | Default | Description |
|---|---|---|---|---|
| `cloudflare_api_token` | **Yes** | **Yes** | — | Cloudflare API token. It needs the **Zone → DNS → Edit** permission, plus **Zone → Zone → Read** if `cloudflare_zone_id` is not set. Scope it to the zones used for certificates. |
| `cloudflare_zone_id` | No | No | (looked up) | ID of the Cloudflare zone for the challenge records. If not set, the zone is found from each domain name. Set it only if every domain in the CSR is in this one zone. |
| `dryrun` | No | No | `false` | `true` uses the Let's Encrypt **staging** server, which avoids production rate limits while testing. Staging certificates are not publicly trusted. |
| `contact` | No | No | none | E-mail address for the Let's Encrypt account. An account update is sent on every run while it's set, so set it once and remove it after it has been registered. Values without an `@` are ignored. Optional. |
| `directory_url` | No | No | Let's Encrypt production (staging with `dryrun`) | ACME directory URL, e.g. for an in-house ACME server. It overrides `dryrun`. |
| `letsencrypt_key` | No | Yes | (generated) | PEM RSA private key of an existing ACME account. If not set, a 4096-bit key is generated on the first run and kept in `/tmp/letsencrypt.key` on the Controller for later runs. |
| `dns_propagation_wait` | No | No | `30` | Seconds to wait after creating a TXT record before asking Let's Encrypt to validate it. |
| `debug` | No | No | `false` | `true` prints debug output (including Cloudflare API calls) to the ControlScript log. |

## Setup in the Avi Controller UI (32.1.x)

### 1. Create a Cloudflare API token

In the Cloudflare dashboard, under **My Profile → API Tokens → Create
Token**, create a custom token with:

- **Zone → DNS → Edit**
- **Zone → Zone → Read** (only needed if you won't set `cloudflare_zone_id`)
- **Zone Resources**: the zone(s) you will issue certificates for

### 2. Import the ControlScript

The ControlScript object must exist before the Certificate Management
Profile can be created.

1. Go to **Templates → Scripts → ControlScripts** and click **Create**.
2. Enter a name, e.g. `letsencrypt-cloudflare`.
3. Upload `letsencrypt_mgmt_profile_with_cloudflare_dns.py` (**Import
   File**), or paste its contents.
4. Click **Save**.

### 3. Create the Certificate Management Profile

1. Go to **Templates → Security → Certificate Management** and click
   **Create**.
2. Enter a name, e.g. `letsencrypt-cloudflare`.
3. Under **Control Script**, select the ControlScript object created in
   step 2.
4. Enable **Enable Custom Parameters** (if shown) and add the
   [script parameters](#script-parameters):
   - `cloudflare_api_token`: the token from step 1, with **Sensitive**
     checked.
   - Any optional parameters you need. For a first test, add `dryrun` set to
     `true`.
   - Leave **Dynamic** unchecked for all parameters.
5. Click **Save**.

### 4. Request a certificate

1. Go to **Templates → Security → SSL/TLS Certificates**, click **Create**
   and choose **Application Certificate**.
2. Enter a name, e.g. `www.example.com RSA`.
3. Set **Type** to **CSR**.
4. Set **Common Name** to the domain to certify. Add **Subject Alternative
   Names** if you need more domains. Each domain must be in a Cloudflare
   zone the token can edit.
5. Choose a supported **Algorithm** and **Key Size** (see
   [How it works](#how-it-works)).
6. Under **Certificate Management Profile**, select the profile from
   step 3.
7. Click **Save**. Requesting the certificate takes about a minute (mostly
   the DNS propagation wait). The certificate then shows as issued and can
   be used by Virtual Services.

The Controller renews the certificate automatically before it expires, by
running the script again, by default seven days prior to expiration. Use
the certificate's **Renew** action to renew it manually.

Once a `dryrun` certificate has worked, remove `dryrun` from the profile (or
set it to `false`) and renew the certificate to get a trusted certificate.

### Troubleshooting

- Set `debug` to `true` in the profile and renew the certificate. The
  script output appears in the event log (**Operations → Events**) for the
  certificate.
- `Incorrect TXT record` from Let's Encrypt: increase
  `dns_propagation_wait`. If you renew right after a previous run, wait at
  least two minutes (the challenge record TTL is 120 seconds) so DNS
  resolvers don't return the old challenge value.
- Cloudflare `403`/`Authentication error`: check the token's permissions and
  zone resources. Without `cloudflare_zone_id`, the token also needs
  **Zone → Zone → Read**.
- See the Let's Encrypt [rate limits](https://letsencrypt.org/docs/rate-limits/)
  and use `dryrun` while testing.

## Development and testing

### Requirements

- Python 3.14 and [Poetry](https://python-poetry.org/) for local
  development. The script itself must stay compatible with the Controller's
  Python (checked as Python 3.8 by Black and Pyright).
- `openssl` on the `PATH` (some unit tests call it).

```sh
poetry install
```

### Project layout

| Path | Contents |
|---|---|
| `letsencrypt_mgmt_profile_with_cloudflare_dns.py` | The ControlScript (must stay one file) |
| `tests/` | Unit tests, with fakes for Cloudflare and the ACME server |
| `tests/integration/` | End-to-end tests against a real Avi Controller |
| `*.example` | Templates for the local credential files (the real files are git-ignored) |

### Unit tests and checks

```sh
poetry run pytest                  # unit tests, 100% branch coverage required
poetry run black --check .         # formatting (line length 79)
poetry run flake8
poetry run pylint letsencrypt_mgmt_profile_with_cloudflare_dns.py
poetry run pyright
poetry run bandit -c pyproject.toml -r .
```

The unit tests make no network calls.

### Integration tests

`tests/integration/test_controller.py` uploads a temporary copy of the
local script to a real Controller, creates a temporary profile (with
`dryrun=true`, so Let's Encrypt staging) and a CSR certificate, checks
that it gets signed, renews it, and deletes everything again. It uses
`avisdk`, the project's only runtime dependency (the script itself doesn't
need it).

Settings come from these files (copy the `.example` files and fill them
in). Together they must provide every required field:

| File | Fields |
|---|---|
| `avicontroller-credentials.json` | `controller`, `username`, `password` |
| `cloudflare.ini` | `dns_cloudflare_api_token` (used as `cloudflare_api_token`) |
| `tests/integration/integration-credentials.json` | Any of `controller`, `username`, `password`, `tenant` (default `admin`), `cloudflare_api_token`, `cloudflare_zone_id`, `common_name`. Its non-empty values win. |

`common_name` must be in a Cloudflare zone the token can edit. The Avi user
must be allowed to create ControlScripts, Certificate Management Profiles
and certificates.

Environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `AVI_INTEGRATION` | **Yes** | — | Set to `1` to run the tests. Otherwise they are skipped. |
| `AVI_INTEGRATION_CREDENTIALS` | No | `tests/integration/integration-credentials.json` | Path of the integration credentials file. |
| `AVI_RENEW_WAIT` | No | `150` | Seconds to wait between issuing and renewing. Keep it above the 120-second TXT record TTL. |

```sh
AVI_INTEGRATION=1 poetry run pytest tests/integration --no-cov -v
```

`--no-cov` is needed because these tests don't import the script, so they
can't meet the unit tests' coverage requirement. Wait at least
`AVI_RENEW_WAIT` seconds between two runs.
