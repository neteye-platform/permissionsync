"""Provision the disposable supported-Keycloak contract environment.

Invoked only by ``bootstrap.sh``. Everything created here is disposable test
state in a container that is destroyed by ``teardown.sh``: one deterministic
realm, the client scopes the PermissionSync ``permissionsync:<target>``
convention needs, and the service-account clients that let the real contract
suite obtain real Keycloak-issued tokens for each case it proves.

Inputs arrive through the environment so that no credential ever appears on a
command line:

``KEYCLOAK_BASE_URL``
    The externally visible HTTPS base URL, including the discovered host port.
``KEYCLOAK_CA_PEM``
    Path to the disposable CA certificate that signs Keycloak's certificate.
``KEYCLOAK_ADMIN_USERNAME`` / ``KEYCLOAK_ADMIN_PASSWORD``
    The container's bootstrap administrator.

Output is a list of ``NAME=value`` records on standard output, which
``bootstrap.sh`` turns into the suite's runtime environment. Client secrets are
generated here and are the only sensitive records; no access token, admin
token, or signing key is ever printed.
"""

import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# One deterministic realm plus a separate realm that exists only to issue
# tokens from a different issuer with different signing keys.
REALM = "permissionsync-contract"
FOREIGN_REALM = "permissionsync-contract-foreign"

# The audience PermissionSync is configured to require. A standard Keycloak
# Audience protocol mapper puts it into every access token below.
AUDIENCE = "permissionsync"
WRONG_AUDIENCE = "not-permissionsync"

# ADR-0002's baseline algorithm. RS512 exists only as a deterministic fixture
# for the disallowed-algorithm case and is never PermissionSync's allowlist.
BASELINE_ALGORITHM = "RS256"
DISALLOWED_ALGORITHM = "RS512"

# Long enough that no contract assertion races a token expiry, except for the
# dedicated short-lived client whose expiry is the property under test.
ACCESS_TOKEN_LIFESPAN_SECONDS = 900
SHORTLIVED_LIFESPAN_SECONDS = 1

# Client scopes covering the complete PermissionSync scope convention: one
# target, a second target for the ambiguous case, a grammar-invalid suffix, an
# unrelated OAuth scope, a case-different prefix, and both lookalikes.
TARGET_SCOPE = "permissionsync:glpi"
SECOND_TARGET_SCOPE = "permissionsync:grafana"
INVALID_TARGET_SCOPE = "permissionsync:"
NOISE_SCOPE = "service-noise"
CASE_DIFFERENT_SCOPE = "Permissionsync:glpi"
LOOKALIKE_PREFIX_SCOPE = "xpermissionsync:glpi"
LOOKALIKE_SUFFIX_SCOPE = "permissionsyncx:glpi"

CONTRACT_SCOPES = (
    TARGET_SCOPE,
    SECOND_TARGET_SCOPE,
    INVALID_TARGET_SCOPE,
    NOISE_SCOPE,
    CASE_DIFFERENT_SCOPE,
    LOOKALIKE_PREFIX_SCOPE,
    LOOKALIKE_SUFFIX_SCOPE,
)

# Keycloak assigns these default client scopes to a new client. The minimal
# client removes them so that a real token can carry an empty ``scope`` claim,
# which ADR-0002 requires to behave as a targetless request. ``service_account``
# is deliberately kept: it is the built-in provisioning that emits the
# ``client_id`` claim PermissionSync requires.
REMOVED_DEFAULT_SCOPES = (
    "profile",
    "email",
    "roles",
    "web-origins",
    "acr",
    "basic",
    "organization",
)


class AdminApi:
    """Minimal Keycloak admin REST client over the disposable HTTPS endpoint."""

    def __init__(
        self, base_url: str, ca_pem: str, username: str, password: str
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.context = ssl.create_default_context(cafile=ca_pem)
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.token = self._administrator_token(username, password)

    def _open(self, request: urllib.request.Request) -> tuple[int, bytes]:
        # Every URL here is built from KEYCLOAK_BASE_URL, which the reviewed
        # bootstrap sets to the disposable local HTTPS Keycloak endpoint
        # (https://127.0.0.1 plus the container-assigned port). No scheme or
        # host is caller-controlled, so the rule's generic concern about a
        # dynamic value selecting file:// or another scheme does not apply, and
        # the certificate and hostname verification configured above stays
        # mandatory.
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(
                request, context=self.context, timeout=30
            ) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def _administrator_token(self, username: str, password: str) -> str:
        form = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": username,
                "password": password,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        status, body = self._open(request)
        if status != 200:
            raise SystemExit("could not obtain a Keycloak administrator token")
        token = json.loads(body).get("access_token")
        if not isinstance(token, str) or not token:
            raise SystemExit("Keycloak returned no administrator access token")
        return token

    def call(
        self, method: str, path: str, payload: object | None = None
    ) -> tuple[int, bytes]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}/admin/realms{path}",
            data=data,
            headers=headers,
            method=method,
        )
        return self._open(request)

    def require(self, method: str, path: str, payload: object | None = None) -> bytes:
        status, body = self.call(method, path, payload)
        if status not in (200, 201, 204):
            raise SystemExit(
                f"Keycloak admin request {method} {path} failed with {status}"
            )
        return body

    def get(self, path: str) -> object:
        return json.loads(self.require("GET", path) or b"null")


def service_account_client(client_id: str, audience: str, attributes: dict) -> dict:
    """Build a confidential Client Credentials client definition.

    The audience mapper is Keycloak's standard ``oidc-audience-mapper``; no
    custom protocol mapper is introduced anywhere in this environment, and the
    required ``client_id`` claim comes from the built-in ``service_account``
    client scope rather than from anything provisioned here.
    """
    return {
        "clientId": client_id,
        "enabled": True,
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "clientAuthenticatorType": "client-secret",
        "secret": secrets.token_hex(24),
        "attributes": attributes,
        "protocolMappers": [
            {
                "name": "permissionsync-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": audience,
                    "access.token.claim": "true",
                    "introspection.token.claim": "true",
                },
            }
        ],
    }


def create_client(api: AdminApi, realm: str, definition: dict) -> str:
    api.require("POST", f"/{realm}/clients", definition)
    clients = api.get(
        f"/{realm}/clients?clientId={urllib.parse.quote(definition['clientId'])}"
    )
    if not clients:
        raise SystemExit(f"client {definition['clientId']} was not created")
    return clients[0]["id"]


def main() -> None:
    base_url = os.environ["KEYCLOAK_BASE_URL"]
    api = AdminApi(
        base_url,
        os.environ["KEYCLOAK_CA_PEM"],
        os.environ["KEYCLOAK_ADMIN_USERNAME"],
        os.environ["KEYCLOAK_ADMIN_PASSWORD"],
    )

    # `frontendUrl` makes the realm's issuer, discovery document, and token
    # `iss` claim exactly the externally visible HTTPS base URL, independent of
    # which host name a particular client used to reach Keycloak. The container
    # smoke test therefore reaches the same realm over the compose network
    # while still receiving the issuer the suite configures.
    for realm in (REALM, FOREIGN_REALM):
        api.require(
            "POST",
            "",
            {
                "realm": realm,
                "enabled": True,
                "accessTokenLifespan": ACCESS_TOKEN_LIFESPAN_SECONDS,
                "attributes": {"frontendUrl": base_url},
            },
        )

    # A second realm signing key whose algorithm is deliberately outside the
    # allowlist the suite configures, so the disallowed-algorithm case can use
    # a real Keycloak-issued token instead of a synthetic one.
    api.require(
        "POST",
        f"/{REALM}/components",
        {
            "name": f"rsa-{DISALLOWED_ALGORITHM.lower()}",
            "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider",
            "config": {
                "priority": ["50"],
                "enabled": ["true"],
                "active": ["true"],
                "algorithm": [DISALLOWED_ALGORITHM],
                "keySize": ["2048"],
            },
        },
    )

    for scope in CONTRACT_SCOPES:
        api.require(
            "POST",
            f"/{REALM}/client-scopes",
            {
                "name": scope,
                "protocol": "openid-connect",
                "attributes": {
                    "include.in.token.scope": "true",
                    "display.on.consent.screen": "false",
                },
            },
        )
    scope_ids = {
        scope["name"]: scope["id"] for scope in api.get(f"/{REALM}/client-scopes")
    }

    caller = service_account_client("permissionsync-caller", AUDIENCE, {})
    caller_uuid = create_client(api, REALM, caller)
    # Assigned as optional scopes so each contract case selects exactly the
    # scope string it needs through the token request itself.
    for scope in CONTRACT_SCOPES:
        api.require(
            "PUT",
            f"/{REALM}/clients/{caller_uuid}/optional-client-scopes/{scope_ids[scope]}",
        )

    minimal = service_account_client("permissionsync-minimal", AUDIENCE, {})
    minimal_uuid = create_client(api, REALM, minimal)
    assigned = api.get(f"/{REALM}/clients/{minimal_uuid}/default-client-scopes")
    for scope in assigned:
        if scope["name"] in REMOVED_DEFAULT_SCOPES:
            api.require(
                "DELETE",
                f"/{REALM}/clients/{minimal_uuid}/default-client-scopes/{scope['id']}",
            )

    disallowed = service_account_client(
        "permissionsync-disallowed-algorithm",
        AUDIENCE,
        {"access.token.signed.response.alg": DISALLOWED_ALGORITHM},
    )
    create_client(api, REALM, disallowed)

    shortlived = service_account_client(
        "permissionsync-shortlived",
        AUDIENCE,
        {"access.token.lifespan": str(SHORTLIVED_LIFESPAN_SECONDS)},
    )
    create_client(api, REALM, shortlived)

    wrong_audience = service_account_client(
        "permissionsync-wrong-audience", WRONG_AUDIENCE, {}
    )
    create_client(api, REALM, wrong_audience)

    foreign = service_account_client("permissionsync-foreign-caller", AUDIENCE, {})
    create_client(api, FOREIGN_REALM, foreign)

    records = {
        "REALM": REALM,
        "FOREIGN_REALM": FOREIGN_REALM,
        "AUDIENCE": AUDIENCE,
        "WRONG_AUDIENCE": WRONG_AUDIENCE,
        "BASELINE_ALGORITHM": BASELINE_ALGORITHM,
        "DISALLOWED_ALGORITHM": DISALLOWED_ALGORITHM,
        "SHORTLIVED_LIFESPAN_SECONDS": str(SHORTLIVED_LIFESPAN_SECONDS),
        "TARGET_SCOPE": TARGET_SCOPE,
        "SECOND_TARGET_SCOPE": SECOND_TARGET_SCOPE,
        "INVALID_TARGET_SCOPE": INVALID_TARGET_SCOPE,
        "NOISE_SCOPE": NOISE_SCOPE,
        "CASE_DIFFERENT_SCOPE": CASE_DIFFERENT_SCOPE,
        "LOOKALIKE_PREFIX_SCOPE": LOOKALIKE_PREFIX_SCOPE,
        "LOOKALIKE_SUFFIX_SCOPE": LOOKALIKE_SUFFIX_SCOPE,
        "CALLER_CLIENT_ID": caller["clientId"],
        "CALLER_CLIENT_SECRET": caller["secret"],
        "MINIMAL_CLIENT_ID": minimal["clientId"],
        "MINIMAL_CLIENT_SECRET": minimal["secret"],
        "DISALLOWED_ALGORITHM_CLIENT_ID": disallowed["clientId"],
        "DISALLOWED_ALGORITHM_CLIENT_SECRET": disallowed["secret"],
        "SHORTLIVED_CLIENT_ID": shortlived["clientId"],
        "SHORTLIVED_CLIENT_SECRET": shortlived["secret"],
        "WRONG_AUDIENCE_CLIENT_ID": wrong_audience["clientId"],
        "WRONG_AUDIENCE_CLIENT_SECRET": wrong_audience["secret"],
        "FOREIGN_CLIENT_ID": foreign["clientId"],
        "FOREIGN_CLIENT_SECRET": foreign["secret"],
    }
    for name, value in records.items():
        if any(character in value for character in "=\r\n`"):
            raise SystemExit(
                f"provisioned record {name} contains a disallowed character"
            )
        sys.stdout.write(f"{name}={value}\n")


if __name__ == "__main__":
    main()
