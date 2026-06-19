"""REST admin client for the cryptopolicy-manager facade (/api/v1/*).

Wraps all twelve A1 endpoints over mTLS.  The server requires:
  - TLS 1.3 with X25519MLKEM768 (preferred) or X25519 key exchange
  - ECDSA P-256 client certificate signed by the server's CA

Cert files are minted at container first-boot via ``--init-certs <dir>``
and shared to the kms-proxy over a Docker volume (``/admin-certs/``).

Example::

    client = AdminClient(
        host="127.0.0.1",
        port=5697,
        ca_cert="/admin-certs/ca.crt",
        client_cert="/admin-certs/client.crt",
        client_key="/admin-certs/client.key",
    )
    print(client.version())
    client.activate("aead-only")
"""
from __future__ import annotations

import http.client
import json
import ssl
from typing import Any, Optional


class AdminError(Exception):
    """Raised when the admin facade returns a non-2xx response."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        try:
            detail = json.loads(body).get("detail", body)
        except (json.JSONDecodeError, AttributeError):
            detail = body
        super().__init__(f"HTTP {status}: {detail}")


class AdminClient:
    """REST client for the cryptopolicy-manager admin facade.

    Parameters
    ----------
    host:
        Server hostname or IP.
    port:
        Admin facade port (default: 5697).
    ca_cert:
        Path to the CA certificate that signed the server's cert.
        Pass ``None`` with ``insecure=True`` for dev/sandbox use.
    client_cert:
        Path to the client certificate (PEM).
    client_key:
        Path to the client private key (PEM).
    insecure:
        If ``True``, skip server certificate verification.  Useful for
        sandbox dev where the CA is self-signed and not in the system store.
    timeout:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5697,
        *,
        ca_cert: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        insecure: bool = False,
        timeout: float = 10.0,
    ):
        self._host = host
        self._port = port
        self._timeout = timeout

        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=ca_cert,
            )

        if client_cert and client_key:
            ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)

        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self._ctx = ctx

    # ── transport ───────────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        *,
        content_type: str = "application/json",
    ) -> Any:
        conn = http.client.HTTPSConnection(
            self._host, self._port, context=self._ctx, timeout=self._timeout
        )
        headers: dict[str, str] = {}
        encoded: Optional[bytes] = None
        if body is not None:
            if isinstance(body, str):
                encoded = body.encode("utf-8")
                headers["Content-Type"] = content_type
            else:
                encoded = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=encoded, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8")
        finally:
            conn.close()

        if resp.status >= 400:
            raise AdminError(resp.status, raw)

        if raw.strip():
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
        return None

    # ── healthcheck / version ────────────────────────────────────────────────

    def healthz(self) -> dict:
        """``GET /healthz`` — returns ``{"status": "ok"}`` or raises."""
        return self._request("GET", "/healthz")

    def version(self) -> dict:
        """``GET /version`` — returns ``{"version": "…", "git_sha": "…"}``."""
        return self._request("GET", "/version")

    def openapi(self) -> str:
        """``GET /openapi.yaml`` — returns the OpenAPI 3.1 spec as a string."""
        return self._request("GET", "/openapi.yaml")

    # ── policy management ────────────────────────────────────────────────────

    def list_policies(self) -> list[str]:
        """``GET /api/v1/policies`` — list of policy names available on-disk."""
        result = self._request("GET", "/api/v1/policies")
        return result.get("policies", [])

    def get_policy(self, name: str) -> dict:
        """``GET /api/v1/policies/{name}`` — returns ``{"name": …, "yaml": …}``."""
        return self._request("GET", f"/api/v1/policies/{name}")

    def create_policy(self, name: str, yaml: str) -> dict:
        """``POST /api/v1/policies`` — create a new policy file on-disk."""
        return self._request(
            "POST", "/api/v1/policies",
            body=yaml,
            content_type="application/yaml",
        )

    def save_policy(self, name: str, yaml: str) -> dict:
        """``PUT /api/v1/policies/{name}`` — write / overwrite a policy file."""
        return self._request(
            "PUT", f"/api/v1/policies/{name}",
            body=yaml,
            content_type="application/yaml",
        )

    # ── active policy ────────────────────────────────────────────────────────

    def get_active(self) -> Optional[dict]:
        """``GET /api/v1/active`` — returns ``{"name": …, "fingerprint": …}`` or ``None``."""
        try:
            return self._request("GET", "/api/v1/active")
        except AdminError as e:
            if e.status == 404:
                return None
            raise

    def activate(self, name: str) -> dict:
        """``PUT /api/v1/active`` — switch the live policy to ``name``."""
        return self._request("PUT", "/api/v1/active", body={"name": name})

    # ── validation / dry-run ─────────────────────────────────────────────────

    def validate(self, yaml: str) -> dict:
        """``POST /api/v1/validate`` — parse-check a YAML policy."""
        return self._request(
            "POST", "/api/v1/validate",
            body=yaml,
            content_type="application/yaml",
        )

    def dry_run(
        self,
        yaml: str,
        op: str,
        algorithm: Optional[str] = None,
    ) -> dict:
        """``POST /api/v1/dry-run`` — evaluate a policy YAML against one operation.

        Returns ``{"decision": "Allow" | "Deny" | "Rekey", …}``.
        """
        payload: dict[str, Any] = {"yaml": yaml, "op": op}
        if algorithm is not None:
            payload["algorithm"] = algorithm
        return self._request("POST", "/api/v1/dry-run", body=payload)

    # ── audit log ────────────────────────────────────────────────────────────

    def get_audit(self, limit: int = 200) -> dict:
        """``GET /api/v1/audit?limit=N`` — recent audit events from the server."""
        return self._request("GET", f"/api/v1/audit?limit={limit}")
