"""Shared ``OAuthClientProvider`` customizations for Hermes MCP OAuth.

Two code paths build an SDK provider — ``tools.mcp_oauth.build_oauth_auth`` (legacy public
API) and ``tools.mcp_oauth_manager.MCPOAuthManager`` — and both need the same real-world
fixes and config → constructor-kwargs plumbing. This module holds that core once; the origin
modules keep their own subclass (logger name, disk-watch hooks) on top of it.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tools.mcp_oauth import HermesTokenStorage
logger = logging.getLogger(__name__)

# Standard OAuth/PKCE parameters that user-supplied extras must not shadow.
# Case-insensitive comparison is applied at validation time (keys are lowercased).
_STANDARD_OAUTH_PARAMS = frozenset({
    "response_type", "client_id", "redirect_uri", "state",
    "code_challenge", "code_challenge_method", "scope", "resource",
    "prompt", "iss",
})


def _sanitize_extra_auth_params(raw: Any, *, warn_logger: logging.Logger) -> dict[str, str]:
    """Return a sanitized copy of user-supplied extra auth params.

    Rules:
    - Input must be a Mapping; non-mappings return {}.
    - Keys and values must be non-empty strings; invalid entries are silently dropped.
    - Keys matching the standard OAuth denylist (case-insensitive) are dropped with a
      warning (key name only — no value logged).
    """
    from collections.abc import Mapping
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            continue
        if not isinstance(value, str) or not value:
            continue
        if key.lower() in _STANDARD_OAUTH_PARAMS:
            warn_logger.warning(
                "oauth.extra_auth_params: ignoring %r — shadows a standard OAuth parameter", key
            )
            continue
        result[key] = value
    return result


class HermesProviderMixin:
    """Token-endpoint fixes layered over the SDK's ``OAuthClientProvider`` (must precede it in
    the MRO; subclasses set ``_hermes_logger`` to keep their own logger name).

    - Supabase-style dynamic registration returns a ``client_secret`` but omits
      ``token_endpoint_auth_method``; the SDK then treats the client as public and the token
      endpoint rejects the exchange (looping the browser page) — coerce ``client_secret_post``.
    - ``token_user_agent`` (``oauth.user_agent``) is stamped onto token-endpoint requests only
      (some authorization servers/WAFs reject httpx's default).
    - Any 2xx token/refresh response is accepted; token bodies never leak into errors/logs.
    - ``extra_auth_params`` (``oauth.extra_auth_params``) merges generic key/value pairs into
      the authorization URL after all canonical SDK fields; standard OAuth params are filtered."""

    _hermes_logger: logging.Logger = logger

    def __init__(
        self,
        *args: Any,
        token_user_agent: str | None = None,
        extra_auth_params: dict[str, str] | None = None,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)
        # oauth.user_agent — stamped onto token-endpoint requests only; some authorization servers/WAFs
        # reject httpx's default (#75576).
        self._hermes_token_user_agent = token_user_agent
        self._hermes_extra_auth_params: dict[str, str] = extra_auth_params or {}

    async def _perform_authorization_code_grant(self) -> "tuple[str, str]":
        """Mirrors the pinned SDK implementation, merging ``_hermes_extra_auth_params`` into
        the authorization URL after all canonical OAuth/PKCE fields are set.

        This override is intentionally a near-copy of the SDK method so that extras are
        injected at the one correct point — after canonical params are locked in and before
        the URL is passed to redirect_handler. Standard OAuth fields (response_type, client_id,
        etc.) remain under SDK control and cannot be replaced by extras.
        """
        import secrets as _secrets
        from urllib.parse import urlencode, urljoin

        from mcp.client.auth.exceptions import OAuthFlowError
        from mcp.client.auth.oauth2 import PKCEParameters
        from mcp.client.auth.utils import validate_authorization_response_iss

        if self.context.client_metadata.redirect_uris is None:
            raise OAuthFlowError("No redirect URIs provided for authorization code grant")
        if not self.context.redirect_handler:
            raise OAuthFlowError("No redirect handler provided for authorization code grant")
        if not self.context.callback_handler:
            raise OAuthFlowError("No callback handler provided for authorization code grant")

        if self.context.oauth_metadata and self.context.oauth_metadata.authorization_endpoint:
            auth_endpoint = str(self.context.oauth_metadata.authorization_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            auth_endpoint = urljoin(auth_base_url, "/authorize")

        if not self.context.client_info:
            raise OAuthFlowError("No client info available for authorization")

        pkce_params = PKCEParameters.generate()
        state = _secrets.token_urlsafe(32)

        auth_params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.context.client_info.client_id,
            "redirect_uri": str(self.context.client_metadata.redirect_uris[0]),
            "state": state,
            "code_challenge": pkce_params.code_challenge,
            "code_challenge_method": "S256",
        }

        if self.context.should_include_resource_param(self.context.protocol_version):
            auth_params["resource"] = self.context.get_resource_url()

        if self.context.client_metadata.scope:
            auth_params["scope"] = self.context.client_metadata.scope
            if "offline_access" in self.context.client_metadata.scope.split():
                auth_params["prompt"] = "consent"

        # Merge provider-specific extras AFTER canonical fields so they cannot shadow them.
        extras = getattr(self, "_hermes_extra_auth_params", None) or {}
        if extras:
            auth_params.update(extras)

        authorization_url = f"{auth_endpoint}?{urlencode(auth_params)}"
        await self.context.redirect_handler(authorization_url)

        result = await self.context.callback_handler()

        if result.state is None or not _secrets.compare_digest(result.state, state):
            raise OAuthFlowError(f"State parameter mismatch: {result.state} != {state}")

        validate_authorization_response_iss(result.iss, self.context.oauth_metadata)

        if not result.code:
            raise OAuthFlowError("No authorization code received")

        return result.code, pkce_params.code_verifier

    def _prepare_token_request(self, request):
        """Stamp the configured User-Agent onto a token/refresh request."""
        ua = getattr(self, "_hermes_token_user_agent", None)  # tests build via __new__
        if ua:
            request.headers["User-Agent"] = ua
        return request

    def _coerce_client_secret_post(self) -> None:
        """Same rule as ``HermesTokenStorage._coerce_secret_auth_method``, applied to the
        in-memory client info BEFORE the SDK builds a token-endpoint request from it."""
        info = self.context.client_info
        if not info:
            return
        from mcp.shared.auth import OAuthClientInformationFull
        from tools.mcp_oauth import HermesTokenStorage
        data = info.model_dump(mode="json", exclude_none=True)
        if HermesTokenStorage._coerce_secret_auth_method(data):
            self.context.client_info = OAuthClientInformationFull.model_validate(data)

    async def _exchange_token_authorization_code(self, *args: Any, **kwargs: Any):
        self._coerce_client_secret_post()
        return self._prepare_token_request(await super()._exchange_token_authorization_code(*args, **kwargs))

    async def _refresh_token(self):
        self._coerce_client_secret_post()
        return self._prepare_token_request(await super()._refresh_token())

    def _preserve_prior_refresh_token(self, token_response):
        """RFC 6749 section 6: retain the previous refresh_token when the
        response omits one. If token_response.refresh_token is falsy, use
        model_copy(update=...) to inject the prior token without mutation."""
        if token_response.refresh_token:
            return token_response
        prior_tokens = self.context.current_tokens
        if not prior_tokens or not prior_tokens.refresh_token:
            return token_response
        return token_response.model_copy(update={"refresh_token": prior_tokens.refresh_token})

    async def _store_tokens(self, token_response) -> None:
        token_response = self._preserve_prior_refresh_token(token_response)
        self.context.current_tokens = token_response
        self.context.update_token_expiry(token_response)
        await self.context.storage.set_tokens(token_response)

    async def _handle_token_response(self, response):
        """Accept any 2xx token response; never echo the body into errors."""
        from mcp.client.auth.oauth2 import OAuthTokenError
        if not (200 <= response.status_code < 300):
            raise OAuthTokenError(f"Token exchange failed ({response.status_code})")
        from httpx import HTTPError
        from mcp.client.auth.utils import handle_token_response_scopes
        try:
            token_response = await handle_token_response_scopes(response)
        except (HTTPError, OAuthTokenError):
            raise OAuthTokenError("Invalid token response") from None
        await self._store_tokens(token_response)

    async def _handle_refresh_response(self, response) -> bool:
        """Accept any 2xx refresh response; never log the body."""
        if not (200 <= response.status_code < 300):
            self._hermes_logger.warning("Token refresh failed: %s", response.status_code)
            self.context.clear_tokens()
            return False
        from httpx import HTTPError
        from mcp.shared.auth import OAuthToken
        from pydantic import ValidationError
        try:
            token_response = OAuthToken.model_validate_json(await response.aread())
        except (HTTPError, ValidationError):
            self._hermes_logger.warning("Invalid refresh response: %s", response.status_code)
            self.context.clear_tokens()
            return False
        await self._store_tokens(token_response)
        return True


def prepare_oauth_config(server_name: str, server_url: str, oauth_config: dict | None) -> tuple[dict, "HermesTokenStorage"]:
    """Copy the ``oauth:`` block, apply provider defaults, open its token storage. The copy
    matters: later steps record ``_resolved_port`` / ``_cimd_url`` in the dict, which must
    never leak back into the caller's config."""
    from tools import mcp_oauth as mo
    cfg = dict(oauth_config or {})
    mo.apply_oauth_provider_defaults(cfg, server_name=server_name, server_url=server_url)
    return cfg, mo.HermesTokenStorage(server_name)


def build_provider_kwargs(cfg: dict, storage: "HermesTokenStorage", *, ssh_proxy_hint: bool) -> dict[str, Any]:
    """Resolve the callback port and return the shared provider constructor kwargs. Order
    matters: metadata needs the resolved port, pre-registration needs the metadata.
    ``ssh_proxy_hint`` lets the redirect handler tailor its remote-session hint to a configured
    proxy ``redirect_uri``. Helpers are looked up on ``tools.mcp_oauth`` so tests can patch them."""
    from tools import mcp_oauth as mo
    port = mo._configure_callback_port(cfg, storage)
    client_metadata = mo._build_client_metadata(cfg)
    mo._maybe_preregister_client(storage, cfg, client_metadata)
    redirect_uri = (cfg.get("redirect_uri") or None) if ssh_proxy_hint else None
    extras = _sanitize_extra_auth_params(cfg.get("extra_auth_params"), warn_logger=logger)
    kwargs: dict[str, Any] = {
        "client_metadata": client_metadata,
        "storage": storage,
        "redirect_handler": mo._make_redirect_handler(port, redirect_uri=redirect_uri),
        # mcp 2.0 dropped OAuthClientProvider's own `timeout`; the configured
        # `oauth.timeout` bounds the callback waiter's poll loop instead.
        "callback_handler": mo._make_callback_waiter(port, cfg.get("_cimd_url"), timeout=float(cfg.get("timeout", 300))),
        "token_user_agent": mo.token_request_user_agent(cfg),
        **mo.cimd_provider_kwargs(cfg)}
    if extras:
        kwargs["extra_auth_params"] = extras
    return kwargs
