"""Tests for OAuth server metadata persistence across process restarts.

Covers:
- :class:`HermesTokenStorage` ``.meta.json`` roundtrip (save / load / remove)
- The production manager provider
  (:class:`tools.mcp_oauth_manager.HermesMCPOAuthProvider`) restoring metadata
  on cold-load init and persisting metadata at the end of ``async_auth_flow``.

Context
=======
The MCP SDK discovers OAuth server metadata (``token_endpoint``, etc.)
on-demand and keeps it in memory only. Without disk persistence a restart
forces the SDK to fall back to guessing ``{server_url}/token``, which returns
404 on most real providers and triggers a full browser re-auth even when the
refresh token is still valid. These tests lock in the disk persistence
layer so refresh across restarts stays quiet.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp.shared.auth import OAuthMetadata

from tools.mcp_oauth import HermesTokenStorage
from tools.mcp_oauth_manager import _HERMES_PROVIDER_CLS


def _make_metadata(token_endpoint: str = "https://auth.example.com/oauth/token") -> OAuthMetadata:
    return OAuthMetadata.model_validate(
        {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": token_endpoint,
            "response_types_supported": ["code"],
        }
    )


# ---------------------------------------------------------------------------
# HermesTokenStorage metadata roundtrip
# ---------------------------------------------------------------------------


class TestMetadataStorage:
    def test_save_and_load_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        storage = HermesTokenStorage("example-server")

        meta = _make_metadata()
        storage.save_oauth_metadata(meta)

        meta_path = tmp_path / "mcp-tokens" / "example-server.meta.json"
        assert meta_path.exists()

        loaded = storage.load_oauth_metadata()
        assert loaded is not None
        assert str(loaded.token_endpoint) == "https://auth.example.com/oauth/token"
        assert str(loaded.issuer).rstrip("/") == "https://auth.example.com"


    def test_remove_deletes_meta_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        storage = HermesTokenStorage("cleanup-server")

        storage.save_oauth_metadata(_make_metadata())
        assert storage._meta_path().exists()

        storage.remove()
        assert not storage._meta_path().exists()


# ---------------------------------------------------------------------------
# Manager-path provider (HermesMCPOAuthProvider) — production code path
# ---------------------------------------------------------------------------


def _manager_provider_with_context(storage: HermesTokenStorage, **context_attrs):
    """Build an uninitialized manager provider with a mocked context.

    Bypasses the full OAuthClientProvider init so we can exercise the
    override logic in isolation.
    """
    if _HERMES_PROVIDER_CLS is None:
        pytest.skip("MCP SDK auth not available")
    provider = _HERMES_PROVIDER_CLS.__new__(_HERMES_PROVIDER_CLS)
    provider._hermes_server_name = context_attrs.get("server_name", "srv")
    context = MagicMock()
    context.storage = storage
    context.oauth_metadata = context_attrs.get("oauth_metadata")
    context.current_tokens = context_attrs.get("current_tokens")
    context.server_url = context_attrs.get("server_url", "https://example.com")
    context.update_token_expiry = MagicMock()
    provider.context = context
    return provider


class TestManagerOAuthProviderMetadata:
    def test_initialize_restores_metadata_from_disk(self, tmp_path, monkeypatch):
        """Cold-load: if we have no in-memory metadata but disk has some, restore it."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        storage = HermesTokenStorage("mgr-srv")
        storage.save_oauth_metadata(_make_metadata("https://mgr.example.com/token"))
        provider = _manager_provider_with_context(storage, oauth_metadata=None)

        with patch.object(
            _HERMES_PROVIDER_CLS.__bases__[-1], "_initialize", new=AsyncMock()
        ):
            asyncio.run(provider._initialize())

        assert provider.context.oauth_metadata is not None
        assert str(provider.context.oauth_metadata.token_endpoint) == \
            "https://mgr.example.com/token"


    def test_async_auth_flow_persists_on_completion(self, tmp_path, monkeypatch):
        """End-to-end: running the wrapped auth_flow persists discovered metadata."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        storage = HermesTokenStorage("flow-srv")
        provider = _manager_provider_with_context(
            storage,
            oauth_metadata=_make_metadata("https://flow.example.com/token"),
            server_name="flow-srv",
        )

        async def fake_parent_flow(self, request):
            if False:
                yield  # pragma: no cover -- make this an async generator
            return

        manager = MagicMock()
        manager.invalidate_if_disk_changed = AsyncMock(return_value=False)

        with patch.object(
            _HERMES_PROVIDER_CLS.__bases__[-1],
            "async_auth_flow",
            new=fake_parent_flow,
        ), patch("tools.mcp_oauth_manager.get_manager", return_value=manager):
            async def drive():
                gen = provider.async_auth_flow(MagicMock())
                async for _ in gen:
                    pass

            asyncio.run(drive())

        loaded = storage.load_oauth_metadata()
        assert loaded is not None
        assert str(loaded.token_endpoint) == "https://flow.example.com/token"


# ---------------------------------------------------------------------------
# Bare-origin trailing-slash normalization in the pre-flight discovery path
# ---------------------------------------------------------------------------


class TestNormalizeAuthServerUrl:
    """Unit tests for HermesMCPOAuthProvider._normalize_auth_server_url.

    The normalization helper strips a trailing slash from a bare-origin http/https
    URL (path exactly '/') so the MCP SDK's string-equality issuer check succeeds
    when PRM and ASM spell the same origin differently.
    """

    def _provider_with_url(self, url):
        if _HERMES_PROVIDER_CLS is None:
            pytest.skip("MCP SDK auth not available")
        provider = _HERMES_PROVIDER_CLS.__new__(_HERMES_PROVIDER_CLS)
        provider._hermes_server_name = "test"
        context = MagicMock()
        context.auth_server_url = url
        provider.context = context
        return provider

    def test_bare_origin_https_slash_stripped(self):
        """https://accounts.google.com/ → https://accounts.google.com"""
        p = self._provider_with_url("https://accounts.google.com/")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "https://accounts.google.com"

    def test_bare_origin_http_slash_stripped(self):
        """http://localhost/ → http://localhost"""
        p = self._provider_with_url("http://localhost/")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "http://localhost"

    def test_bare_origin_with_port_slash_stripped(self):
        """https://auth.example.com:8080/ → https://auth.example.com:8080"""
        p = self._provider_with_url("https://auth.example.com:8080/")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "https://auth.example.com:8080"

    def test_no_slash_unchanged(self):
        """https://accounts.google.com (no slash) is unchanged."""
        p = self._provider_with_url("https://accounts.google.com")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "https://accounts.google.com"

    def test_path_bearing_url_not_normalized(self):
        """https://idp.example.com/tenant/ has path /tenant/ — must not be touched."""
        p = self._provider_with_url("https://idp.example.com/tenant/")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "https://idp.example.com/tenant/"

    def test_url_with_query_not_normalized(self):
        """A URL with query string must not be altered."""
        p = self._provider_with_url("https://accounts.example.com/?realm=corp")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "https://accounts.example.com/?realm=corp"

    def test_url_with_fragment_not_normalized(self):
        """A URL with a fragment must not be altered."""
        p = self._provider_with_url("https://accounts.example.com/#section")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "https://accounts.example.com/#section"

    def test_none_url_no_error(self):
        """None auth_server_url must not raise."""
        p = self._provider_with_url(None)
        p._normalize_auth_server_url()
        assert p.context.auth_server_url is None

    def test_empty_url_no_error(self):
        """Empty-string auth_server_url must not raise."""
        p = self._provider_with_url("")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == ""

    def test_non_http_scheme_not_normalized(self):
        """ftp://auth.example.com/ must not be touched (scheme is not http/https)."""
        p = self._provider_with_url("ftp://auth.example.com/")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "ftp://auth.example.com/"

    def test_no_authority_https_not_normalized(self):
        """https:/ (no netloc/authority) must not be touched."""
        p = self._provider_with_url("https:/")
        p._normalize_auth_server_url()
        assert p.context.auth_server_url == "https:/"
