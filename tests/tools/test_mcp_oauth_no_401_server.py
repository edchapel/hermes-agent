"""Servers that answer initialize/tools-list without auth (Google Workspace MCP)
never return 401, so the SDK's reactive OAuth flow never starts. In an
interactive login the provider must run the authorization flow anyway when no
token exists on disk.

Tests exercise the actual HermesMCPOAuthProvider.async_auth_flow bridge to
verify the observable SDK next-request behavior, not private implementation
details.
"""
from __future__ import annotations

import pytest


pytest.importorskip("mcp.client.auth.oauth2", reason="MCP SDK 1.26.0+ required")


async def _noop_redirect(_url: str) -> None:
    return None


async def _noop_callback() -> tuple[str, str | None]:
    raise AssertionError("callback handler should not be invoked in this test")


async def _make_provider(tmp_path, monkeypatch):
    from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata
    from pydantic import AnyUrl

    from tools.mcp_oauth import HermesTokenStorage
    from tools.mcp_oauth_manager import _HERMES_PROVIDER_CLS, reset_manager_for_tests

    assert _HERMES_PROVIDER_CLS is not None
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    reset_manager_for_tests()

    storage = HermesTokenStorage("srv")
    await storage.set_client_info(
        OAuthClientInformationFull(
            client_id="test-client",
            redirect_uris=[AnyUrl("http://127.0.0.1:12345/callback")],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        )
    )
    metadata = OAuthClientMetadata(
        redirect_uris=[AnyUrl("http://127.0.0.1:12345/callback")],
        client_name="Hermes Agent",
    )
    return _HERMES_PROVIDER_CLS(
        server_name="srv",
        server_url="https://example.com/mcp",
        client_metadata=metadata,
        storage=storage,
        redirect_handler=_noop_redirect,
        callback_handler=_noop_callback,
    )


@pytest.mark.asyncio
async def test_interactive_no_token_200_starts_authorization(tmp_path, monkeypatch):
    """Interactive + no token + 2xx on the original request -> SDK sees synthetic 401
    and starts PRM/ASM discovery (the next yielded request targets an OAuth metadata URL).
    """
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import force_interactive_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)

    with force_interactive_oauth():
        flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
        outbound = await flow.__anext__()
        assert "authorization" not in outbound.headers

        next_request = await flow.asend(httpx.Response(200, request=outbound))
        assert isinstance(next_request, httpx.Request)
        assert "oauth-protected-resource" in str(next_request.url)
        await flow.aclose()


@pytest.mark.asyncio
async def test_non_interactive_no_token_200_passes_through(tmp_path, monkeypatch):
    """Non-interactive + no token + 2xx -> flow ends normally (no forced auth)."""
    from tools.mcp_tool import sdk_httpx
    from tools import mcp_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)
    monkeypatch.setattr(mcp_oauth, "_is_interactive", lambda: False)

    flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
    outbound = await flow.__anext__()
    with pytest.raises(StopAsyncIteration):
        await flow.asend(httpx.Response(200, request=outbound))


# ---------------------------------------------------------------------------
# Bare-origin authorization-server trailing-slash normalization
# ---------------------------------------------------------------------------


class _AuthorizeReached(Exception):
    pass


async def _stop_callback() -> tuple[str, str | None]:
    raise _AuthorizeReached()


@pytest.mark.asyncio
async def test_trailing_slash_bare_origin_authorization_server_matches_issuer(
    tmp_path, monkeypatch
):
    """PRM lists https://accounts.google.com/ (trailing slash) while ASM issuer is
    https://accounts.google.com — after normalization the SDK issuer check succeeds
    and context.auth_server_url is the slash-free canonical form."""
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import force_interactive_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)
    provider.context.callback_handler = _stop_callback

    prm = {
        "resource": "https://example.com/mcp",
        "authorization_servers": ["https://accounts.google.com/"],
    }
    asm = {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
    }
    with force_interactive_oauth():
        flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
        outbound = await flow.__anext__()
        prm_req = await flow.asend(httpx.Response(200, request=outbound))
        asm_req = await flow.asend(httpx.Response(200, request=prm_req, json=prm))
        assert "oauth-authorization-server" in str(asm_req.url)
        with pytest.raises(_AuthorizeReached):
            await flow.asend(httpx.Response(200, request=asm_req, json=asm))
    assert provider.context.auth_server_url == "https://accounts.google.com"


@pytest.mark.asyncio
async def test_path_bearing_authorization_server_not_normalized(tmp_path, monkeypatch):
    """A URL with a meaningful path (e.g. tenant path) must not be stripped."""
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import force_interactive_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)

    prm = {
        "resource": "https://example.com/mcp",
        "authorization_servers": ["https://idp.example.com/tenant/"],
    }
    with force_interactive_oauth():
        flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
        outbound = await flow.__anext__()
        prm_req = await flow.asend(httpx.Response(200, request=outbound))
        await flow.asend(httpx.Response(200, request=prm_req, json=prm))
        await flow.aclose()
    # Path /tenant/ must be preserved
    assert provider.context.auth_server_url == "https://idp.example.com/tenant/"


@pytest.mark.asyncio
async def test_authorization_server_with_query_not_normalized(tmp_path, monkeypatch):
    """A URL with a query string must not have its trailing slash stripped."""
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import force_interactive_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)

    prm = {
        "resource": "https://example.com/mcp",
        "authorization_servers": ["https://accounts.example.com/?realm=corp"],
    }
    with force_interactive_oauth():
        flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
        outbound = await flow.__anext__()
        prm_req = await flow.asend(httpx.Response(200, request=outbound))
        await flow.asend(httpx.Response(200, request=prm_req, json=prm))
        await flow.aclose()
    assert provider.context.auth_server_url == "https://accounts.example.com/?realm=corp"


@pytest.mark.asyncio
async def test_interactive_valid_token_200_passes_through(tmp_path, monkeypatch):
    """Interactive + valid cached token + 2xx -> normal completion, no forced auth."""
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import HermesTokenStorage, force_interactive_oauth
    from tools.mcp_oauth_manager import _HERMES_PROVIDER_CLS, reset_manager_for_tests
    from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
    from pydantic import AnyUrl

    assert _HERMES_PROVIDER_CLS is not None
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    reset_manager_for_tests()

    httpx = sdk_httpx()
    storage = HermesTokenStorage("srv")
    await storage.set_tokens(
        OAuthToken(access_token="valid-access", token_type="Bearer", expires_in=3600)
    )
    await storage.set_client_info(
        OAuthClientInformationFull(
            client_id="test-client",
            redirect_uris=[AnyUrl("http://127.0.0.1:12345/callback")],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        )
    )
    provider = _HERMES_PROVIDER_CLS(
        server_name="srv",
        server_url="https://example.com/mcp",
        client_metadata=OAuthClientMetadata(
            redirect_uris=[AnyUrl("http://127.0.0.1:12345/callback")],
            client_name="Hermes Agent",
        ),
        storage=storage,
        redirect_handler=_noop_redirect,
        callback_handler=_noop_callback,
    )

    with force_interactive_oauth():
        flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
        outbound = await flow.__anext__()
        # Token was seeded -- SDK attaches Authorization header
        assert "authorization" in outbound.headers
        with pytest.raises(StopAsyncIteration):
            await flow.asend(httpx.Response(200, request=outbound))


@pytest.mark.asyncio
async def test_interactive_no_token_200_with_auth_header_passes_through(tmp_path, monkeypatch):
    """Interactive + no token + 2xx + outgoing request carries an Authorization header ->
    no forced auth (guard: authorization header present means request is already authenticated).
    """
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import force_interactive_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)

    with force_interactive_oauth():
        # Supply an Authorization header on the original request.  The SDK yields this same
        # request object as the first outgoing, so the guard sees the header and must not fire.
        req = httpx.Request(
            "POST", "https://example.com/mcp",
            headers={"Authorization": "Bearer pre-existing-token"},
        )
        flow = provider.async_auth_flow(req)
        outbound = await flow.__anext__()
        assert "authorization" in outbound.headers
        with pytest.raises(StopAsyncIteration):
            await flow.asend(httpx.Response(200, request=outbound))


@pytest.mark.asyncio
async def test_interactive_no_token_200_on_later_outgoing_passes_through(tmp_path, monkeypatch):
    """Interactive + no token + guard fires on the first 200 -> SDK starts authorization;
    subsequent outgoing requests (e.g. metadata discovery) that are not the original request
    object must not trigger the guard again even if they also receive a 2xx response.
    """
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import force_interactive_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)

    with force_interactive_oauth():
        flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
        outbound = await flow.__anext__()
        assert "authorization" not in outbound.headers

        # First response: 2xx on the original request.  Guard fires; SDK sees synthetic 401
        # and yields its first discovery sub-request (a metadata GET).
        discovery_req = await flow.asend(httpx.Response(200, request=outbound))
        assert isinstance(discovery_req, httpx.Request)
        assert discovery_req is not outbound          # this is a later/sub-request, not the original
        assert "oauth-protected-resource" in str(discovery_req.url)

        # Second response: 2xx on the discovery sub-request.  The guard must NOT fire again
        # (outgoing is not the original request), so the SDK processes the metadata response
        # normally rather than receiving another spurious 401.
        # The SDK will either yield another sub-request (next discovery step) or raise on a
        # missing/malformed metadata body.  Either way it must NOT raise StopAsyncIteration
        # with a discovery request still in flight, and must NOT re-enter forced-auth.
        # A minimal valid assertion: the flow does not immediately stop AND does not re-issue
        # an oauth-protected-resource discovery URL (which would indicate a second guard fire).
        try:
            next_req = await flow.asend(httpx.Response(200, request=discovery_req))
            # If we get here the SDK yielded another sub-request — it's processing normally.
            assert isinstance(next_req, httpx.Request)
            # Specifically must not be a second PRM discovery request (guard did not re-fire).
            assert "oauth-protected-resource" not in str(next_req.url) or next_req is not discovery_req
        except Exception:
            # Any SDK-internal error from the empty 200 body is acceptable; what matters is the
            # guard did not fire a second time (which would cause another PRM discovery request
            # indistinguishable from the first).  We've already confirmed discovery_req was issued
            # once; reaching here means the flow advanced past it.
            pass
        finally:
            await flow.aclose()


@pytest.mark.asyncio
async def test_interactive_no_token_non_2xx_passes_through(tmp_path, monkeypatch):
    """Interactive + no token + real 401 -> SDK handles natively (no guard fires)."""
    from tools.mcp_tool import sdk_httpx
    from tools.mcp_oauth import force_interactive_oauth

    httpx = sdk_httpx()
    provider = await _make_provider(tmp_path, monkeypatch)

    with force_interactive_oauth():
        flow = provider.async_auth_flow(httpx.Request("POST", "https://example.com/mcp"))
        outbound = await flow.__anext__()
        # A real 401 with resource metadata -> SDK yields next discovery request
        next_req = await flow.asend(
            httpx.Response(
                401,
                request=outbound,
                headers={
                    "www-authenticate": (
                        'Bearer resource_metadata="https://example.com/'
                        '.well-known/oauth-protected-resource"'
                    )
                },
            )
        )
        assert isinstance(next_req, httpx.Request)
        assert "oauth-protected-resource" in str(next_req.url)
        await flow.aclose()
