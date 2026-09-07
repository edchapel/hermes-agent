# MCP OAuth Manager Keep Refresh Token Implementation Plan

> **For Hermes:** Use the `claude-code` skill to implement this plan task-by-task. Do not push or create a pull request.

**Goal:** Maintain an atomic, replayable semantic port of the fork's OAuth interoperability fixes on current `upstream/main`, preserving refresh tokens and Google Workspace login behavior across CLI, TUI, dashboard, WebUI, and Desktop.

**Architecture:** Do not resolve the old branch through a line-by-line rebase. `upstream/main` extracted common provider behavior into `tools/mcp_oauth_provider.py::HermesProviderMixin`; port each behavioral intent to the current ownership point. Keep each upstream PR-equivalent behavior in its own local commit and retain this document as the replay guide. Keep the existing fork branch as an untouched behavioral reference.

**Tech stack:** Python, pytest, MCP Python SDK OAuth providers, Hermes OAuth dashboard/TUI callback flow.

---

## Current context

- Working repository: `/Users/echapel/.hermes/hermes-agent-local`
- Upstream remote: `https://github.com/NousResearch/hermes-agent.git`
- Current target at investigation time: `upstream/main` = `fc8d15d7797c36cdc78ca9cd4a07187c3cc61c91`
- Existing local work branch: `mcp-oauth-manager-keep-refresh-token`.
  - It currently contains the original eight fork commits plus three current commits from public PR heads.
  - A mechanical rebase was attempted and safely aborted due to a 466-line structural conflict in `tools/mcp_oauth_manager.py`.
  - Do not delete or rewrite this branch; use it as the behavioral reference.
- The three public PRs are still open and not merged upstream:
  - #97010: Google Workspace MCP login handling
  - #99023: preserve a prior `refresh_token` when a token/refresh response omits it
  - #93342: provider-specific authorization parameters
- The critical behavior is absent from current upstream: neither the shared provider mixin nor its token storage path preserves an existing refresh token.

## Maintenance and replay status (2026-09-07)

- Behavioral reference branch: `mcp-oauth-manager-keep-refresh-token` at `7e8d9a7ed9`. Do not rewrite or delete it.
- Semantic-port branch: `mcp-oauth-manager-keep-refresh-token-upstream`, created directly from `upstream/main` at `c4a5deeffa`.
- Ported and manually proven: RFC 6749 refresh-token carry-forward. Commit `0f22f3cf30` adds shared persistence behavior plus regression tests. A real Google Workspace refresh after forced expiry succeeded from the default Hermes profile; the stored refresh token remained present and Google rotated it.
- Pending, each to be a separate atomic local commit: guarded 2xx-without-token authorization (`#97010`), bare-origin authorization-server trailing-slash normalization (`#97010`), RFC 9207 `iss` callback propagation across dashboard/WebUI/Desktop (`#97010`).
- Ported: guarded `oauth.extra_auth_params` (`#93342`, including the later shadow guard). Commit adds `_sanitize_extra_auth_params` and `_STANDARD_OAUTH_PARAMS` to `HermesProviderMixin` in `tools/mcp_oauth_provider.py`; both `build_oauth_auth` (legacy) and manager paths receive sanitized extras via `build_provider_kwargs`.
- Historical source commits, retained for replay and future upstream reconciliation:
  - `#97010`: `327a50c5c8` (2xx authorization), `54d55c6935` (bare-origin slash), `d4563a4e30` (RFC 9207 `iss`).
  - `#99023`: `db6bc86669`, `9508caec1c`, `ad9f8ba4f5`, `0fbd4e3007` (refresh-token persistence / client metadata).
  - `#93342`: `897804730e`, `8d4ed2567c`, `f2539c43d4`, `20bfc69cf` (provider-specific authorization parameters and shadow guard).
  - Fork-only integration commit: `ef20e126bb` (manager-path extra authorization parameters).
- Upstream maintenance policy: before each replay, fetch `upstream/main`, compare each listed behavior/commit to upstream, and omit a local patch only when its tests demonstrate equivalent upstream behavior. When the upstream PR is merged or replaced by an equivalent upstream implementation, remove only the corresponding atomic local commit after verification; do not remove unrelated commits.
- Safety/compatibility: dashboard, WebUI, TUI, local Desktop, and remote Desktop gateway callback routes are first-class acceptance surfaces. Preserve existing callback state validation, optionality, and non-interactive behavior. Never push or open a pull request without explicit approval.

## Affected files

- Create: tests specific to the refactored provider/mixin only if current tests cannot be extended cleanly.
- Modify: `tools/mcp_oauth_provider.py`
  - Shared `HermesProviderMixin`; the central token persistence path (`_store_tokens`) is the correct home for refresh-token carry-forward.
  - Provider-specific authorization parameters and Google protected-resource metadata normalization should be adapted here if the SDK extension points remain in this mixin.
- Modify: `tools/mcp_oauth_manager.py`
  - Only manager-specific bridge/control-flow code that cannot live in `HermesProviderMixin`.
- Modify: `tools/mcp_oauth.py`
  - Provider construction, legacy callback waiter, and compatibility path only as required by current upstream APIs.
- Modify: `tools/mcp_dashboard_oauth.py`
  - Preserve RFC 9207 `iss` from dashboard callback receipt.
- Modify: `tui_gateway/mcp_oauth_sessions.py`
  - Read `iss` from the browser callback query string and pass it to `DashboardOAuthFlow.deliver_callback`.
- Modify/add focused tests under: `tests/tools/`
  - Reuse existing OAuth/provider/dashboard test modules where current ownership is already covered.

## Step-by-step plan

### Task 1: Establish a clean semantic-port branch

**Objective:** Start the implementation from the actual current upstream architecture without altering the preserved reference branch.

**Files:** None.

1. Fetch `upstream` and verify the working tree is clean.
2. Create a new local branch, for example `mcp-oauth-manager-keep-refresh-token-upstream`, directly from `upstream/main`.
3. Record the reference branch tip and upstream base in the implementation log/terminal output.
4. Verify `git diff upstream/main...HEAD` is empty before code work.

**Verification:** `git status --short --branch` shows the new branch with a clean tree; no remote branch is changed.

### Task 2: Map old behavior to current extension points

**Objective:** Identify current equivalents before modifying any source.

**Files:**
- Read: `tools/mcp_oauth_provider.py`
- Read: `tools/mcp_oauth.py`
- Read: `tools/mcp_oauth_manager.py`
- Read: relevant `tests/tools/test_mcp_oauth*.py`

1. Compare the current mixin’s `_store_tokens`, authorization-code handling, and `async_auth_flow` bridge against the reference branch’s behavior.
2. Locate where `extra_auth_params` can be carried into the MCP SDK authorization request without reintroducing the old inline provider class.
3. Locate the current PRM-to-ASM discovery flow and identify where a bare-origin trailing slash can be normalized before issuer comparison.
4. Confirm current callback data structures and return shapes for code, state, and `iss`.

**Verification:** Produce a concise mapping from each legacy behavior to exactly one current source location. Do not implement duplicate methods in both manager and shared provider.

### Task 3: Add failing refresh-token regression tests

**Objective:** Specify RFC 6749 section 6 behavior for both authorization-code and refresh responses through the current shared storage path.

**Files:**
- Test: existing focused OAuth-provider test module under `tests/tools/` (prefer the module that already tests `HermesProviderMixin` / `_store_tokens`).

1. Add a test with existing cached tokens containing `refresh_token="old-refresh"` and a new token response lacking `refresh_token`.
2. Assert the stored result retains `old-refresh` while adopting the new access token and expiry values.
3. Add or adapt a test using a non-mutable/Pydantic token response if the real SDK response type needs conversion before carry-forward.
4. Run only the new tests and confirm they fail against unmodified `upstream/main`.

**Verification:** Focused pytest exits non-zero for the expected missing preservation behavior, not for test setup/import errors.

### Task 4: Implement refresh-token carry-forward in the shared mixin

**Objective:** Preserve a valid existing refresh token exactly when the incoming response omits one.

**Files:**
- Modify: `tools/mcp_oauth_provider.py`
- Test: focused module selected in Task 3.

1. Add a minimal helper adjacent to `_store_tokens` that reads the cached/current tokens and fills in only a missing incoming `refresh_token`.
2. Do not overwrite a newly supplied refresh token.
3. Handle the actual response representation used by the MCP SDK without mutating an immutable model in place.
4. Invoke the helper immediately before the common storage call so both primary and manager provider paths receive the fix.
5. Run the focused tests until they pass.

**Verification:** Focused tests pass; a response with a replacement refresh token retains the replacement, and a response without one retains the old token.

### Task 5: Add/port Google anonymous-2xx authorization behavior

**Objective:** Make interactive Google Workspace MCP login start authorization when an unauthenticated MCP request gets 2xx and no token exists.

**Files:**
- Modify: `tools/mcp_oauth_provider.py` unless current manager bridge uniquely owns the generator interception.
- Modify: `tools/mcp_oauth_manager.py` only if required by the current manager bridge.
- Test: focused OAuth flow test module under `tests/tools/`.

1. Add a regression test modelling an interactive request with no cached tokens and a 2xx response from the server.
2. Assert the provider feeds an equivalent synthetic 401 to the SDK only under the guarded conditions: interactive mode, original unauthenticated request, no valid token, and no authorization header.
3. Implement the smallest current-architecture guard and synthetic response mechanism.
4. Run the targeted test plus existing non-interactive/no-token tests.

**Verification:** Interactive 2xx-without-token reaches authorization; non-interactive and already-authorized requests retain upstream behavior.

### Task 6: Normalize Google PRM authorization-server bare-origin slash

**Objective:** Avoid false issuer mismatch between `https://accounts.google.com/` from PRM and `https://accounts.google.com` from AS metadata.

**Files:**
- Modify: `tools/mcp_oauth_provider.py` or the discovered current metadata boundary.
- Test: focused OAuth metadata/discovery test module under `tests/tools/`.

1. Add a regression test using PRM `authorization_servers: ["https://accounts.google.com/"]` and AS metadata issuer `https://accounts.google.com`.
2. Confirm it fails on current upstream at the SDK issuer check.
3. Normalize only a trailing slash on a bare origin; do not rewrite URLs with meaningful paths.
4. Run the test and existing metadata discovery tests.

**Verification:** Bare-origin slash matches the issuer; a path-bearing URL is unchanged.

### Task 7: Port provider-specific authorization parameters

**Objective:** Carry configured non-standard authorization parameters into the SDK authorization request without allowing standard OAuth parameters to be shadowed.

**Files:**
- Modify: `tools/mcp_oauth_provider.py`
- Modify: `tools/mcp_oauth.py` only if configuration preparation owns the parameter handoff.
- Test: `tests/tools/test_mcp_oauth.py` or the current equivalent.

1. Adapt the useful existing tests from PR #93342 to current test fixtures.
2. Add a test showing a configured provider-specific parameter reaches the authorization URL/request.
3. Add a test showing configured extra parameters cannot replace standard fields such as `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, or PKCE fields.
4. Implement the parameter handoff at the mixin/SDK request seam identified in Task 2.
5. Run the targeted tests.

**Verification:** Provider-specific parameters are included; standards remain controlled by the OAuth flow.

### Task 8: Port RFC 9207 `iss` through the dashboard callback path

**Objective:** Preserve the authorization response issuer from web callback through dashboard/TUI handoff into the SDK callback result.

**Files:**
- Modify: `tools/mcp_dashboard_oauth.py`
- Modify: `tui_gateway/mcp_oauth_sessions.py`
- Modify: `tools/mcp_oauth.py`
- Test: existing dashboard OAuth tests under `tests/tools/`.

1. Add a test for `DashboardOAuthFlow.deliver_callback(..., iss=...)` and callback wait/normalization result.
2. Add/adapt a route/listener test that query-string `iss` reaches the flow.
3. Add the field and optional method argument without breaking callers that omit `iss`.
4. Forward it through the callback waiter into the SDK-compatible authorization result.
5. Run focused dashboard and OAuth callback tests.

**Verification:** `iss` survives end-to-end; callbacks without it remain compatible where the server does not advertise RFC 9207 support.

### Task 9: Run full relevant quality gates and review the port

**Objective:** Validate the semantic port against the repository’s current test/lint conventions.

**Files:** All modified files.

1. Discover exact repository test/lint commands from project configuration (`pyproject.toml`, Makefile, or contributor docs); do not invent commands.
2. Run all focused OAuth and dashboard/TUI tests.
3. Run the project’s relevant lint/type checks and report any pre-existing failures separately from new failures.
4. Review `git diff --check` and the final diff against `upstream/main` for duplicate old provider methods, unintentional rewrites, or unrelated changes.
5. Commit locally once as a clean outcome-focused commit after tests pass. Do not push or open a PR.

**Verification:** Relevant tests and configured checks pass (or blockers are recorded verbatim), `git diff --check` is clean, and no remote state changes.

## Risks and mitigations

- Risk: MCP SDK private APIs changed again after the old PRs. Mitigation: inspect installed SDK symbols and current upstream tests before choosing an override point; avoid relying on names that no longer exist.
- Risk: A local fix in only `mcp_oauth_manager.py` would leave `build_oauth_auth()` on the primary provider broken. Mitigation: make refresh-token preservation live at the shared `HermesProviderMixin._store_tokens` boundary and test both access paths if feasible.
- Risk: Synthetic 401 can alter normal anonymous MCP-server behavior. Mitigation: require all original guards and test non-interactive, valid-token, and already-authorized request paths.
- Risk: URL normalization could change meaningful issuer paths. Mitigation: normalize only bare origins with path `/`.
- Risk: Reintroducing the pre-refactor class structure duplicates logic. Mitigation: create the new branch from `upstream/main`, port behavior rather than cherry-picking/rebasing old file bodies, and review for duplication.
- Risk: The originally proven fork has behavior beyond current public PR heads. Mitigation: retain the reference branch unchanged and compare behavior/diffs before finalizing the semantic port.

## Manual integration testing and approval checkpoints

Manual integration testing is a required acceptance criterion, not a substitute for automated regression tests. Each checkpoint below pauses implementation until Ed runs the indicated command(s) and reports the observed result. Do not run `hermes mcp login` against the active `sr_engineer` profile: it intentionally wipes cached OAuth state before starting a new authorization flow.

### Baseline (completed, official release)

A no-network, in-memory reproduction was run directly against the official release at `/Users/echapel/.hermes/hermes-agent` (`Hermes Agent v0.21.0`, upstream `fc8d15d7`). It supplied cached tokens containing `refresh_token="keep-me"`, then called the current shared `HermesProviderMixin._store_tokens()` with a normal token response that omitted `refresh_token`.

Observed output:

```text
stored_access_token=new-access
stored_refresh_token=None
AssertionError: BUG REPRODUCED: refresh_token was discarded
```

This is the precise failure to eliminate. It does not access real token files, config, or Google.

### Isolated local test home

Use an independent Hermes home so the official running release and its tokens are never overwritten. The commands below copy configuration only; they intentionally do not copy `mcp-tokens`, client registration, `auth.json`, or state databases.

```bash
export HERMES_OAUTH_TEST_HOME="$HOME/.hermes/profiles/sr_engineer-local-oauth-test"
rm -rf "$HERMES_OAUTH_TEST_HOME"
mkdir -p "$HERMES_OAUTH_TEST_HOME"
cp "$HOME/.hermes/profiles/sr_engineer/config.yaml" "$HERMES_OAUTH_TEST_HOME/config.yaml"
[ -f "$HOME/.hermes/profiles/sr_engineer/.env" ] && cp "$HOME/.hermes/profiles/sr_engineer/.env" "$HERMES_OAUTH_TEST_HOME/.env"
chmod 700 "$HERMES_OAUTH_TEST_HOME"
```

Run the local branch from its checkout, never through the globally installed `hermes` command:

```bash
cd "$HOME/.hermes/hermes-agent-local"
HERMES_HOME="$HERMES_OAUTH_TEST_HOME" uv run --extra dev hermes --version
```

Expected: the command identifies the local checkout/version. If dependency resolution needs to create/update the local ignored `.venv`, allow that; it does not alter source or the official installation.

### Checkpoint A: after the automated refresh-token fix is green

**Why pause:** This confirms the local branch can perform a fresh Google Workspace OAuth authorization using its isolated token store before attempting any forced refresh behavior.

Ed runs:

```bash
cd "$HOME/.hermes/hermes-agent-local"
HERMES_HOME="$HERMES_OAUTH_TEST_HOME" uv run --extra dev hermes mcp login google-workspace
```

Expected: browser login completes and the CLI reports `Authenticated`. The official release remains running because it uses `/Users/echapel/.hermes/profiles/sr_engineer`, not `$HERMES_OAUTH_TEST_HOME`.

Ed reports: whether login completed, the exact final success/error line, and whether Google Workspace tools are available in a new local Hermes session. Do not paste token values or token-file contents.

### Checkpoint B: after the forced-authorization, PRM-slash, and RFC 9207 callback changes are green

**Why pause:** This is the first end-to-end test of the Google-specific login path after all callback/discovery behavior has moved to the refactored upstream architecture.

Ed removes only the isolated test-home Google OAuth state, then repeats login:

```bash
rm -f "$HERMES_OAUTH_TEST_HOME/mcp-tokens/google-workspace.json" \
      "$HERMES_OAUTH_TEST_HOME/mcp-tokens/google-workspace.client.json" \
      "$HERMES_OAUTH_TEST_HOME/mcp-tokens/google-workspace.meta.json" \
      "$HERMES_OAUTH_TEST_HOME/mcp-tokens/google-workspace.cimd-off"
cd "$HOME/.hermes/hermes-agent-local"
HERMES_HOME="$HERMES_OAUTH_TEST_HOME" uv run --extra dev hermes mcp login google-workspace
```

Expected: authorization starts even if the Google Workspace MCP server responds successfully before a token exists; the browser callback completes without an `Authorization response missing iss parameter` or authorization-server issuer-mismatch error.

Ed reports: browser opens/redirects, final CLI outcome, and any complete error text (redacting callback `code`, `state`, access token, and refresh token values).

### Checkpoint C: final refresh-token retention test

**Why pause:** This is the high-value human confirmation that a real Google refresh response does not erase the isolated refresh token.

Before this checkpoint, the implementation must provide an approved, non-secret-printing test helper or documented local command that marks only the isolated token expiry as elapsed while preserving its refresh credential. Do not hand-edit or print production token data. Then Ed runs the local connection/test action selected from the current CLI behavior:

```bash
cd "$HOME/.hermes/hermes-agent-local"
HERMES_HOME="$HERMES_OAUTH_TEST_HOME" uv run --extra dev hermes mcp test google-workspace
```

Expected: the local client refreshes/reconnects successfully and a second `mcp test google-workspace` succeeds. The helper must assert only that the isolated token file still contains a non-empty `refresh_token`; it must never print that value.

Ed reports: both command exit statuses/final lines and whether the helper reports refresh-token presence before and after refresh. If Google does not issue a refresh during this path, capture the observed status and stop rather than claiming success; the implementation must then add a deterministic integration harness or use a test authorization server.

### Checkpoint D: final regression smoke test before local commit

Ed starts a fresh local CLI session from the isolated home and invokes one Google Workspace tool that requires authentication. This verifies that persisted local OAuth state is readable after process restart.

Expected: no reauthorization prompt and a successful tool invocation. The specific tool/prompt will be chosen from the configured Google Workspace MCP tool list at that time.

## Final verification checklist

- The new branch is based directly on current `upstream/main`.
- Existing reference branch remains untouched.
- Token responses without `refresh_token` preserve the previous token; responses with one replace it.
- Google’s anonymous-2xx login path triggers interactive authorization only under the intended guard.
- Google bare-origin PRM URL slash is normalized without modifying path-bearing URLs.
- Provider-specific authorization parameters are passed through and cannot shadow standard OAuth parameters.
- Dashboard/TUI callback `iss` reaches the SDK callback result.
- Relevant tests, lint/type checks, and `git diff --check` are run with real output.
- One local clean commit is ready; no push or PR is created.
