# VKarmani Desktop

Windows desktop VPN: Tauri/Rust + React/TypeScript + Xray. Work from the actual
working tree, including existing user changes; verify versions from manifests.

- Application: `D:/GIT/VKarmani-Desktop`
- Canonical internal documentation: `D:/GIT/VKarmani-Desktop_DOC`
- Start: `D:/GIT/VKarmani-Desktop_DOC/00_CONTROL/START_HERE.md`
- State: `D:/GIT/VKarmani-Desktop_DOC/00_CONTROL/PROJECT_STATE.md`
- Current task: `D:/GIT/VKarmani-Desktop_DOC/12_WORK/CURRENT.md`

Read those entrypoints, then the relevant Skill and only targeted docs/source.
Permanent policy: `00_CONTROL/CODEX_RULES.md` in the documentation root.
Source authority and search routing: `SOURCE_OF_TRUTH.md` and `PROJECT_MAP.md`.
Do not repeat a completed bootstrap or start a new fix without a user task.

## Work safely

Before application edits inspect `git status --short`, branch, HEAD and remotes.
Preserve staged, unstaged and untracked user work. No destructive reset/clean,
mass restore, stash, force checkout/push or history rewriting without explicit
authorization. No application commit, tag, push or release unless requested.

Root cause first; evidence before conclusions; smallest correct change.
Define expected behavior and acceptance criteria. No unrelated refactoring,
dependency/version updates, UI changes or speculative architecture. Audit-only
requests do not authorize application fixes. Continue authorized reversible work
without asking routine permission questions.

Networking changes must establish success, partial failure, rollback and
unexpected app/Xray-exit behavior. Own exact processes/routes/proxy changes;
never globally reset Windows networking or kill all Xray processes. Protect the
user's active VPN session. Do not expose keys, subscription URLs or runtime
credentials; preserve DPAPI, remote-fetch restrictions and updater trust.

## Skills and completion

Canonical Skills: `D:/GIT/VKarmani-Desktop_DOC/00_CONTROL/SKILLS`:
vkarmani-context, vkarmani-delivery, vkarmani-networking, vkarmani-security,
vkarmani-release, vkarmani-ui, vkarmani-docs. Read the relevant SKILL.md directly
if discovery is unavailable; never maintain another editable copy.

Complex work uses `00_CONTROL/PLANS.md` and a live `12_WORK/TASKS` ExecPlan.
Run applicable `00_CONTROL/QUALITY_GATES.md` checks, failure/negative checks and
adversarial self-review. Don't weaken tests/security to get green results.
Review diff, cleanup and minimality; report actual PASS/FAIL/BLOCKED/NOT_RUN.

After behavior changes update canonical subsystem docs, PROJECT_STATE and
CURRENT; keep reports/receipts under documentation `_SYSTEM/reports`.
Generated reports/indexes are evidence, not product source of truth. Keep
internal knowledge, research, plans and history out of this application repo.
