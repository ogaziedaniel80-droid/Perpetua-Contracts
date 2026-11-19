# Design: rent-manager RBAC, multisig-threshold resilience, oracle-router invariants

Status: **Draft** — design for net-new contracts. The three subsystems named in
the issues (`rent-manager`, `multisig-threshold`, `oracle-router`) do **not**
exist in this repository yet. This document defines how they are added as
standalone Soroban crates under `contracts/`, following the conventions already
established by `contracts/stream`, `contracts/factory`, and `contracts/governance`.

Issues covered:

| Issue | Subsystem | Objective |
|---|---|---|
| #439 | `rent-manager` | Granular role-based authorization to prevent unauthorized configuration updates |
| #437 | `multisig-threshold` | Fuzzing coverage for edge-case timestamps near `u64::MAX` |
| #435 | `multisig-threshold` | Automated entry lifetime extension for archival resilience |
| #424 | `oracle-router` | Strict invariant assertions against re-entrancy and state desync |

Each issue requires an in-depth code review, defensive error handling with
checked arithmetic, and unit/fuzz tests. Because the contracts are new, the
"review" step is a review against this repo's existing contracts: the design
below is the output of that cross-contract review, and the implementation must
satisfy it.

---

## 1. Cross-cutting principles (inherited from existing contracts)

These are not new decisions. They are the conventions every contract in this
repo already follows, restated here so the three new subsystems do not diverge.

### 1.1 Standalone crate layout

Each new contract is its own Cargo project with its own `Cargo.toml` and
`Cargo.lock`, exactly like `contracts/stream`, `contracts/factory`,
`contracts/governance`, `contracts/archival-probe`. There is no shared
workspace; crates build, test, and release independently.

```
contracts/
  rent-manager/         Cargo.toml, Cargo.lock, src/{lib.rs,error.rs,storage.rs,events.rs,types.rs}, tests/
  multisig-threshold/  Cargo.toml, Cargo.lock, src/{lib.rs,error.rs,storage.rs,events.rs,types.rs}, tests/
  oracle-router/       Cargo.toml, Cargo.lock, src/{lib.rs,error.rs,storage.rs,events.rs,types.rs}, tests/
```

Build/test invocation matches the existing pattern:

```bash
(cd contracts/rent-manager        && cargo test)
(cd contracts/multisig-threshold  && cargo test)
(cd contracts/oracle-router       && cargo test)
```

Toolchain: `soroban-sdk` 22.x contract surface against protocol 27, Rust
1.97.1, target `wasm32v1-none` — identical to the existing crates.

### 1.2 Typed errors are ABI

`#[contracterror]`, `#[repr(u32)]`, discriminants start at 1. Discriminants are
part of the public ABI: **never renumber an existing variant; only append.**
Every numeric failure is a typed error; nothing panics on a numeric edge case.
All arithmetic is checked (`checked_add` / `checked_sub` / `checked_mul` /
`checked_div`) and maps to an `Overflow`/`ArithmeticOverflow` variant. This is
the pattern in `contracts/stream/src/error.rs` and `contracts/governance/src/lib.rs`.

### 1.3 Storage keys are a versioned `DataKey` enum

`#[contracttype] #[repr(u32)] enum DataKey { ... }` with explicit discriminants.
Discriminants are chosen deliberately and documented inline, because sharing a
code between two unit variants makes them the same storage slot — the governance
contract documents a real bug of exactly this kind (`SignerGeneration` vs
`NextProposalId`). New keys append a fresh, unused discriminant with a comment
explaining why it is not the "next free" number.

### 1.4 Authorization

Mutating entrypoints call `Address::require_auth()` on the authorized caller.
The contract never trusts a caller's self-reported identity; auth is enforced by
the Soroban host. Views never mutate and never extend TTL (matching
`contracts/stream`'s view policy — views are called through simulation where a
footprint write is noise).

### 1.5 Events

Audit-log events use `#[contracttype]` structs. **Topics** carry
indexer-friendly filter keys (event name, entity id, acting address); **data**
carries the full schema. `entity_id` is always the second topic element so a
single topic subscription reconstructs a full lifecycle. State mutation
precedes the event (CEI).

### 1.6 TTL / rent policy (the hard part)

Persistent entries archive when their ledger TTL runs out. Archived does not
mean lost — funds/balances remain — but the accounting entry is unreadable
until someone pays to restore it. Every contract here engineers around this
with the same three mechanisms, and the two new persistent-state contracts
(`rent-manager`, `multisig-threshold`) must follow them:

1. **Extend on every touch.** Every mutating call bumps the touched entry's TTL.
2. **Extend generously at creation**, targeting remaining lifetime + buffer,
   floored at a minimum, clamped to the network's `max_entry_ttl` (queried
   dynamically via `env.storage().max_ttl()`, never baked in — it can change on
   protocol upgrade).
3. **Permissionless `extend_*_ttl` / `batch_extend_ttl`.** Anyone may pay to keep
   an entry alive. Unauthenticated on purpose: a claim must never depend on the
   original owner's continued goodwill, and TTL extension cannot move funds or
   change state, so there is nothing to grief.

Constants and helpers are ported from `contracts/stream/src/storage.rs`:
`SECONDS_PER_LEDGER = 5` (nominal, conservative), `seconds_to_ledgers` rounds
**up** (ceiling) so a TTL target never undershoots, a `MIN_*_TTL_LEDGERS` floor
with a drift headroom multiplier, and a per-state retention table.

### 1.7 Re-entrancy and state desync

Soroban cross-contract calls are synchronous and the host reverts the whole
transaction on error, so classic re-entrancy is largely structural. The
existing contracts still defend explicitly:

- **CEI ordering** (checks-effects-interactions): all state mutations happen
  before any external call, and before the success event.
- **Instance-flag reentrancy guard**: an `Executing` instance entry is set on
  entry to a dispatching function and cleared on exit; a re-entrant call finds
  it set and returns a `ReentrancyGuard` error. This is the pattern in
  `contracts/governance` (issue #47).
- **Invariant assertions** at trust boundaries: after loading state and before
  committing state, assert invariants the contract claims to maintain. A
  violated invariant is a typed error, not a silent corruption.

---

## 2. `rent-manager` — granular role-based authorization (#439)

### 2.1 Problem

A rent manager is responsible for collecting and distributing Soroban
persistent-storage rent across the protocol's contracts (or across streams). It
holds configuration that is operationally sensitive — which contracts are
covered, the rent budget per contract, the keeper reward, the fallback
recipient for unrecoverable rent. If any caller can change this configuration,
an attacker can redirect rent, drain the keeper reward, or unregister a
covered contract so its entries silently archive.

### 2.2 Design: roles, not a single admin

A single admin is too coarse — it forces all configuration changes through one
key, which is both an operational bottleneck and a single point of compromise.
Instead, authorization is split into **roles**, each scoped to the operations
it needs. This mirrors how `contracts/governance` separates the admin (membership
management) from emergency guardians (cancellation) from signers (approval).

#### Roles

| Role | Key | Permitted operations | Denied |
|---|---|---|---|
| `Admin` | instance, singleton | grant/revoke roles, set `ConfigAdmin` | everything else, by convention |
| `ConfigAdmin` | instance, set | `set_covered_contracts`, `set_rent_budget`, `set_keeper_reward`, `set_fallback_recipient` | role management |
| `Keeper` | instance, set | `collect_rent`, `distribute_rent`, `extend_covered_ttl` | configuration |
| `Auditor` | instance, set | all views (read-only) | any mutation |

Roles are stored as a `Map<Address, Role>` in instance storage plus a
`Map<Address, bool>` membership index per role for O(1) checks, matching the
governance `SignerIndex` pattern. `Admin` is a singleton assigned at
initialization; the initial admin is the initializer's address (the deployer),
rotatable via `set_admin` exactly as in `governance` and `factory`.

#### Authorization enforcement

Every mutating entrypoint begins with a `require_role(env, caller, Role::X)`
helper that calls `caller.require_auth()` **and** verifies the caller holds the
required role. The role check is what makes authorization *granular*: a caller
who is a `Keeper` cannot call `set_rent_budget` even though they are a known
principal, because `set_rent_budget` requires `ConfigAdmin`.

Configuration-update entrypoints (`set_*`) all require `ConfigAdmin`. This is
the literal resolution of #439: configuration updates are unauthorized for
everyone who is not `ConfigAdmin`, and `Keeper`/`Auditor`/unauthenticated
callers are rejected with `Unauthorized`.

#### Role management

- `grant_role(addr, role)` / `revoke_role(addr, role)`: require `Admin`.
- `set_admin(new_admin)`: require `Admin`, emits `AdminChanged { old, new }`.
- A role can be granted to an address that already holds a *different* role
  only by first revoking the old one (a principal holds exactly one role),
  enforced so that an address cannot silently accumulate privileges. This is
  stronger than governance's signer set and is the right choice for a contract
  that moves value.

#### Defensiveness

- `set_covered_contracts(Vec<Address>)` rejects an empty list and duplicates,
  and bounds the list (`MAX_COVERED_CONTRACTS`, derived from footprint budget as
  `MAX_BATCH_SIZE = 16` is derived from the event budget in `stream`).
- `set_rent_budget(i128)`, `set_keeper_reward(i128)` reject zero/negative and
  require `keeper_reward <= rent_budget` (a keeper cannot be promised more than
  the budget collects), checked with `checked_add` when summing across covered
  contracts.
- `set_fallback_recipient(Address)` rejects the zero address and the contract's
  own address.

### 2.3 Errors (append-only, `#[repr(u32)]`)

```
NotInitialized = 1
AlreadyInitialized = 2
Unauthorized = 3          // caller lacks the required role
RoleNotFound = 4
DuplicateRole = 5         // address already holds a different role
InvalidConfig = 6         // empty list, duplicate, zero/negative value, etc.
CoveredContractsTooMany = 7
ArithmeticOverflow = 8
CoveredContractNotFound = 9
InsufficientRent = 10
KeeperRewardExceedsBudget = 11
InvalidAddress = 12
ReentrancyGuard = 13
```

### 2.4 Storage (`DataKey`)

```
Admin = 0
ConfigAdmin = 1              // set of ConfigAdmin addresses
Keeper = 2                    // set of Keeper addresses
Auditor = 3
Roles = 4                     // Map<Address, Role> — authoritative role assignment
CoveredContracts = 5          // Vec<Address>
RentBudget = 6
KeeperReward = 7
FallbackRecipient = 8
RentLedger(contract_id) = 9   // per-contract rent accumulator (persistent)
Executing = 10                 // reentrancy guard (instance)
```

`CoveredContracts`, `RentBudget`, `KeeperReward`, `FallbackRecipient` live in
instance storage (small, frequently read, config). Per-contract rent
accumulators live in persistent storage keyed by contract address and follow
the §1.6 TTL policy.

### 2.5 Tests

Unit tests (`src/test/`):

- `grant_role`/`revoke_role` enforce `Admin`; non-admin rejected with `Unauthorized`.
- Each `set_*` rejects callers without `ConfigAdmin`.
- `Keeper` can `collect_rent`/`distribute_rent` but cannot `set_*`.
- `Auditor` can read all views but every mutating call is rejected.
- `DuplicateRole` when granting a role to an address holding another role.
- `KeeperRewardExceedsBudget` and `InvalidConfig` paths.
- `set_admin` rotates and emits `AdminChanged`; old admin loses access.
- Reentrancy guard: a `collect_rent` that re-enters `collect_rent` aborts with
  `ReentrancyGuard` (via a mock that calls back).

Fuzz tests (see §5): role-assignment sequences never grant a principal two
roles; every configuration reachable through valid `set_*` calls satisfies
`keeper_reward <= rent_budget` and non-empty `CoveredContracts`.

---

## 3. `multisig-threshold` — archival resilience + `u64` boundary fuzzing (#435, #437)

`multisig-threshold` is a threshold multisig: an operation is authorized once a
threshold of signers approve it, with no timelock (unlike `governance`, which is
the timelocked policy multisig). It is the closest analogue to
`contracts/governance`, and the design reuses governance's data model
approach — `Proposal`, `ProposalStatus`, signer set with weights, signer
generation, approval index — adapted to threshold-only semantics.

### 3.1 #435: automated entry lifetime extension (archival resilience)

The threat: a multisig entry whose TTL elapses archives, so the threshold of
approvals collected so far is unreadable until someone restores the entry — and
because there is no timelock, an archived entry can block an otherwise-complete
authorization indefinitely. The fix is the same retention model
`contracts/stream` and `contracts/governance` already use, ported to this
contract's entries.

#### State-aware retention

| Proposal state | Rent target on any touch | Why |
|---|---|---|
| `Proposed` / `Approved` (active, below threshold) | remaining executable lifetime + buffer, floored at `MIN_PROPOSAL_TTL_LEDGERS` | an active proposal must not archive before it reaches threshold, however long signers wait between approvals |
| `ThresholdMet` (executable, not yet executed) | `MIN_PROPOSAL_TTL_LEDGERS` floor | a met-threshold proposal is ready to execute; keep it readable long enough for an executor to act, then let it decay |
| `Executed` / `Cancelled` (terminal) | one-shot floor granted at transition, never topped up | terminal records are reconciled by indexers against their events, then left to decay; topping them up forever is the unbounded-rent growth this policy prevents |

A proposal owns three persistent entries (record, approval-index, signer-generation
snapshot). They are read and written together and share a lifetime, so they
share one policy — keeping the record alive while the index decays would
corrupt the duplicate-approval check or the threshold gate.

#### Mechanisms (ported from `contracts/stream/src/storage.rs`)

1. **Extend on every touch.** `approve`, `execute`, `cancel` each call
   `bump_proposal_retention` on the three entries they touched.
2. **Extend generously at creation.** `propose` grants the active-proposal bump
   (max proposal age + headroom, clamped to `max_entry_ttl`).
3. **Permissionless `extend_proposal_ttl(id)` and `batch_extend_ttl(ids)`.**
   Anyone may pay to keep a proposal alive; the calls only extend TTL, never
   touch state, so there is nothing to grief. The instance entry (proposal id
   counter) is always pinned to `max_entry_ttl`, so the counter can never archive
   before the proposals it issued (the ordering guarantee from `stream`).

Constants ported verbatim with renamed prefixes: `SECONDS_PER_LEDGER = 5`,
`seconds_to_ledgers` (ceiling), `MIN_PROPOSAL_TTL_LEDGERS` with the 10% drift
multiplier, `max_entry_ttl` queried at call time. `ledgers(seconds)` saturates
rather than wraps, so a misconfigured constant clamps instead of becoming a
negative-length window.

#### Why this resolves #435

An actively-used proposal cannot archive while it is still actionable (extend
on touch + generous creation bump). A proposal whose signers go quiet is kept
readable by any passer-by (permissionless extend). A terminal proposal stops
consuming rent (one-shot floor, no further top-ups). Archival resilience is the
combination of the three, and the tests below prove each leg.

### 3.2 #437: fuzzing edge-case timestamps near `u64::MAX`

The threshold multisig computes several timestamps:

- `created_at` = ledger timestamp at proposal submission.
- `max_executable_at = created_at.checked_add(MAX_PROPOSAL_AGE_SECONDS)?` — the
  window after which `approve`/`execute` reject with `ProposalExpired`.
- approval ordering: approvals are time-stamped; the *last* approval that
  crosses the threshold sets `threshold_met_at`, recorded for audit.
- `execute` may apply the operation at the current ledger timestamp.

Near `u64::MAX`, every one of these `checked_add`/`checked_sub` paths is a live
overflow surface. The existing `governance` contract uses `checked_add` and
returns `ArithmeticOverflow`; the design requirement here is *coverage* — a fuzz
harness that drives these paths with timestamps at and near `u64::MAX` and
asserts that the contract never panics, wraps, or accepts an impossible
deadline.

#### Fuzz targets

1. **`fuzz_proposal_age_near_u64_max`**: seed `created_at` in
   `[u64::MAX - 2*MAX_PROPOSAL_AGE_SECONDS, u64::MAX]`. Submit proposals, drive
   approvals across the boundary. Assert: no panic; every computed
   `max_executable_at` either equals `created_at + MAX_PROPOSAL_AGE_SECONDS` or
   the call returns `ArithmeticOverflow`; an overflowed deadline is never stored.
2. **`fuzz_threshold_met_timestamp`**: drive the final approval that crosses
   threshold at ledger timestamps near `u64::MAX`. Assert `threshold_met_at` is
   either the ledger timestamp or the call rejects with `ArithmeticOverflow`,
   never a wrapped value.
3. **`fuzz_ttl_target_near_u64_max`**: with `end_time`-equivalent fields near
   `u64::MAX`, assert `ttl_target_ledgers` saturates at `u32::MAX` and then
   clamps to `max_entry_ttl`, never wraps to a tiny TTL (which would let the
   entry archive immediately).
4. **`fuzz_checked_sub_remaining`**: `remaining = end.saturating_sub(now)` must
   never underflow; the saturating choice is intentional and documented
   (mirrors `contracts/stream/src/storage.rs`).

#### Harness choice

Two complementary layers, matching how `contracts/stream` already does property
testing (env vars `FLUXORA_FUZZ_SEEDS`, `FLUXORA_FUZZ_STEPS`, `PROPTEST_CASES`):

- **In-crate `proptest`** for deterministic, CI-friendly shrinking — the
  boundary inputs shrink cleanly, which is exactly what makes proptest valuable
  here.
- **`cargo +nightly fuzz`** targets for long unstructured runs (nightly CI),
  as the `stream` contract does randomized sweeps.

Both reuse a pure helper layer (timestamp arithmetic extracted into a
`#[inline] fn` with no `Env`, like `contracts/stream/src/accrual.rs`) so a fuzz
case costs microseconds instead of a host invocation.

### 3.3 Errors (append-only)

Reuse governance's discriminant plan, adapted:

```
NotInitialized = 1
AlreadyInitialized = 2
Unauthorized = 3
NotASigner = 4
ProposalNotFound = 5
AlreadyExecuted = 6
ThresholdNotReached = 7
AlreadyApproved = 8
ProposalExpired = 9
ProposalCancelled = 10
NotProposerOrAdmin = 11
InvalidThreshold = 12
ThresholdWouldBreak = 13       // removing a signer drops signers below threshold
DuplicateSigner = 14
ArithmeticOverflow = 15        // checked-add on timestamps/deadlines
InvalidSignerGeneration = 16
ReentrancyGuard = 17
BatchTooLarge = 18
```

### 3.4 Storage (`DataKey`)

```
Admin = 0
Signers = 1
Threshold = 2
NextProposalId = 3
Proposal(id) = 4              // persistent
SignerIndex = 5
ProposalApprovalIdx(id) = 6  // persistent, duplicate-approval detection
SignerGeneration = 7         // NOT 3 — collides with NextProposalId (see governance)
Executing = 8                 // reentrancy guard
SignerWeights = 9
```

The `SignerGeneration` discriminant is set deliberately **not** to the implicit
"next free" number, exactly as `contracts/governance` documents: `3` is
`NextProposalId`, and two unit variants sharing a code collapse to one slot.

### 3.5 Tests

Unit + property, in `src/test/` and `tests/`:

- Threshold semantics: exactly `threshold` approvals authorize; `threshold-1`
  does not.
- `InvalidThreshold` for zero or `> signer_count`; `ThresholdWouldBreak` when
  removing a signer would drop below threshold.
- `ProposalExpired` after `created_at + MAX_PROPOSAL_AGE_SECONDS`.
- Signer-generation invalidation: a proposal under an old generation is
  rejected with `InvalidSignerGeneration`.
- Retention (#435): a proposal kept only by keeper sweeps survives a
  multi-window lifetime; terminal proposals get a one-shot floor and decay;
  the instance counter never archives before its proposals (port
  `test::ttl` from `stream`).
- Fuzz (#437): the four targets above, run under both `proptest` and
  `cargo +nightly fuzz`, asserting no panic/wrap/accept-impossible-deadline.

The known caveat from `docs/KNOWN-LIMITATIONS.md §1` applies: the SDK test host
auto-restores expired entries in recording mode, so these tests prove the
*rent arithmetic and extend-on-touch behavior*, not the live-network
restore-fail-then-resubmit flow. That distinction is stated in the test module
docs, as it is in `stream`.

---

## 4. `oracle-router` — strict invariant assertions (#424)

### 4.1 Problem

An oracle router aggregates prices from a whitelist of upstream oracle
contracts and exposes a single `price(asset) -> i128` (and a decimal-scale
`decimals`) to consumers. Two classes of failure:

1. **State desync**: the router's cached aggregate disagrees with the oracle
   inputs it was derived from — e.g. a partial update left the aggregate stale
   while one oracle was marked fresh, or a decimal-rescaling rounded in a
   direction that broke the conservation `aggregate == f(inputs)`.
2. **Re-entrancy**: an upstream oracle callback that re-enters the router during
   an update could observe a half-updated whitelist or aggregate and corrupt
   state or double-count an update.

### 4.2 Design: invariant assertions at trust boundaries

The contract defines a small set of invariants it claims to maintain, and
asserts each at the point it could be violated: after loading oracle state,
before committing an aggregate, and before returning a price. A violated
invariant returns a typed error and reverts (Soroban reverts the whole
transaction, so no partial state is committed).

#### Invariants

- **I1 — Whitelist integrity**: every oracle used in an aggregate is in the
  whitelist and not disabled. Asserted before `update_aggregate` and before
  `price`.
- **I2 — Freshness**: the aggregate's `updated_at` is `>=` every contributing
  oracle's `updated_at`, and `<=` the current ledger timestamp. A stale
  aggregate (older than `MAX_STALENESS_SECONDS`) returns `StalePrice` and is
  never silently served.
- **I3 — Conservation**: `aggregate_price == aggregate_fn(oracle_prices)` for
  the configured aggregation (median by default). Recomputed from the stored
  inputs immediately before the aggregate is committed and before it is served.
  A mismatch returns `AggregateDesync` and reverts — this is the literal
  resolution of "state desync."
- **I4 — Decimal scaling**: `price` returns a value normalized to the router's
  declared `decimals`. Each oracle's `decimals` is read and the rescaling uses
  checked `checked_mul`/`checked_div`; a scaling that would overflow returns
  `ArithmeticOverflow`, never a truncated value.
- **I5 — Monotonic id**: every update increments an `update_id` with
  `checked_add`; the aggregate record carries the `update_id` it was computed
  from, and `price` asserts the served aggregate's `update_id` equals the latest
  — serving a stale `update_id` returns `AggregateDesync`.

Each invariant maps to a typed error so a consumer can distinguish stale price
from a corrupted aggregate from a missing oracle.

### 4.3 Re-entrancy defense

- **CEI**: `update_aggregate` loads all oracle prices (effects-input), computes
  the aggregate, writes the new aggregate and `update_id`, then emits
  `AggregateUpdated`. No external call follows the writes; the only external
  calls (to upstream oracles) precede the writes.
- **Instance-flag guard**: `Executing` instance entry set on entry to
  `update_aggregate`, cleared on exit. A re-entrant `update_aggregate` (an
  upstream oracle that calls back into the router) finds the flag set and
  returns `ReentrancyGuard`. This is the `governance` #47 pattern.
- **Whitelist mutation is not callable from an oracle callback path**: only
  `set_oracles` (an admin/config call) mutates the whitelist, and it cannot run
  while `Executing` is set, so a re-entrant update cannot enlarge the oracle set
  mid-aggregation.

### 4.4 Errors (append-only)

```
NotInitialized = 1
AlreadyInitialized = 2
Unauthorized = 3
OracleNotFound = 4
OracleNotWhitelisted = 5
OracleDisabled = 6
StalePrice = 7              // aggregate older than MAX_STALENESS_SECONDS
AggregateDesync = 8          // I3/I5: recomputed aggregate != stored, or update_id mismatch
NoOraclesConfigured = 9
InsufficientOracles = 10     // fewer than min_oracles for a valid aggregate
ArithmeticOverflow = 11      // I4 decimal scaling overflow
InvalidDecimals = 12
InvalidConfig = 13
ReentrancyGuard = 14
InvalidAddress = 15
```

### 4.5 Storage (`DataKey`)

```
Admin = 0
Oracles = 1                  // Vec<Address> whitelist
OracleStatus(addr) = 2       // persistent: enabled/disabled + last_updated_at
Aggregate = 3                // instance: {price, decimals, updated_at, update_id}
Decimals = 4                 // router's declared decimals
MinOracles = 5
MaxStalenessSeconds = 6
UpdateId = 7                 // monotonic, checked_add
Executing = 8                 // reentrancy guard (instance)
```

`Aggregate` and `UpdateId` are small and read on every `price`, so they live in
instance storage. Per-oracle status is persistent and follows the §1.6 TTL
policy (extend on touch + permissionless `extend_oracle_ttl`).

### 4.6 Tests

Unit + fuzz:

- **I1**: `price` with a disabled or un-whitelisted oracle in the contributing
  set returns `OracleNotWhitelisted`/`OracleDisabled`.
- **I2**: an aggregate older than `MAX_STALENESS_SECONDS` returns `StalePrice`;
  a fresh one serves. Timestamps near `u64::MAX` for `updated_at` do not wrap
  the staleness check (`checked_sub` → `ArithmeticOverflow`).
- **I3**: deliberately corrupt the stored aggregate (via a test-only setter)
  and assert `price` returns `AggregateDesync` and reverts; `update_aggregate`
  re-derives and the next `price` succeeds.
- **I4**: decimal rescaling with oracle decimals far from router decimals
  overflows → `ArithmeticOverflow`, never truncation.
- **I5**: serving an aggregate whose `update_id` != latest returns
  `AggregateDesync`.
- **Re-entrancy**: an upstream oracle mock that calls back into
  `update_aggregate` triggers `ReentrancyGuard` and the outer call reverts
  cleanly with no partial whitelist/aggregate change.
- **Fuzz**: randomized oracle price sequences (including extreme `i128` values
  and mismatched decimals) assert that every served price satisfies I2, I3, I4,
  I5 and that no sequence causes a panic or a non-typed abort.

---

## 5. Testing strategy (cross-cutting)

All three contracts use the repo's established testing approach:

- **Unit tests** in `src/test/` (or `tests/`), staged by build order as in
  `contracts/stream/src/test/`.
- **Property tests** via `proptest`, driven by the same env vars the suite
  already uses (`PROPTEST_CASES`, `FLUXORA_FUZZ_SEEDS`, `FLUXORA_FUZZ_STEPS`).
- **`cargo +nightly fuzz`** targets for long unstructured runs, run in nightly
  CI as `contracts/stream` already is.
- **Pure helper layer**: timestamp arithmetic, aggregate computation, and role
  resolution are extracted into `#[inline] fn`s with no `Env` (the
  `contracts/stream/src/accrual.rs` discipline), so a fuzz case is microseconds,
  not a host invocation, and the math is auditable in one place.

Every contract's test module documents the `KNOWN-LIMITATIONS.md §1` caveat:
the SDK test host auto-restores archived entries in recording mode, so TTL
tests prove the rent arithmetic and extend-on-touch behavior, not the
live-network restore-fail-then-resubmit flow. That half is closed against
testnet separately (the `archival-probe` pattern).

---

## 6. Out of scope / open questions

1. **Are these contracts actually wanted in this repo?** They are new
   subsystems, not hardening of existing ones. If the intent was to harden the
   closest existing analogues instead, the work maps to: `governance` for the
   two `multisig-threshold` issues, `factory` for the `rent-manager` RBAC issue.
   Confirm before implementation proceeds against new crates.
2. **`rent-manager` value flow**: this design covers authorization and
   configuration. Whether rent is *collected as tokens* (a SEP-41 transfer) or
   *accounted as ledger rent* (no token movement, only ledger-entry TTL) is a
   product decision that changes the `collect_rent`/`distribute_rent` surface.
   The RBAC design is independent of it, but the tests are not.
3. **`oracle-router` aggregation**: median is the default; a configurable
   aggregation function (mean with outlier rejection, etc.) is out of scope
   unless requested. The invariant-assertion design accommodates either, since
   I3 recomputes against whatever `aggregate_fn` is configured.
4. **Deployment naming**: following `fluxora_<name>.wasm`, the wasms would be
   `fluxora_rent_manager.wasm`, `fluxora_multisig_threshold.wasm`,
   `fluxora_oracle_router.wasm`. `script/release.sh` currently builds only the
   product (`fluxora_stream`); releasing these would extend it.

---

## 7. Acceptance criteria

- [ ] Each new contract is a standalone Cargo crate under `contracts/` and
      builds/tests independently: `cargo test` and
      `cargo build --target wasm32v1-none --release`.
- [ ] `rent-manager`: every `set_*` configuration entrypoint rejects non-
      `ConfigAdmin` callers with `Unauthorized`; unit tests cover all four roles
      and the cross-role rejection matrix.
- [ ] `multisig-threshold`: a proposal survives a multi-TTL-window lifetime on
      keeper sweeps alone (#435); terminal proposals decay after a one-shot
      floor; the instance counter never archives before its proposals.
- [ ] `multisig-threshold`: the four `u64::MAX` fuzz targets pass under both
      `proptest` and `cargo +nightly fuzz` with no panic, wrap, or accepted
      impossible deadline (#437).
- [ ] `oracle-router`: invariants I1–I5 are each asserted at their trust
      boundary and each maps to a typed error; a deliberately desynced
      aggregate returns `AggregateDesync` and reverts; the re-entrancy mock
      returns `ReentrancyGuard` with no partial state (#424).
- [ ] All arithmetic is checked; every numeric failure is a typed error; no
      `unwrap`/`expect`/`panic` on numeric paths.
- [ ] Error discriminants are append-only `#[repr(u32)]` starting at 1; `DataKey`
      discriminants are explicit, documented, and collision-free.
