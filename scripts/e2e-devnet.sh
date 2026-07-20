#!/usr/bin/env bash
# G4 e2e (docs/build-plan.md): canister signatures against the real devnet.
#
# One local replica runs both crown-index (reading the real devnet) and the
# game canister (the replica's threshold key). Timers are compressed: the
# chunk period is 45 s (production values are client policy, the canister
# does not care); the refund escrow is born with t0 in the past so that
# RELEASE_MARGIN (900 s, a deploy constant of the shape) is already spent —
# zero waiting. Acts:
#   1. escrow S (3 chunks × 45 s): chunk 0 releases right away on the
#      canister's signature → the game's fee to its wallet, the rest to the
#      owner through the splitter; chunk 1 before its due time — the
#      canister refuses (a negative);
#   2. once chunks 1 and 2 mature: the signature for chunk 2 is valid, but
#      release(2) reverts in the shape — the order is held on-chain (a
#      negative); a foreign subscription's signature does not open S (a
#      negative); release(1) passes;
#   3. cancel by the donor: the §8 authorization → request_cancel → cancel —
#      the remainder (chunk 2) returns to the donor, the escrow is terminal;
#   4. escrow R outside the game (t0 = now − 2000): refund() right away —
#      no Settled;
#   5. the book: the donor gains +2 chunks at the owner; unchanged after
#      cancel/refund; zero anomalies.
#
# The full run is ~5–10 minutes (chunk maturation + book ingest).
#
# Usage: scripts/e2e-devnet.sh
set -euo pipefail
cd "$(dirname "$0")/.."

SOL_RPC_URL=${SOL_RPC_URL:-https://api.devnet.solana.com}
SOL_DONOR_KEYPAIR=${SOL_DONOR_KEYPAIR:-$HOME/.cache/crown-e2e/donor.json}
# The permanent channel owner (the same streamer as the other games' e2e):
# payouts stay recoverable between runs.
SOL_OWNER_KEYPAIR=${SOL_OWNER_KEYPAIR:-$HOME/.cache/crown-e2e/streamer.json}
CORE=$(cd ../../Crown-Core && pwd)

# Short test timers: the chunk period and amounts are sized to the devnet
# wallet.
PERIOD=45
N_CHUNKS=3
CHUNK=40000
R_CHUNK=1000
FEE_BPS=$(grep "^fee_bps" config/testnet.toml | cut -d"=" -f2 | tr -d " ")
FEE_WALLET=$(grep "^fee_wallet" config/testnet.toml | cut -d'"' -f2)
CHUNK_PAYOUT=$((CHUNK - CHUNK * FEE_BPS / 10000))
NONCE=$(date +%s)

# ---- tooling ------------------------------------------------------------

participant() { cargo run -q -p subscription --example participant -- "$@"; }
driver() { (cd e2e/solana-driver && cargo run -q -- "$@"); }

# Build both binaries before any act stamps a time. Act 1 records t0 and only
# then creates the escrow through the driver; on a cold target dir that first
# `cargo run` compiles for minutes, chunk 1 matures meanwhile, and the negative
# below observes a correctly signed release instead of a refusal — the test
# fails while the canister is right. Compile first, then start the clock.
echo "== warm the binaries (a cold build must not run inside a timed act)"
cargo build -q -p subscription --example participant
(cd e2e/solana-driver && cargo build -q)

blob_hex() { # hex -> candid-блоб \xx
    python3 -c "import sys; h=sys.argv[1]; print(''.join(f'\\\\{h[i:i+2]}' for i in range(0,len(h),2)))" "$1"
}
b58_hex() { # base58 -> hex
    python3 - "$1" <<'EOF'
import sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
s = sys.argv[1]; n = 0
for c in s: n = n * 58 + A.index(c)
b = n.to_bytes(32, "big")
print(b.hex())
EOF
}
result_field() { # field со stdin (json ответа Result-варианта) -> hex/число
    python3 -c "
import json, sys
field = sys.argv[1]
v = json.load(sys.stdin)
while isinstance(v, list) and len(v) == 1: v = v[0]
ok = v.get('Ok') if isinstance(v, dict) else None
if ok is None: print(); sys.exit()
value = ok if field == '.' else ok.get(field)
if isinstance(value, list) and value and all(isinstance(b, int) for b in value):
    print(''.join(f'{b:02x}' for b in value))
elif isinstance(value, str):
    print(value.removeprefix('0x'))
else:
    print(value if value is not None else '')
" "$1"
}

game_call() { dfx canister call subscription "$@"; }
reputation() { # payer_blob owner_blob
    dfx canister call crown-index get_reputation "(\"solana-devnet\", blob \"$1\", blob \"$2\")" \
        --query | tr -d '(_ )' | sed 's/:nat//'
}
resolver_of() { # subscription_id_hex -> resolver hex
    game_call get_resolver "(\"solana-devnet\", blob \"$(blob_hex "$1")\")" --output json \
        | result_field .
}
release_json() { # subscription_id_hex index
    game_call request_release "(record {
        chain = \"solana-devnet\";
        subscription_id = blob \"$(blob_hex "$1")\";
        donor = blob \"$(blob_hex "$DONOR_HEX")\";
        recipients = vec { blob \"$(blob_hex "$OWNER_HEX")\" };
        shares = vec { 10000 : nat16 };
        chunk = $CHUNK : nat64;
        n_chunks = $N_CHUNKS : nat16;
        t0 = $T0 : int64;
        period = $PERIOD : int64;
        nonce = $NONCE : nat64;
        index = $2 : nat16 })" --output json
}
cancel_json() { # subscription_id_hex signature_hex
    game_call request_cancel "(record {
        chain = \"solana-devnet\";
        subscription_id = blob \"$(blob_hex "$1")\";
        donor = blob \"$(blob_hex "$DONOR_HEX")\";
        recipients = vec { blob \"$(blob_hex "$OWNER_HEX")\" };
        shares = vec { 10000 : nat16 };
        chunk = $CHUNK : nat64;
        n_chunks = $N_CHUNKS : nat16;
        t0 = $T0 : int64;
        period = $PERIOD : int64;
        nonce = $NONCE : nat64;
        signature = blob \"$(blob_hex "$2")\" })" --output json
}

# ---- config -------------------------------------------------------------

core_value() { grep "^$1" "$CORE/config/testnet.toml" | head -1 | cut -d'=' -f2- | tr -d ' "' ; }
SPLITTER=$(core_value splitter)
USDC=$(core_value usdc)

DONOR=$(solana-keygen pubkey "$SOL_DONOR_KEYPAIR")
[ -f "$SOL_OWNER_KEYPAIR" ] || solana-keygen new --no-bip39-passphrase --silent -o "$SOL_OWNER_KEYPAIR"
OWNER=$(solana-keygen pubkey "$SOL_OWNER_KEYPAIR")
DONOR_HEX=$(b58_hex "$DONOR")
OWNER_HEX=$(b58_hex "$OWNER")
echo "donor=$DONOR owner=$OWNER"

# ---- replica and canisters ------------------------------------------------

echo "== build crown-index (local profile) and start the replica"
SOL_SEED=$(curl -s "$SOL_RPC_URL" -X POST -H "Content-Type: application/json" -d "{
    \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",
    \"params\":[\"$SPLITTER\", {\"limit\": 1}]}" \
    | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print(r[0]['signature'] if r else '')")
# Empty when the splitter has no signatures the RPC still serves (fresh or
# pruned devnet): start ingest with no cursor and read the run's own donates.
if [ -n "$SOL_SEED" ]; then
    SEED_FIELD="cursor_seed = opt vec { record { \"solana-devnet\"; \"$SOL_SEED\" } };"
else
    SEED_FIELD=""
fi
echo "cursor seed: ${SOL_SEED:-<none, ingest from scratch>}"

cat > "$CORE/config/local.toml" <<EOF
# Generated by subscription/scripts/e2e-devnet.sh; never committed.
[[chain]]
id        = "solana-devnet"
source    = "Custom:$SOL_RPC_URL"
consensus = "equality"
splitter  = "$SPLITTER"
usdc      = "$USDC"
$(grep '^factories' "$CORE/config/testnet.toml")
EOF
(cd "$CORE" && CROWN_PROFILE=local \
    CC_wasm32_unknown_unknown="$CORE/scripts/wasm-cc.sh" \
    AR_wasm32_unknown_unknown="${AR_WASM32:-$(command -v llvm-ar || ls -d "$HOME"/.cache/solana/*/platform-tools/llvm/bin/llvm-ar 2>/dev/null | sort -V | tail -1 | grep . || echo "$HOME/.cache/zig/zig-ar")}" \
    cargo build --target wasm32-unknown-unknown --release -p crown-index)

# THE LOCAL REPLICA IS SHARED AND IS NEVER WIPED HERE: threshold keys born by
# earlier runs may still resolve live devnet escrows. Reuse a running replica
# or start one over the existing state, and leave it up.
if ! dfx ping >/dev/null 2>&1; then
    echo "== starting the local replica over the EXISTING state (no --clean)"
    dfx start --background >/dev/null 2>&1
    for _ in $(seq 1 30); do dfx ping >/dev/null 2>&1 && break; sleep 1; done
fi
dfx ping >/dev/null 2>&1 || { echo "FAIL: replica did not come up" >&2; exit 1; }

dfx deploy sol_rpc
dfx deploy crown-index --argument "(opt record {
    sol_rpc = opt principal \"$(dfx canister id sol_rpc)\";
    $SEED_FIELD })"
dfx ledger fabricate-cycles --canister crown-index --t 100 >/dev/null
dfx deploy subscription
dfx ledger fabricate-cycles --canister subscription --t 100 >/dev/null
GAME_ID=$(dfx canister id subscription)

# ---- acts -----------------------------------------------------------------

SUB_A=$(python3 -c "import hashlib; print(hashlib.sha256(b'crown:e2e:sub-a:$NONCE').hexdigest())")
SUB_B=$(python3 -c "import hashlib; print(hashlib.sha256(b'crown:e2e:sub-b:$NONCE').hexdigest())")
RES_A=$(resolver_of "$SUB_A")
RES_B=$(resolver_of "$SUB_B")
echo "subscription A resolver=$RES_A"
echo "subscription B resolver=$RES_B"
[ -n "$RES_A" ] && [ "$RES_A" != "$RES_B" ] || { echo "FAIL: resolvers"; exit 1; }

echo "== act 1: the subscription escrow, chunk 0 due at once"
T0=$(date +%s)
ESCROW=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$OWNER" "$CHUNK" "$N_CHUNKS" "$T0" "$PERIOD" "$RES_A" "$FEE_BPS" "$FEE_WALLET" "$NONCE")
ESCROW_HEX=$(b58_hex "$ESCROW")
echo "escrow=$ESCROW"

echo "== negative: chunk 1 before its due time — the canister refuses"
OUT=$(release_json "$SUB_A" 1)
echo "$OUT" | grep -q "not due" || { echo "FAIL: early chunk signed: $OUT"; exit 1; }

echo "== release chunk 0: canister signature through the real splitter"
JSON=$(release_json "$SUB_A" 0)
SIG0=$(echo "$JSON" | result_field signature)
ESCROW_FROM_CANISTER=$(echo "$JSON" | result_field escrow)
[ -n "$SIG0" ] || { echo "FAIL: no signature for chunk 0: $JSON"; exit 1; }
[ "$ESCROW_FROM_CANISTER" = "$ESCROW_HEX" ] || { echo "FAIL: derived escrow mismatch"; exit 1; }
OWNER_BEFORE=$(driver balance "$SOL_RPC_URL" "$OWNER")
driver release "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$ESCROW" 0 "$SIG0" "$RES_A"
OWNER_AFTER=$(driver balance "$SOL_RPC_URL" "$OWNER")
[ "$OWNER_AFTER" = "$((OWNER_BEFORE + CHUNK_PAYOUT))" ] || { echo "FAIL: owner payout"; exit 1; }

echo "== wait until chunks 1 and 2 mature"
NOW=$(date +%s); DUE2=$((T0 + 2 * PERIOD + 5))
[ "$NOW" -lt "$DUE2" ] && sleep $((DUE2 - NOW))

echo "== negative: a due but out-of-turn chunk — the form reverts, not the canister"
SIG2=$(release_json "$SUB_A" 2 | result_field signature)
[ -n "$SIG2" ] || { echo "FAIL: no signature for due chunk 2"; exit 1; }
if driver release "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$ESCROW" 2 "$SIG2" "$RES_A" >/dev/null 2>&1; then
    echo "FAIL: out-of-order release passed"; exit 1
fi

echo "== negative: a foreign subscription's signature does not open this escrow"
SIG_B=$(release_json "$SUB_B" 1 | result_field signature)
[ -n "$SIG_B" ] || { echo "FAIL: no signature from subscription B"; exit 1; }
if driver release "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$ESCROW" 1 "$SIG_B" "$RES_B" >/dev/null 2>&1; then
    echo "FAIL: a foreign subscription's signature released"; exit 1
fi

echo "== release chunk 1"
SIG1=$(release_json "$SUB_A" 1 | result_field signature)
driver release "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$ESCROW" 1 "$SIG1" "$RES_A"
read -r RELEASED SETTLED <<<"$(driver state "$SOL_RPC_URL" "$ESCROW")"
[ "$RELEASED" = "2" ] && [ "$SETTLED" = "false" ] || { echo "FAIL: state $RELEASED $SETTLED"; exit 1; }

echo "== act 3: the donor cancels — the remainder returns at once"
# The authorization is UTF-8 text with newlines (auth.rs): by file, not by arg.
AUTH_FILE=$(mktemp)
participant cancel-authorization solana-devnet "$GAME_ID" "$ESCROW_HEX" > "$AUTH_FILE"
AUTH_SIG=$(participant sol-sign "$SOL_DONOR_KEYPAIR" "$AUTH_FILE")
rm -f "$AUTH_FILE"
CANCEL_SIG=$(cancel_json "$SUB_A" "$AUTH_SIG" | result_field signature)
[ -n "$CANCEL_SIG" ] || { echo "FAIL: no cancel signature"; exit 1; }
DONOR_BEFORE=$(driver balance "$SOL_RPC_URL" "$DONOR")
driver cancel "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$ESCROW" "$CANCEL_SIG" "$RES_A"
DONOR_AFTER=$(driver balance "$SOL_RPC_URL" "$DONOR")
[ "$DONOR_AFTER" = "$((DONOR_BEFORE + CHUNK))" ] || { echo "FAIL: cancel remainder"; exit 1; }
read -r RELEASED SETTLED <<<"$(driver state "$SOL_RPC_URL" "$ESCROW")"
[ "$SETTLED" = "true" ] || { echo "FAIL: not terminal after cancel"; exit 1; }

echo "== act 4: an overdue stream outside the game — refund(), no Settled"
R_T0=$(( $(date +%s) - 2000 ))
R_ESCROW=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$OWNER" "$R_CHUNK" 1 "$R_T0" "$PERIOD" "$RES_A" "$FEE_BPS" "$FEE_WALLET" $((NONCE + 1)))
echo "refund escrow=$R_ESCROW"
DONOR_BEFORE=$(driver balance "$SOL_RPC_URL" "$DONOR")
driver refund "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$R_ESCROW"
DONOR_AFTER=$(driver balance "$SOL_RPC_URL" "$DONOR")
[ "$DONOR_AFTER" = "$((DONOR_BEFORE + R_CHUNK))" ] || { echo "FAIL: refund"; exit 1; }

echo "== the book credits the donor for the released chunks, and only them"
EXPECTED=$((2 * CHUNK_PAYOUT))
REP=""
for _ in $(seq 1 90); do
    REP=$(reputation "$(blob_hex "$DONOR_HEX")" "$(blob_hex "$OWNER_HEX")")
    echo "book: donor $REP/$EXPECTED"
    [ "$REP" = "$EXPECTED" ] && break
    sleep 10
done
[ "$REP" = "$EXPECTED" ] || { echo "FAIL: attribution"; exit 1; }

echo "== cancel and refund left the book unchanged; zero anomalies"
sleep 30
REP=$(reputation "$(blob_hex "$DONOR_HEX")" "$(blob_hex "$OWNER_HEX")")
[ "$REP" = "$EXPECTED" ] || { echo "FAIL: the book moved after cancel/refund: $REP"; exit 1; }
ANOMALIES=$(dfx canister call crown-index get_anomaly_count --query | tr -d '(_ )' | sed 's/:nat64//')
[ "$ANOMALIES" = "0" ] || { echo "FAIL: anomaly count = $ANOMALIES"; exit 1; }

echo "e2e devnet OK"
