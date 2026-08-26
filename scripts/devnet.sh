#!/usr/bin/env bash
# Deploy PriceRight to a local anvil devnet and run the whole story against it.
#
# Everything the CLI prints during this run is a real transaction: the x402 payment is
# an EIP-3009 authorisation signed by the resolver and submitted by the arena, the
# collateral moves into a vault contract, and the slash is a Slashed event you can read
# back with `cast logs`. Nothing is mirrored in-process.
#
#   ./scripts/devnet.sh              # starts its own anvil, deploys, runs, stops
#   ./scripts/devnet.sh --keep       # leaves anvil running and prints the env to reuse
#
# Requires foundry (anvil, forge, cast) and python3. Local devnet only.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

RPC="${PRICERIGHT_RPC_URL:-http://127.0.0.1:8545}"
PY="${PRICERIGHT_PYTHON:-python3}"
KEEP=0
RECORD=0
for arg in "$@"; do
  [[ "$arg" == "--keep" ]] && KEEP=1
  [[ "$arg" == "--record" ]] && RECORD=1
done

# anvil accounts 0/1/2: resolver, poster, second resolver. Devnet keys, no value.
RESOLVER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
POSTER_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
RESOLVER2_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RESOLVER=$(cast wallet address --private-key $RESOLVER_KEY)
POSTER=$(cast wallet address --private-key $POSTER_KEY)
RESOLVER2=$(cast wallet address --private-key $RESOLVER2_KEY)

ANVIL_PID=""
cleanup() {
  if [[ -n "$ANVIL_PID" && $KEEP -eq 0 ]]; then kill "$ANVIL_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

if ! cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "starting anvil on $RPC"
  anvil --silent >/dev/null 2>&1 &
  ANVIL_PID=$!
  for _ in $(seq 1 40); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.25; done
fi

deploy() { # contract path:name, then constructor args
  local target="$1"; shift
  local out
  if [[ $# -gt 0 ]]; then
    out=$(forge create --rpc-url "$RPC" --private-key "$POSTER_KEY" --broadcast "$target" --constructor-args "$@" 2>&1)
  else
    out=$(forge create --rpc-url "$RPC" --private-key "$POSTER_KEY" --broadcast "$target" 2>&1)
  fi
  local addr
  addr=$(awk '/Deployed to:/ {print $3}' <<< "$out")
  if [[ -z "$addr" ]]; then echo "deploy failed for $target:" >&2; echo "$out" >&2; exit 1; fi
  echo "$addr"
}

echo "deploying contracts"
TOKEN=$(deploy src/mocks/MockERC20.sol:MockERC20 "Test USD" "tUSD" 6)
IDENTITY=$(deploy src/erc8004/IdentityRegistry.sol:IdentityRegistry)
REPUTATION=$(deploy src/erc8004/ReputationRegistry.sol:ReputationRegistry "$IDENTITY")
VALIDATION=$(deploy src/erc8004/ValidationRegistry.sol:ValidationRegistry "$IDENTITY")
VAULT=$(deploy src/AgentStakeVault.sol:AgentStakeVault "$TOKEN" "$IDENTITY")
ARENA=$(deploy src/AgentArena.sol:AgentArena "$TOKEN" "$IDENTITY" "$REPUTATION" "$VALIDATION" "$VAULT" 3600 7200)

send() { cast send --rpc-url "$RPC" --private-key "$1" "${@:2}" >/dev/null; }

echo "wiring: vault operator, balances, allowances"
send "$POSTER_KEY" "$VAULT" "setOperator(address,bool)" "$ARENA" true
for who in "$POSTER" "$RESOLVER" "$RESOLVER2"; do
  send "$POSTER_KEY" "$TOKEN" "mint(address,uint256)" "$who" 10000
done
# the bounty and the collateral use allowances; the x402 fee deliberately does not.
send "$POSTER_KEY" "$TOKEN" "approve(address,uint256)" "$ARENA" 1000000
send "$RESOLVER_KEY" "$TOKEN" "approve(address,uint256)" "$VAULT" 1000000
send "$RESOLVER2_KEY" "$TOKEN" "approve(address,uint256)" "$VAULT" 1000000

cat <<ENV > .devnet.env
export PRICERIGHT_RPC_URL=$RPC
export PRICERIGHT_NETWORK=anvil-31337
export PRICERIGHT_TOKEN_ADDRESS=$TOKEN
export PRICERIGHT_IDENTITY_ADDRESS=$IDENTITY
export PRICERIGHT_REPUTATION_ADDRESS=$REPUTATION
export PRICERIGHT_VALIDATION_ADDRESS=$VALIDATION
export PRICERIGHT_VAULT_ADDRESS=$VAULT
export PRICERIGHT_ARENA_ADDRESS=$ARENA
export PRICERIGHT_IN_MEMORY_STATE=1
ENV
echo "addresses written to .devnet.env"

# shellcheck disable=SC1091
source .devnet.env
echo
if [[ $RECORD -eq 1 ]]; then
  PYTHONPATH="$REPO" $PY -m priceright.record --out docs/run.json --inject ui/index.html
  echo "recorded this deployment into docs/run.json and ui/index.html"
  echo
fi
PYTHONPATH="$REPO" $PY -m priceright.main demo

echo
echo "verify it independently:"
echo "  cast logs --rpc-url $RPC --from-block 0 'Slashed(bytes32,uint256,address,uint256)'"
echo "  cast call --rpc-url $RPC $VAULT 'slashedOf(uint256)(uint256)' 2"
if [[ $KEEP -eq 1 ]]; then
  echo "anvil left running; 'source .devnet.env' to keep using it"
fi
