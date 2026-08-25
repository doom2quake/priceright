// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ArenaFixture} from "./ArenaFixture.sol";
import {AgentArena} from "../src/AgentArena.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev The x402 payment rail. These tests are the difference between "we call it x402"
///      and "the fee moves because of a signed x402 authorisation, once, for this task".
contract X402PaymentTest is ArenaFixture {
    function setUp() public {
        _deploy();
    }

    /// @dev The resolver holds no allowance for the arena. The fee still moves, because
    ///      the payment is settled by the EIP-3009 signature the x402 `exact` scheme
    ///      carries in the X-PAYMENT header. Remove the signature and the claim fails.
    function test_fee_moves_by_signature_not_by_allowance() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _assert(token.allowance(RESOLVER, address(arena)) == 0, "no allowance to the arena");
        uint256 before = token.balanceOf(address(arena));
        _claim(taskId);
        _assert(token.balanceOf(address(arena)) == before + FEE, "fee settled by authorisation");
        _assert(token.authorizationState(RESOLVER, arena.claimNonce(taskId, agentId)), "nonce consumed");
    }

    /// @dev The exact defect: a payment authorisation must not be reusable, and the fee
    ///      must be charged once. The token's nonce map makes a replay revert.
    function test_payment_authorisation_cannot_be_replayed() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        AgentArena.X402Payment memory p = _payment(RESOLVER_PK, taskId, agentId, FEE);
        vm.prank(RESOLVER);
        arena.claimTask(taskId, agentId, p);

        vm.prank(RESOLVER);
        vm.expectPartialRevert(MockERC20.AuthorizationAlreadyUsed.selector);
        token.transferWithAuthorization(
            p.from, address(arena), p.value, p.validAfter, p.validBefore, p.nonce, p.v, p.r, p.s
        );
    }

    /// @dev An authorisation signed for task 1 is worthless on task 2: the nonce commits
    ///      to the task id, the agent id, the arena address and the chain id.
    function test_payment_is_bound_to_its_task() public {
        uint256 taskA = _post(AgentArena.Verdict.Yes);
        uint256 taskB = _post(AgentArena.Verdict.Yes);
        AgentArena.X402Payment memory p = _payment(RESOLVER_PK, taskA, agentId, FEE);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.NonceNotBoundToTask.selector);
        arena.claimTask(taskB, agentId, p);
    }

    function test_payment_amount_must_equal_the_posted_fee() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        AgentArena.X402Payment memory p = _payment(RESOLVER_PK, taskId, agentId, FEE - 1);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.FeeAmountMismatch.selector);
        arena.claimTask(taskId, agentId, p);
    }

    function test_payer_must_be_the_claiming_resolver() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        AgentArena.X402Payment memory p = _payment(POSTER_PK, taskId, agentId, FEE);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.PayerMismatch.selector);
        arena.claimTask(taskId, agentId, p);
    }

    /// @dev A tampered value invalidates the signature: `ecrecover` no longer returns
    ///      the payer, so the token refuses the transfer.
    function test_tampered_authorisation_is_rejected_by_the_token() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        AgentArena.X402Payment memory p = _payment(RESOLVER_PK, taskId, agentId, FEE);
        vm.expectPartialRevert(MockERC20.InvalidSignature.selector);
        token.transferWithAuthorization(
            p.from, address(arena), p.value + 1, p.validAfter, p.validBefore, p.nonce, p.v, p.r, p.s
        );
    }

    function test_expired_authorisation_is_rejected() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        AgentArena.X402Payment memory p = _payment(RESOLVER_PK, taskId, agentId, FEE);
        vm.warp(p.validBefore + 1);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(MockERC20.AuthorizationExpired.selector);
        arena.claimTask(taskId, agentId, p);
    }

    /// @dev Cross-language parity. `priceright/x402.py` signs authorisations with the
    ///      pure-Python secp256k1 in `priceright/secp256k1.py`; the constants below were
    ///      produced by it. Solidity re-derives the EIP-712 domain separator, the struct
    ///      hash and the digest from the same fields, checks the digest matches, and then
    ///      lets `ecrecover` judge the signature. Wrong curve math, wrong EIP-712 encoding
    ///      or a drifted nonce derivation all fail here.
    ///
    ///      `tests/test_x402.py::test_solidity_vector_matches_python_signer` reads these
    ///      constants back out of this file and regenerates them, so neither side can be
    ///      edited to fit the other.
    function test_python_signed_authorisation_verifies_in_solidity() public view {
        address vFrom = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        address vTo = 0x5FC8d32690cc91D4c39d9d3abcBD16989F875707;
        uint256 vValue = 10;
        uint256 vValidAfter = 0;
        uint256 vValidBefore = 1893456000;
        bytes32 vNonce = 0x32fea67083198ec3667911aa7f9a51b425be171bc5c5be56a69df90ef01fa2b8;
        bytes32 vDigest = 0x78145914505d8ecb3dc5de4eda5ae32ac03f46ff74350451203d9d3004fe8d6f;
        uint8 vV = 27;
        bytes32 vR = 0x564afa0286e0f5323144c85b1f9601b8364c027eb24122e98b09cf9698f1519f;
        bytes32 vS = 0x180f69a4c254eb3005e00e0080214dd2c74e3767e31e006f16359fb6e997ae8d;

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Test USD")),
                keccak256(bytes("2")),
                uint256(31337),
                address(0x5FbDB2315678afecb367f032d93F642f64180aa3)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), vFrom, vTo, vValue, vValidAfter, vValidBefore, vNonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        _assert(digest == vDigest, "EIP-712 digest parity with the Python client");
        _assert(ecrecover(digest, vV, vR, vS) == vFrom, "python signature recovers to the payer");
    }

    /// @dev The nonce derivation is the binding, so it has to agree across languages too.
    ///      This is the value `InMemoryChain.claim_nonce(1, 1)` produces for the arena
    ///      address the mirror uses; the same expression in Solidity must reproduce it.
    function test_claim_nonce_derivation_matches_python() public view {
        bytes32 expected = 0x32fea67083198ec3667911aa7f9a51b425be171bc5c5be56a69df90ef01fa2b8;
        bytes32 derived = keccak256(
            abi.encode(
                keccak256("x402.priceright.claim.v1"),
                address(0x5FC8d32690cc91D4c39d9d3abcBD16989F875707),
                uint256(31337),
                uint256(1),
                uint256(1)
            )
        );
        _assert(derived == expected, "claimNonce parity with the Python mirror");
    }
}
