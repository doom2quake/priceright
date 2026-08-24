// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ArenaFixture} from "./ArenaFixture.sol";
import {AgentArena} from "../src/AgentArena.sol";
import {IdentityRegistry} from "../src/erc8004/IdentityRegistry.sol";
import {ReputationRegistry} from "../src/erc8004/ReputationRegistry.sol";
import {ValidationRegistry} from "../src/erc8004/ValidationRegistry.sol";

/// @dev ERC-8004 conformance, at the level a reviewer would check it: is the identity
///      registry actually an ERC-721, is feedback actually permissionless and filterable,
///      and does a transferred identity really carry its history.
contract Erc8004Test is ArenaFixture {
    function setUp() public {
        _deploy();
    }

    // ---- identity: a real ERC-721 ----

    function test_identity_reports_erc721_interfaces() public view {
        _assert(identity.supportsInterface(0x01ffc9a7), "ERC-165");
        _assert(identity.supportsInterface(0x80ac58cd), "ERC-721");
        _assert(identity.supportsInterface(0x5b5e139f), "ERC-721Metadata");
        _assert(!identity.supportsInterface(0xffffffff), "invalid id is false");
    }

    function test_register_mints_a_token_to_the_controller() public {
        _assert(identity.ownerOf(agentId) == RESOLVER, "owned by the resolver");
        _assert(identity.balanceOf(RESOLVER) == 1, "balance tracked");
        _assert(
            keccak256(bytes(identity.tokenURI(agentId))) == keccak256(bytes("ipfs://resolver-card")), "agent card URI"
        );
    }

    function test_identity_is_transferable_and_carries_its_reputation() public {
        // earn a wrong verdict first, so there is history to carry
        uint256 taskId = _post(AgentArena.Verdict.No);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        arena.settle(taskId, AgentArena.Verdict.No, SALT);

        vm.prank(RESOLVER);
        identity.transferFrom(RESOLVER, STRANGER, agentId);
        _assert(identity.ownerOf(agentId) == STRANGER, "identity moved");

        // reputation is keyed by agentId, so the record follows the identity
        (uint64 count, uint8 avg) = reputation.getSummary(agentId, new address[](0), arena.TAG_SETTLEMENT());
        _assert(count == 1 && avg == 0, "the zero score travelled with the token");
        _assert(vault.slashedOf(agentId) == SLASH, "so did the slash record");
    }

    function test_approved_operator_can_transfer() public {
        vm.prank(RESOLVER);
        identity.approve(STRANGER, agentId);
        _assert(identity.getApproved(agentId) == STRANGER, "approval recorded");
        vm.prank(STRANGER);
        identity.transferFrom(RESOLVER, STRANGER, agentId);
        _assert(identity.ownerOf(agentId) == STRANGER, "transferred by the approved operator");
    }

    function test_transfer_rejects_a_stranger() public {
        vm.prank(STRANGER);
        vm.expectPartialRevert(IdentityRegistry.NotAuthorized.selector);
        identity.transferFrom(RESOLVER, STRANGER, agentId);
    }

    function test_unknown_agent_reverts() public {
        vm.expectPartialRevert(IdentityRegistry.UnknownAgent.selector);
        identity.ownerOf(4242);
    }

    // ---- reputation: permissionless, filterable ----

    function test_feedback_is_permissionless_and_filtered_by_client() public {
        // the arena's own score for the agent
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        arena.settle(taskId, AgentArena.Verdict.Yes, SALT);

        // anyone may also leave feedback; a reader who does not trust them filters it out
        bytes32 tag = arena.TAG_SETTLEMENT();
        vm.prank(STRANGER);
        reputation.giveFeedback(agentId, 0, tag, bytes32("spite"), "", bytes32(0));

        (uint64 allCount, uint8 allAvg) = reputation.getSummary(agentId, new address[](0), bytes32(0));
        _assert(allCount == 2 && allAvg == 50, "unfiltered view includes the stranger");

        address[] memory trusted = new address[](1);
        trusted[0] = address(arena);
        (uint64 count, uint8 avg) = reputation.getSummary(agentId, trusted, bytes32(0));
        _assert(count == 1 && avg == 100, "filtering to the arena restores the real score");
    }

    function test_feedback_can_be_revoked_only_by_its_author() public {
        bytes32 tag = arena.TAG_SETTLEMENT();
        vm.prank(STRANGER);
        reputation.giveFeedback(agentId, 0, tag, bytes32("spite"), "", bytes32(0));
        vm.prank(POSTER);
        vm.expectPartialRevert(ReputationRegistry.NoSuchFeedback.selector);
        reputation.revokeFeedback(agentId, 0);

        vm.prank(STRANGER);
        reputation.revokeFeedback(agentId, 0);
        (uint64 count,) = reputation.getSummary(agentId, new address[](0), bytes32(0));
        _assert(count == 0, "revoked feedback is excluded");
    }

    function test_feedback_rejects_out_of_range_scores() public {
        vm.prank(STRANGER);
        vm.expectPartialRevert(ReputationRegistry.ScoreOutOfRange.selector);
        reputation.giveFeedback(agentId, 101, bytes32(0), bytes32(0), "", bytes32(0));
    }

    // ---- validation ----

    function test_validation_request_precedes_the_reveal_and_only_the_validator_answers() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        bytes32 requestHash = arena.validationHashOf(taskId);

        (address validator,, bool answered,,, uint64 requestedAt) = validation.getValidationStatus(requestHash);
        _assert(validator == address(arena) && !answered && requestedAt == block.timestamp, "filed, unanswered");

        vm.prank(STRANGER);
        vm.expectPartialRevert(ValidationRegistry.NotValidator.selector);
        validation.validationResponse(requestHash, 100, "", bytes32(0));

        vm.prank(POSTER);
        arena.settle(taskId, AgentArena.Verdict.Yes, SALT);
        (,, bool nowAnswered, uint8 response,,) = validation.getValidationStatus(requestHash);
        _assert(nowAnswered && response == 100, "answered at settlement");
    }

    function test_validation_response_cannot_be_overwritten() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        arena.settle(taskId, AgentArena.Verdict.Yes, SALT);
        bytes32 requestHash = arena.validationHashOf(taskId);
        vm.prank(address(arena));
        vm.expectPartialRevert(ValidationRegistry.AlreadyAnswered.selector);
        validation.validationResponse(requestHash, 0, "", bytes32(0));
    }
}
