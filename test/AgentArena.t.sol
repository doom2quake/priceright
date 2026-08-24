// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ArenaFixture} from "./ArenaFixture.sol";
import {AgentArena} from "../src/AgentArena.sol";
import {AgentStakeVault} from "../src/AgentStakeVault.sol";

/// @dev Lifecycle, settlement, liveness and value-conservation tests for the arena.
contract AgentArenaTest is ArenaFixture {
    function setUp() public {
        _deploy();
    }

    // ---- lifecycle ----

    function test_post_pulls_bounty_into_escrow() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _assert(token.balanceOf(address(arena)) == BOUNTY, "bounty escrowed");
        (, uint256 bounty, uint256 fee, uint256 slashAmount, AgentArena.Status status,,,,,,) = arena.getTask(taskId);
        _assert(bounty == BOUNTY && fee == FEE && slashAmount == SLASH, "task funded");
        _assert(status == AgentArena.Status.Open, "open");
    }

    function test_claim_settles_x402_fee_and_bonds_collateral() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        uint256 before = token.balanceOf(RESOLVER);
        _claim(taskId);
        _assert(token.balanceOf(RESOLVER) == before - FEE - SLASH, "fee+collateral pulled");
        _assert(token.balanceOf(address(arena)) == BOUNTY + FEE, "arena holds bounty+fee");
        // collateral is custodied by the vault, not by the arena
        _assert(token.balanceOf(address(vault)) == SLASH, "vault custodies collateral");
        _assert(vault.stakeOf(agentId) == SLASH, "stake tracked against the 8004 identity");
        (,,,, AgentArena.Status status, uint256 aid, address resolver,,,,) = arena.getTask(taskId);
        _assert(status == AgentArena.Status.Claimed && aid == agentId && resolver == RESOLVER, "claimed");
    }

    function test_commit_records_verdict_and_files_validation_request() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        (,,,, AgentArena.Status status,,, AgentArena.Verdict committed, bytes32 rh,,) = arena.getTask(taskId);
        _assert(status == AgentArena.Status.Committed, "committed");
        _assert(committed == AgentArena.Verdict.Yes && rh == REASONING, "verdict + hash stored");
        // the ERC-8004 validation request exists before the truth is revealed
        (address validator, uint256 aid, bool answered,,,) = validation.getValidationStatus(arena.validationHashOf(taskId));
        _assert(validator == address(arena) && aid == agentId && !answered, "validation request filed pre-reveal");
    }

    // ---- the hero: right vs wrong settlement ----

    function test_settle_correct_pays_resolver_and_returns_collateral() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);

        uint256 before = token.balanceOf(RESOLVER);
        vm.prank(POSTER);
        arena.settle(taskId, AgentArena.Verdict.Yes, SALT);

        // fee back + bounty + the collateral it bonded: nothing is stranded on a win.
        _assert(arena.credits(RESOLVER) == FEE + BOUNTY + SLASH, "credited fee+bounty+collateral");
        _withdraw(RESOLVER);
        _assert(token.balanceOf(RESOLVER) == before + FEE + BOUNTY + SLASH, "paid out");
        _assert(vault.stakeOf(agentId) == 0, "bond closed");
        (uint64 count, uint8 avg) = reputation.getSummary(agentId, new address[](0), arena.TAG_SETTLEMENT());
        _assert(count == 1 && avg == 100, "ERC-8004 feedback: perfect score");
        (,,, uint8 response,,) = validation.getValidationStatus(arena.validationHashOf(taskId));
        _assert(response == 100, "validation answered 100");
    }

    function test_settle_wrong_slashes_collateral_to_poster() public {
        uint256 taskId = _post(AgentArena.Verdict.No);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes); // WRONG

        uint256 posterBefore = token.balanceOf(POSTER);
        uint256 resolverBefore = token.balanceOf(RESOLVER);
        vm.prank(POSTER);
        arena.settle(taskId, AgentArena.Verdict.No, SALT);

        _assert(vault.stakeOf(agentId) == 0, "collateral seized");
        _assert(vault.slashedOf(agentId) == SLASH, "slash recorded against the identity");
        _assert(arena.credits(RESOLVER) == 0, "resolver gets nothing");
        _assert(arena.credits(POSTER) == FEE + BOUNTY + SLASH, "poster credited fee+bounty+slashed stake");
        _withdraw(POSTER);
        _assert(token.balanceOf(POSTER) == posterBefore + FEE + BOUNTY + SLASH, "slashed value actually moved");
        _assert(token.balanceOf(RESOLVER) == resolverBefore, "resolver recovered nothing");

        (uint64 count, uint8 avg) = reputation.getSummary(agentId, new address[](0), arena.TAG_SETTLEMENT());
        _assert(count == 1 && avg == 0, "ERC-8004 feedback: zero score");
        (,,, uint8 response,,) = validation.getValidationStatus(arena.validationHashOf(taskId));
        _assert(response == 0, "validation answered 0");
    }

    /// @dev The defect this pins: settlement used to keep the collateral inside the
    ///      contract forever. Both terminal paths must leave the system empty.
    function test_no_tokens_are_stranded_after_settlement() public {
        uint256 correctTask = _post(AgentArena.Verdict.Yes);
        _claim(correctTask);
        _commit(correctTask, AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        arena.settle(correctTask, AgentArena.Verdict.Yes, SALT);
        _withdraw(RESOLVER);
        _withdraw(POSTER);
        _assert(token.balanceOf(address(arena)) == 0, "arena drained after correct");
        _assert(token.balanceOf(address(vault)) == 0, "vault drained after correct");

        uint256 wrongTask = _post(AgentArena.Verdict.No);
        _claim(wrongTask);
        _commit(wrongTask, AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        arena.settle(wrongTask, AgentArena.Verdict.No, SALT);
        _withdraw(RESOLVER);
        _withdraw(POSTER);
        _assert(token.balanceOf(address(arena)) == 0, "arena drained after wrong");
        _assert(token.balanceOf(address(vault)) == 0, "vault drained after wrong");
        _assert(token.balanceOf(POSTER) + token.balanceOf(RESOLVER) == 2000, "no value created or destroyed");
    }

    // ---- liveness: neither side can freeze the escrow ----

    function test_timeout_commit_is_permissionless_and_frees_escrow() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId); // resolver claims, then goes quiet forever
        vm.warp(block.timestamp + COMMIT_WINDOW + 1);

        vm.prank(STRANGER); // anyone may unstick it
        arena.timeoutCommit(taskId);

        _assert(arena.credits(POSTER) == FEE + BOUNTY, "poster recovers bounty + keeps the fee");
        _assert(arena.credits(RESOLVER) == SLASH, "collateral returned: no wrong verdict was given");
        _withdraw(POSTER);
        _withdraw(RESOLVER);
        _assert(token.balanceOf(address(arena)) == 0 && token.balanceOf(address(vault)) == 0, "nothing stranded");
        (uint64 count, uint8 avg) = reputation.getSummary(agentId, new address[](0), arena.TAG_SETTLEMENT());
        _assert(count == 1 && avg == 0, "no-show recorded against the agent");
    }

    function test_timeout_settle_pays_the_resolver_when_the_poster_hides() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes); // poster never reveals
        vm.warp(block.timestamp + SETTLE_WINDOW + 1);

        vm.prank(STRANGER);
        arena.timeoutSettle(taskId);

        _assert(arena.credits(RESOLVER) == FEE + BOUNTY + SLASH, "resolver made whole and paid");
        _assert(arena.credits(POSTER) == 0, "poster forfeits by withholding");
        _withdraw(RESOLVER);
        _assert(token.balanceOf(address(arena)) == 0 && token.balanceOf(address(vault)) == 0, "nothing stranded");
    }

    function test_timeouts_reject_early_calls() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        vm.expectPartialRevert(AgentArena.DeadlineNotReached.selector);
        arena.timeoutCommit(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.expectPartialRevert(AgentArena.DeadlineNotReached.selector);
        arena.timeoutSettle(taskId);
    }

    function test_commit_after_deadline_reverts() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        vm.warp(block.timestamp + COMMIT_WINDOW + 1);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.DeadlinePassed.selector);
        arena.commitVerdict(taskId, AgentArena.Verdict.Yes, REASONING);
    }

    function test_settle_after_deadline_reverts() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.warp(block.timestamp + SETTLE_WINDOW + 1);
        vm.prank(POSTER);
        vm.expectPartialRevert(AgentArena.DeadlinePassed.selector);
        arena.settle(taskId, AgentArena.Verdict.Yes, SALT);
    }

    function test_cancel_refunds_an_unclaimed_task() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        arena.cancelTask(taskId);
        _assert(arena.credits(POSTER) == BOUNTY, "bounty refunded");
        _withdraw(POSTER);
        _assert(token.balanceOf(POSTER) == 1000, "poster whole again");
    }

    function test_cancel_rejected_once_claimed() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        vm.prank(POSTER);
        vm.expectPartialRevert(AgentArena.NotOpen.selector);
        arena.cancelTask(taskId);
    }

    // ---- guards ----

    function test_settle_rejects_wrong_salt() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        vm.expectPartialRevert(AgentArena.TruthMismatch.selector);
        arena.settle(taskId, AgentArena.Verdict.Yes, keccak256("wrong-salt"));
    }

    function test_settle_rejects_truth_that_breaks_commitment() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.prank(POSTER);
        vm.expectPartialRevert(AgentArena.TruthMismatch.selector);
        arena.settle(taskId, AgentArena.Verdict.No, SALT);
    }

    function test_claim_requires_open() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        AgentArena.X402Payment memory p = _payment(RESOLVER_PK, taskId, agentId, FEE);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.NotOpen.selector);
        arena.claimTask(taskId, agentId, p);
    }

    function test_claim_requires_agent_controller() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        AgentArena.X402Payment memory p = _payment(POSTER_PK, taskId, agentId, FEE);
        vm.prank(POSTER); // POSTER does not control agentId
        vm.expectPartialRevert(AgentArena.NotResolver.selector);
        arena.claimTask(taskId, agentId, p);
    }

    function test_commit_requires_claim_first() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.NotClaimed.selector);
        arena.commitVerdict(taskId, AgentArena.Verdict.Yes, REASONING);
    }

    function test_commit_rejects_empty_reasoning() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.EmptyReasoning.selector);
        arena.commitVerdict(taskId, AgentArena.Verdict.Yes, bytes32(0));
    }

    function test_settle_only_poster() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        _commit(taskId, AgentArena.Verdict.Yes);
        vm.prank(RESOLVER);
        vm.expectPartialRevert(AgentArena.NotPoster.selector);
        arena.settle(taskId, AgentArena.Verdict.Yes, SALT);
    }

    function test_settle_requires_committed() public {
        uint256 taskId = _post(AgentArena.Verdict.Yes);
        _claim(taskId);
        vm.prank(POSTER);
        vm.expectPartialRevert(AgentArena.NotCommitted.selector);
        arena.settle(taskId, AgentArena.Verdict.Yes, SALT);
    }

    function test_post_rejects_zero_commit() public {
        vm.prank(POSTER);
        vm.expectPartialRevert(AgentArena.BadCommit.selector);
        arena.postTask(BOUNTY, FEE, SLASH, bytes32(0));
    }

    function test_unknown_task_reverts() public {
        vm.expectPartialRevert(AgentArena.UnknownTask.selector);
        arena.getTask(999);
    }

    function test_withdraw_rejects_empty_balance() public {
        vm.prank(STRANGER);
        vm.expectPartialRevert(AgentArena.NothingToWithdraw.selector);
        arena.withdraw();
    }

    function test_vault_rejects_unauthorized_operator() public {
        bytes32 key = arena.bondKey(1);
        vm.prank(STRANGER);
        vm.expectPartialRevert(AgentStakeVault.NotOperator.selector);
        vault.slash(key, STRANGER);
    }

    /// @dev The property `AgentStakeVault` documents, tested at the vault directly: a
    ///      bond has exactly two terminal states, both move real tokens out to a named
    ///      party, and neither can be applied twice. The defect this pins is a slash
    ///      that only decrements an accounting number while the collateral sits in the
    ///      contract forever, which is what the review found in the first version.
    function test_vault_conserves_tokens() public {
        vault.setOperator(address(this), true);
        token.mint(address(this), 100);
        token.approve(address(vault), type(uint256).max);

        bytes32 releasedKey = keccak256("bond:released");
        bytes32 slashedKey = keccak256("bond:slashed");
        vault.bondFor(releasedKey, agentId, address(this), 60);
        vault.bondFor(slashedKey, agentId, address(this), 40);
        _assert(token.balanceOf(address(vault)) == 100, "vault custodies both bonds");
        _assert(vault.stakeOf(agentId) == 100, "stake tracked against the identity");

        uint256 resolverBefore = token.balanceOf(RESOLVER);
        uint256 posterBefore = token.balanceOf(POSTER);
        uint256 released = vault.release(releasedKey, RESOLVER);
        uint256 slashed = vault.slash(slashedKey, POSTER);

        _assert(released == 60 && slashed == 40, "both terminal calls report the full bond");
        _assert(token.balanceOf(RESOLVER) == resolverBefore + 60, "released collateral was transferred");
        _assert(token.balanceOf(POSTER) == posterBefore + 40, "slashed collateral reached the beneficiary");
        _assert(token.balanceOf(address(vault)) == 0, "nothing is left stranded in the vault");
        _assert(vault.stakeOf(agentId) == 0, "bonded stake cleared");
        _assert(vault.slashedOf(agentId) == 40, "the slash is recorded against the identity");

        vm.expectPartialRevert(AgentStakeVault.BondClosed.selector);
        vault.release(releasedKey, RESOLVER);
        vm.expectPartialRevert(AgentStakeVault.BondClosed.selector);
        vault.slash(slashedKey, POSTER);
    }
}
