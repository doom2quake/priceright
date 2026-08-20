// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {
    IERC20,
    IERC3009,
    IIdentityRegistry,
    IReputationRegistry,
    IValidationRegistry,
    IAgentStakeVault
} from "./interfaces/IAgentRegistry.sol";

/// @title AgentArena - an x402-settled task market with deterministic ERC-8004 slashing.
/// @author Dipankar Sarkar
/// @notice A poster opens a TASK with a hash commitment to a ground truth it already
///         knows. A resolver agent CLAIMS the task by presenting a signed x402 payment
///         (an EIP-3009 `transferWithAuthorization`, the `exact` scheme's on-chain
///         settlement primitive) and bonding collateral against its ERC-8004 identity.
///         It then COMMITS a verdict plus the keccak-256 of its reasoning. SETTLEMENT
///         reveals the truth and is a pure function of (committed verdict, revealed
///         truth): correct pays the resolver, wrong moves its collateral to the poster.
///
///         Three things make that claim survive an audit rather than a demo:
///
///         1. The fee is charged exactly once, by a signature that is *bound to this
///            task*: the x402 nonce is `claimNonce(taskId, agentId)`, which commits to
///            the arena address and the chain id, so an authorisation signed for one
///            task cannot be replayed against another task, arena or chain.
///         2. No path strands value. Collateral lives in `AgentStakeVault` and every
///            terminal state releases it or slashes it to a named party; fee, bounty and
///            collateral all land in the `credits` ledger and are withdrawn by pull.
///         3. Neither side can freeze the escrow. A resolver that never commits, and a
///            poster that never reveals, both hit a deadline after which *anyone* can
///            call the timeout and the escrow resolves against the party that stalled.
///
///         Testnet only.
contract AgentArena {
    enum Verdict {
        None, // 0: not yet committed
        Yes,  // 1
        No    // 2
    }

    enum Status {
        Open,      // 0: posted, awaiting a resolver
        Claimed,   // 1: x402 fee settled, collateral bonded
        Committed, // 2: verdict + reasoning hash committed
        Settled,   // 3: settled (right or wrong)
        Cancelled  // 4: withdrawn by the poster before any claim
    }

    /// @dev An x402 `exact`-scheme payment payload, as signed by the payer and relayed
    ///      by a facilitator: EIP-3009 authorisation fields plus the signature.
    struct X402Payment {
        address from;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct Task {
        address poster;
        uint256 bounty;
        uint256 fee;
        uint256 slashAmount;
        bytes32 truthCommit;
        Status status;
        uint256 agentId;
        address resolver;
        Verdict committed;
        bytes32 reasoningHash;
        bytes32 validationHash;
        Verdict truth;
        bool correct;
        uint64 commitDeadline;
        uint64 settleDeadline;
    }

    IERC20 public immutable feeToken;
    IIdentityRegistry public immutable identity;
    IReputationRegistry public immutable reputation;
    IValidationRegistry public immutable validation;
    IAgentStakeVault public immutable vault;

    /// @notice Seconds a resolver has to commit after claiming.
    uint64 public immutable commitWindow;
    /// @notice Seconds a poster has to reveal after a commit.
    uint64 public immutable settleWindow;

    /// @dev Domain tag for the x402 claim nonce. Keeps claim authorisations from
    ///      colliding with any other EIP-3009 authorisation the payer might sign.
    bytes32 public constant CLAIM_SCOPE = keccak256("x402.priceright.claim.v1");

    bytes32 public constant TAG_SETTLEMENT = bytes32("priceright.settlement");
    bytes32 public constant TAG_CORRECT = bytes32("correct");
    bytes32 public constant TAG_WRONG = bytes32("wrong");
    bytes32 public constant TAG_COMMIT_TIMEOUT = bytes32("commit-timeout");
    bytes32 public constant TAG_REVEAL_TIMEOUT = bytes32("reveal-timeout");

    uint256 public nextTaskId = 1;
    mapping(uint256 => Task) internal _tasks;
    /// @notice Pull-payment ledger. Settlement credits; `withdraw` moves tokens.
    mapping(address => uint256) public credits;

    event TaskPosted(uint256 indexed taskId, address indexed poster, uint256 bounty, uint256 fee, uint256 slashAmount);
    event TaskCancelled(uint256 indexed taskId, address indexed poster, uint256 refunded);
    event X402PaymentSettled(uint256 indexed taskId, address indexed payer, uint256 amount, bytes32 nonce);
    event TaskClaimed(
        uint256 indexed taskId, uint256 indexed agentId, address indexed resolver, uint256 feePaid, uint256 bonded, uint64 commitDeadline
    );
    event VerdictCommitted(
        uint256 indexed taskId, uint256 indexed agentId, Verdict verdict, bytes32 reasoningHash, uint64 settleDeadline
    );
    event TaskSettled(
        uint256 indexed taskId, uint256 indexed agentId, bool correct, Verdict truth, uint256 slashed, uint256 rewardPaid
    );
    event TaskTimedOut(uint256 indexed taskId, uint256 indexed agentId, bytes32 reason, uint256 movedToPoster, uint256 movedToResolver);
    event Credited(address indexed account, uint256 amount, uint256 balance);
    event Withdrawn(address indexed account, uint256 amount);

    error ZeroAddress();
    error ZeroWindow();
    error BadCommit();
    error NotOpen();
    error NotClaimed();
    error NotCommitted();
    error NotResolver();
    error NotPoster();
    error BadVerdict();
    error EmptyReasoning();
    error TruthMismatch();
    error FeeTransferFailed();
    error UnknownTask();
    error PayerMismatch();
    error FeeAmountMismatch();
    error NonceNotBoundToTask();
    error FeeNotReceived();
    error DeadlineNotReached();
    error DeadlinePassed();
    error NothingToWithdraw();

    constructor(
        IERC20 _feeToken,
        IIdentityRegistry _identity,
        IReputationRegistry _reputation,
        IValidationRegistry _validation,
        IAgentStakeVault _vault,
        uint64 _commitWindow,
        uint64 _settleWindow
    ) {
        if (
            address(_feeToken) == address(0) || address(_identity) == address(0) || address(_reputation) == address(0)
                || address(_validation) == address(0) || address(_vault) == address(0)
        ) revert ZeroAddress();
        if (_commitWindow == 0 || _settleWindow == 0) revert ZeroWindow();
        feeToken = _feeToken;
        identity = _identity;
        reputation = _reputation;
        validation = _validation;
        vault = _vault;
        commitWindow = _commitWindow;
        settleWindow = _settleWindow;
    }

    // --- posting -------------------------------------------------------------

    /// @notice Post a task. The bounty is pulled into escrow up front and the ground
    ///         truth is fixed by a salted hash before any resolver can commit.
    function postTask(uint256 bounty, uint256 fee, uint256 slashAmount, bytes32 truthCommit)
        external
        returns (uint256 taskId)
    {
        if (truthCommit == bytes32(0)) revert BadCommit();
        taskId = nextTaskId++;
        if (bounty > 0 && !feeToken.transferFrom(msg.sender, address(this), bounty)) revert FeeTransferFailed();
        Task storage t = _tasks[taskId];
        t.poster = msg.sender;
        t.bounty = bounty;
        t.fee = fee;
        t.slashAmount = slashAmount;
        t.truthCommit = truthCommit;
        t.status = Status.Open;
        emit TaskPosted(taskId, msg.sender, bounty, fee, slashAmount);
    }

    /// @notice Withdraw an unclaimed task and take the bounty back. Only possible while
    ///         Open, so a resolver's committed work can never be pulled out from under it.
    function cancelTask(uint256 taskId) external {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        if (t.status != Status.Open) revert NotOpen();
        if (msg.sender != t.poster) revert NotPoster();
        t.status = Status.Cancelled;
        _credit(t.poster, t.bounty);
        emit TaskCancelled(taskId, t.poster, t.bounty);
    }

    // --- x402 claim ----------------------------------------------------------

    /// @notice The x402 nonce a claim payment for `(taskId, agentId)` must carry.
    ///         Binding the EIP-3009 nonce to the task, the arena and the chain is what
    ///         makes the payment un-replayable: the same signature is worthless anywhere
    ///         else, and the token's own nonce map makes it single-use here.
    function claimNonce(uint256 taskId, uint256 agentId) public view returns (bytes32) {
        return keccak256(abi.encode(CLAIM_SCOPE, address(this), block.chainid, taskId, agentId));
    }

    /// @notice The vault key holding this task's collateral.
    function bondKey(uint256 taskId) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), taskId));
    }

    /// @notice Claim a task by settling an x402 `exact` payment and bonding collateral.
    ///         The fee is moved by the payer's signature (EIP-3009), not by an approval,
    ///         and it is charged exactly once: the token marks the nonce used, so a
    ///         second claim with the same authorisation reverts inside the token.
    function claimTask(uint256 taskId, uint256 agentId, X402Payment calldata payment) external {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        if (t.status != Status.Open) revert NotOpen();
        if (identity.ownerOf(agentId) != msg.sender) revert NotResolver();
        if (payment.from != msg.sender) revert PayerMismatch();
        if (payment.value != t.fee) revert FeeAmountMismatch();
        if (payment.nonce != claimNonce(taskId, agentId)) revert NonceNotBoundToTask();

        if (t.fee > 0) {
            uint256 before = feeToken.balanceOf(address(this));
            IERC3009(address(feeToken)).transferWithAuthorization(
                payment.from,
                address(this),
                payment.value,
                payment.validAfter,
                payment.validBefore,
                payment.nonce,
                payment.v,
                payment.r,
                payment.s
            );
            // fail closed: a token that silently no-ops must not buy a claim.
            if (feeToken.balanceOf(address(this)) - before != t.fee) revert FeeNotReceived();
            emit X402PaymentSettled(taskId, payment.from, t.fee, payment.nonce);
        }

        t.status = Status.Claimed;
        t.agentId = agentId;
        t.resolver = msg.sender;
        t.commitDeadline = uint64(block.timestamp) + commitWindow;

        // collateral is custodied per task in the vault, pulled from the resolver.
        vault.bondFor(bondKey(taskId), agentId, msg.sender, t.slashAmount);

        emit TaskClaimed(taskId, agentId, msg.sender, t.fee, t.slashAmount, t.commitDeadline);
    }

    // --- commit --------------------------------------------------------------

    /// @notice Commit a verdict plus keccak-256 of the reasoning, and file the ERC-8004
    ///         validation request for it. The request is on-chain before the truth is
    ///         revealed, so the attestation cannot be written to fit the outcome.
    function commitVerdict(uint256 taskId, Verdict verdict, bytes32 reasoningHash) external {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        if (t.status != Status.Claimed) revert NotClaimed();
        if (msg.sender != t.resolver) revert NotResolver();
        if (block.timestamp > t.commitDeadline) revert DeadlinePassed();
        if (verdict == Verdict.None) revert BadVerdict();
        if (reasoningHash == bytes32(0)) revert EmptyReasoning();

        t.committed = verdict;
        t.reasoningHash = reasoningHash;
        t.status = Status.Committed;
        t.settleDeadline = uint64(block.timestamp) + settleWindow;
        t.validationHash = keccak256(abi.encode(address(this), taskId, reasoningHash));

        validation.validationRequest(address(this), t.agentId, "priceright:reasoning-commit", t.validationHash);
        emit VerdictCommitted(taskId, t.agentId, verdict, reasoningHash, t.settleDeadline);
    }

    // --- settlement ----------------------------------------------------------

    /// @notice Reveal the truth and settle. Pure function of (committed, truth):
    ///           correct -> resolver is credited fee + bounty and gets its collateral back
    ///           wrong   -> poster is credited fee + bounty and the collateral is slashed to it
    ///         Either way every token in play is credited to somebody.
    function settle(uint256 taskId, Verdict truth, bytes32 salt) external {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        if (t.status != Status.Committed) revert NotCommitted();
        if (msg.sender != t.poster) revert NotPoster();
        if (block.timestamp > t.settleDeadline) revert DeadlinePassed();
        if (truth == Verdict.None) revert BadVerdict();
        if (keccak256(abi.encodePacked(uint8(truth), salt)) != t.truthCommit) revert TruthMismatch();

        t.truth = truth;
        bool correct = (t.committed == truth);
        t.correct = correct;
        t.status = Status.Settled;

        uint256 slashed = 0;
        uint256 rewardPaid = 0;

        if (correct) {
            uint256 returned = vault.release(bondKey(taskId), address(this));
            rewardPaid = t.fee + t.bounty;
            _credit(t.resolver, rewardPaid + returned);
        } else {
            slashed = vault.slash(bondKey(taskId), address(this));
            _credit(t.poster, t.fee + t.bounty + slashed);
        }

        reputation.giveFeedback(
            t.agentId,
            correct ? 100 : 0,
            TAG_SETTLEMENT,
            correct ? TAG_CORRECT : TAG_WRONG,
            "priceright:settlement",
            t.reasoningHash
        );
        validation.validationResponse(
            t.validationHash, correct ? 100 : 0, "priceright:settlement", correct ? TAG_CORRECT : TAG_WRONG
        );

        emit TaskSettled(taskId, t.agentId, correct, truth, slashed, rewardPaid);
    }

    /// @notice Permissionless: the resolver claimed and then went quiet. After the commit
    ///         deadline the poster gets its bounty back plus the resolver's fee as the
    ///         penalty for occupying the task; the collateral is returned, because no
    ///         wrong verdict was ever given. Anyone may call this, so the poster's escrow
    ///         cannot be held hostage.
    function timeoutCommit(uint256 taskId) external {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        if (t.status != Status.Claimed) revert NotClaimed();
        if (block.timestamp <= t.commitDeadline) revert DeadlineNotReached();

        t.status = Status.Settled;
        uint256 returned = vault.release(bondKey(taskId), address(this));
        _credit(t.poster, t.fee + t.bounty);
        _credit(t.resolver, returned);
        reputation.giveFeedback(t.agentId, 0, TAG_SETTLEMENT, TAG_COMMIT_TIMEOUT, "priceright:timeout", bytes32(0));
        emit TaskTimedOut(taskId, t.agentId, TAG_COMMIT_TIMEOUT, t.fee + t.bounty, returned);
    }

    /// @notice Permissionless: the resolver committed and the poster never revealed.
    ///         After the settle deadline the resolver is made whole and paid the bounty,
    ///         and its collateral is released. Withholding a reveal is therefore strictly
    ///         worse for the poster than revealing, whatever the truth turns out to be.
    function timeoutSettle(uint256 taskId) external {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        if (t.status != Status.Committed) revert NotCommitted();
        if (block.timestamp <= t.settleDeadline) revert DeadlineNotReached();

        t.status = Status.Settled;
        uint256 returned = vault.release(bondKey(taskId), address(this));
        uint256 paid = t.fee + t.bounty;
        _credit(t.resolver, paid + returned);
        reputation.giveFeedback(
            t.agentId, 100, TAG_SETTLEMENT, TAG_REVEAL_TIMEOUT, "priceright:timeout", t.reasoningHash
        );
        emit TaskTimedOut(taskId, t.agentId, TAG_REVEAL_TIMEOUT, 0, paid + returned);
    }

    // --- payouts -------------------------------------------------------------

    function withdraw() external returns (uint256 amount) {
        amount = credits[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credits[msg.sender] = 0;
        if (!feeToken.transfer(msg.sender, amount)) revert FeeTransferFailed();
        emit Withdrawn(msg.sender, amount);
    }

    function _credit(address account, uint256 amount) internal {
        if (amount == 0) return;
        credits[account] += amount;
        emit Credited(account, amount, credits[account]);
    }

    // --- views ---------------------------------------------------------------

    /// @notice The commitment a poster publishes for a given truth + salt.
    function commitmentFor(Verdict truth, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(truth), salt));
    }

    function getTask(uint256 taskId)
        external
        view
        returns (
            address poster,
            uint256 bounty,
            uint256 fee,
            uint256 slashAmount,
            Status status,
            uint256 agentId,
            address resolver,
            Verdict committed,
            bytes32 reasoningHash,
            Verdict truth,
            bool correct
        )
    {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        return (
            t.poster, t.bounty, t.fee, t.slashAmount, t.status, t.agentId,
            t.resolver, t.committed, t.reasoningHash, t.truth, t.correct
        );
    }

    function deadlines(uint256 taskId) external view returns (uint64 commitBy, uint64 settleBy) {
        Task storage t = _tasks[taskId];
        if (t.poster == address(0)) revert UnknownTask();
        return (t.commitDeadline, t.settleDeadline);
    }

    function validationHashOf(uint256 taskId) external view returns (bytes32) {
        return _tasks[taskId].validationHash;
    }

    function taskCount() external view returns (uint256) {
        return nextTaskId - 1;
    }
}
