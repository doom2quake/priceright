// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20, IIdentityRegistry} from "./interfaces/IAgentRegistry.sol";

/// @title AgentStakeVault - task-scoped collateral for ERC-8004 identities.
/// @author Dipankar Sarkar
/// @notice ERC-8004 deliberately says nothing about money: it standardises identity,
///         reputation and validation, and leaves economic security to an extension.
///         This is that extension. Collateral is real ERC-20 held by this vault, keyed
///         by a bond key the arena derives from `(arena, taskId)` and tagged with the
///         agentId it backs, so a slash burns a *specific* task's collateral and a
///         release returns it.
///
///         Every bond ends in exactly one of two terminal states, and both move tokens:
///           release(key, to) -> the full amount is transferred to `to`
///           slash(key, beneficiary) -> the full amount is transferred to `beneficiary`
///         There is no path that leaves collateral in this contract, which is checked by
///         `test_vault_conserves_tokens` and by the arena's settlement tests.
contract AgentStakeVault {
    struct Bond {
        uint256 agentId;
        address depositor;
        uint256 amount;
        bool closed;
    }

    IERC20 public immutable token;
    IIdentityRegistry public immutable identity;
    address public owner;

    mapping(address => bool) public isOperator; // arenas allowed to bond/release/slash
    mapping(bytes32 => Bond) private _bonds;
    mapping(uint256 => uint256) private _stakeOf;   // agentId => currently bonded
    mapping(uint256 => uint256) private _slashedOf; // agentId => cumulative slashed

    event OperatorSet(address indexed operator, bool allowed);
    event Bonded(bytes32 indexed bondKey, uint256 indexed agentId, address indexed depositor, uint256 amount);
    event Released(bytes32 indexed bondKey, uint256 indexed agentId, address indexed to, uint256 amount);
    event Slashed(bytes32 indexed bondKey, uint256 indexed agentId, address indexed beneficiary, uint256 amount);

    error NotOwner();
    error NotOperator();
    error UnknownAgent();
    error DuplicateBond();
    error NoSuchBond();
    error BondClosed();
    error TransferFailed();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyOperator() {
        if (!isOperator[msg.sender]) revert NotOperator();
        _;
    }

    constructor(IERC20 _token, IIdentityRegistry _identity) {
        if (address(_token) == address(0) || address(_identity) == address(0)) revert ZeroAddress();
        token = _token;
        identity = _identity;
        owner = msg.sender;
    }

    function setOperator(address operator, bool allowed) external onlyOwner {
        isOperator[operator] = allowed;
        emit OperatorSet(operator, allowed);
    }

    /// @notice Pull `amount` of collateral from `depositor` and lock it against `agentId`.
    function bondFor(bytes32 bondKey, uint256 agentId, address depositor, uint256 amount) external onlyOperator {
        if (!identity.exists(agentId)) revert UnknownAgent();
        if (_bonds[bondKey].depositor != address(0)) revert DuplicateBond();
        _bonds[bondKey] = Bond({agentId: agentId, depositor: depositor, amount: amount, closed: false});
        _stakeOf[agentId] += amount;
        if (amount > 0 && !token.transferFrom(depositor, address(this), amount)) revert TransferFailed();
        emit Bonded(bondKey, agentId, depositor, amount);
    }

    /// @notice Close a bond and send the collateral to `to`. Used when the resolver
    ///         earned it back (correct verdict, or a poster who never revealed).
    function release(bytes32 bondKey, address to) external onlyOperator returns (uint256 amount) {
        Bond storage b = _closeBond(bondKey);
        amount = b.amount;
        if (amount > 0 && !token.transfer(to, amount)) revert TransferFailed();
        emit Released(bondKey, b.agentId, to, amount);
    }

    /// @notice Close a bond and send the collateral to `beneficiary`. Slashed value is
    ///         never destroyed in place: it moves to the party the arena names.
    function slash(bytes32 bondKey, address beneficiary) external onlyOperator returns (uint256 amount) {
        if (beneficiary == address(0)) revert ZeroAddress();
        Bond storage b = _closeBond(bondKey);
        amount = b.amount;
        _slashedOf[b.agentId] += amount;
        if (amount > 0 && !token.transfer(beneficiary, amount)) revert TransferFailed();
        emit Slashed(bondKey, b.agentId, beneficiary, amount);
    }

    function _closeBond(bytes32 bondKey) internal returns (Bond storage b) {
        b = _bonds[bondKey];
        if (b.depositor == address(0)) revert NoSuchBond();
        if (b.closed) revert BondClosed();
        b.closed = true;
        _stakeOf[b.agentId] -= b.amount;
    }

    function stakeOf(uint256 agentId) external view returns (uint256) {
        return _stakeOf[agentId];
    }

    function slashedOf(uint256 agentId) external view returns (uint256) {
        return _slashedOf[agentId];
    }

    function bondInfo(bytes32 bondKey)
        external
        view
        returns (uint256 agentId, address depositor, uint256 amount, bool closed)
    {
        Bond storage b = _bonds[bondKey];
        if (b.depositor == address(0)) revert NoSuchBond();
        return (b.agentId, b.depositor, b.amount, b.closed);
    }
}
