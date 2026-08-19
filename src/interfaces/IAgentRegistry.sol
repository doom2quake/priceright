// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title The external surfaces AgentArena writes through.
/// @notice Identity/Reputation/Validation follow ERC-8004; IERC3009 is the settlement
///         primitive the x402 "exact" scheme uses on EVM chains.

/// @dev ERC-8004 IdentityRegistry (an ERC-721 whose tokenId is the agentId).
interface IIdentityRegistry {
    function ownerOf(uint256 agentId) external view returns (address);
    function exists(uint256 agentId) external view returns (bool);
}

/// @dev ERC-8004 ReputationRegistry. Feedback is permissionless; readers filter by client.
interface IReputationRegistry {
    function giveFeedback(
        uint256 agentId,
        uint8 score,
        bytes32 tag1,
        bytes32 tag2,
        string calldata fileuri,
        bytes32 filehash
    ) external returns (uint64 index);
}

/// @dev ERC-8004 ValidationRegistry.
interface IValidationRegistry {
    function validationRequest(address validator, uint256 agentId, string calldata requestUri, bytes32 requestHash)
        external;
    function validationResponse(bytes32 requestHash, uint8 response, string calldata responseUri, bytes32 tag)
        external;
}

/// @dev Task-scoped collateral custody, keyed by the ERC-8004 agentId.
interface IAgentStakeVault {
    function bondFor(bytes32 bondKey, uint256 agentId, address depositor, uint256 amount) external;
    function release(bytes32 bondKey, address to) external returns (uint256 amount);
    function slash(bytes32 bondKey, address beneficiary) external returns (uint256 amount);
    function stakeOf(uint256 agentId) external view returns (uint256);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @dev EIP-3009 transfer authorisations. This is what x402's `exact` scheme signs:
///      the payer signs an EIP-712 TransferWithAuthorization and anyone may submit it,
///      so the payment is settled by the signature, not by a prior approval.
interface IERC3009 {
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
