// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IIdentityRegistry} from "../interfaces/IAgentRegistry.sol";

/// @title ValidationRegistry - the ERC-8004 validation layer.
/// @author Dipankar Sarkar
/// @notice Reputation is what clients say about an agent; validation is what a named
///         validator attests about one specific piece of work. In PriceRight the work
///         is a committed verdict: at commit time the arena files a request whose
///         `requestHash` is the keccak-256 of the resolver's reasoning, and at
///         settlement the poster (the designated validator) responds 100 or 0. The
///         request therefore exists on-chain *before* the truth is revealed, so the
///         attestation cannot be back-dated to fit the outcome.
contract ValidationRegistry {
    struct Request {
        address validator;
        address requester;
        uint256 agentId;
        string requestUri;
        uint64 requestedAt;
        bool answered;
        uint8 response;
        bytes32 tag;
    }

    IIdentityRegistry public immutable identity;
    mapping(bytes32 => Request) private _requests;

    event ValidationRequest(
        address indexed validator, uint256 indexed agentId, string requestUri, bytes32 indexed requestHash
    );
    event ValidationResponse(
        address indexed validator, uint256 indexed agentId, bytes32 indexed requestHash, uint8 response, string responseUri, bytes32 tag
    );

    error UnknownAgent();
    error DuplicateRequest();
    error NoSuchRequest();
    error NotValidator();
    error AlreadyAnswered();
    error ResponseOutOfRange();
    error ZeroHash();

    constructor(IIdentityRegistry _identity) {
        identity = _identity;
    }

    function validationRequest(address validator, uint256 agentId, string calldata requestUri, bytes32 requestHash)
        external
    {
        if (!identity.exists(agentId)) revert UnknownAgent();
        if (requestHash == bytes32(0)) revert ZeroHash();
        if (_requests[requestHash].validator != address(0)) revert DuplicateRequest();
        _requests[requestHash] = Request({
            validator: validator,
            requester: msg.sender,
            agentId: agentId,
            requestUri: requestUri,
            requestedAt: uint64(block.timestamp),
            answered: false,
            response: 0,
            tag: bytes32(0)
        });
        emit ValidationRequest(validator, agentId, requestUri, requestHash);
    }

    function validationResponse(bytes32 requestHash, uint8 response, string calldata responseUri, bytes32 tag)
        external
    {
        Request storage r = _requests[requestHash];
        if (r.validator == address(0)) revert NoSuchRequest();
        if (msg.sender != r.validator) revert NotValidator();
        if (r.answered) revert AlreadyAnswered();
        if (response > 100) revert ResponseOutOfRange();
        r.answered = true;
        r.response = response;
        r.tag = tag;
        emit ValidationResponse(r.validator, r.agentId, requestHash, response, responseUri, tag);
    }

    function getValidationStatus(bytes32 requestHash)
        external
        view
        returns (address validator, uint256 agentId, bool answered, uint8 response, bytes32 tag, uint64 requestedAt)
    {
        Request storage r = _requests[requestHash];
        if (r.validator == address(0)) revert NoSuchRequest();
        return (r.validator, r.agentId, r.answered, r.response, r.tag, r.requestedAt);
    }
}
