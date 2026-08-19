// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IIdentityRegistry} from "../interfaces/IAgentRegistry.sol";

/// @title ReputationRegistry - the ERC-8004 feedback layer.
/// @author Dipankar Sarkar
/// @notice ERC-8004 does not let a registry decide who is trustworthy. Anyone may leave
///         feedback about an agent; readers decide whose feedback counts by filtering
///         `getSummary` to a client allow-list. That design is what stops a single
///         privileged writer from owning an agent's track record, and it is why the
///         arena leaves feedback as a *client* rather than as an admin: a judge can
///         read the arena's score for an agent without having to trust the arena.
///
///         Scores are 0..100. Feedback is append-only and revocable only by its author.
contract ReputationRegistry {
    struct Feedback {
        uint8 score;
        bytes32 tag1;
        bytes32 tag2;
        string fileuri;
        bytes32 filehash;
        bool isRevoked;
    }

    IIdentityRegistry public immutable identity;

    // agentId => client => feedback list
    mapping(uint256 => mapping(address => Feedback[])) private _feedback;
    // agentId => clients that ever left feedback
    mapping(uint256 => address[]) private _clients;
    mapping(uint256 => mapping(address => bool)) private _seenClient;

    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint8 score,
        bytes32 indexed tag1,
        bytes32 tag2,
        string fileuri,
        bytes32 filehash
    );
    event FeedbackRevoked(uint256 indexed agentId, address indexed clientAddress, uint64 index);

    error UnknownAgent();
    error ScoreOutOfRange();
    error NoSuchFeedback();
    error AlreadyRevoked();

    constructor(IIdentityRegistry _identity) {
        identity = _identity;
    }

    /// @notice Leave feedback about an agent. Permissionless by design.
    function giveFeedback(
        uint256 agentId,
        uint8 score,
        bytes32 tag1,
        bytes32 tag2,
        string calldata fileuri,
        bytes32 filehash
    ) external returns (uint64 index) {
        if (!identity.exists(agentId)) revert UnknownAgent();
        if (score > 100) revert ScoreOutOfRange();
        Feedback[] storage list = _feedback[agentId][msg.sender];
        list.push(Feedback(score, tag1, tag2, fileuri, filehash, false));
        if (!_seenClient[agentId][msg.sender]) {
            _seenClient[agentId][msg.sender] = true;
            _clients[agentId].push(msg.sender);
        }
        index = uint64(list.length - 1);
        emit NewFeedback(agentId, msg.sender, score, tag1, tag2, fileuri, filehash);
    }

    function revokeFeedback(uint256 agentId, uint64 index) external {
        Feedback[] storage list = _feedback[agentId][msg.sender];
        if (index >= list.length) revert NoSuchFeedback();
        if (list[index].isRevoked) revert AlreadyRevoked();
        list[index].isRevoked = true;
        emit FeedbackRevoked(agentId, msg.sender, index);
    }

    /// @notice Aggregate an agent's feedback. `clients` empty means every client;
    ///         `tag1` zero means every tag. Revoked entries are excluded.
    function getSummary(uint256 agentId, address[] calldata clients, bytes32 tag1)
        external
        view
        returns (uint64 count, uint8 averageScore)
    {
        address[] memory who;
        if (clients.length == 0) {
            who = _clients[agentId]; // every client that ever left feedback
        } else {
            who = new address[](clients.length);
            for (uint256 i = 0; i < clients.length; i++) {
                who[i] = clients[i];
            }
        }
        uint256 total;
        for (uint256 i = 0; i < who.length; i++) {
            Feedback[] storage list = _feedback[agentId][who[i]];
            for (uint256 j = 0; j < list.length; j++) {
                if (list[j].isRevoked) continue;
                if (tag1 != bytes32(0) && list[j].tag1 != tag1) continue;
                total += list[j].score;
                count++;
            }
        }
        averageScore = count == 0 ? 0 : uint8(total / count);
    }

    function readFeedback(uint256 agentId, address client, uint64 index)
        external
        view
        returns (uint8 score, bytes32 tag1, bytes32 tag2, string memory fileuri, bytes32 filehash, bool isRevoked)
    {
        Feedback[] storage list = _feedback[agentId][client];
        if (index >= list.length) revert NoSuchFeedback();
        Feedback storage f = list[index];
        return (f.score, f.tag1, f.tag2, f.fileuri, f.filehash, f.isRevoked);
    }

    function feedbackCount(uint256 agentId, address client) external view returns (uint64) {
        return uint64(_feedback[agentId][client].length);
    }

    function getClients(uint256 agentId) external view returns (address[] memory) {
        return _clients[agentId];
    }
}
