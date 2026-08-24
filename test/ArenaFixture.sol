// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {AgentArena} from "../src/AgentArena.sol";
import {AgentStakeVault} from "../src/AgentStakeVault.sol";
import {IdentityRegistry} from "../src/erc8004/IdentityRegistry.sol";
import {ReputationRegistry} from "../src/erc8004/ReputationRegistry.sol";
import {ValidationRegistry} from "../src/erc8004/ValidationRegistry.sol";
import {
    IERC20,
    IIdentityRegistry,
    IReputationRegistry,
    IValidationRegistry,
    IAgentStakeVault
} from "../src/interfaces/IAgentRegistry.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev The cheatcodes the suite uses. Declared locally so the repo builds with no
///      vendored dependencies at all - `forge test` works on a clean clone.
interface Vm {
    function expectRevert() external;
    function expectPartialRevert(bytes4 selector) external;
    function prank(address) external;
    function warp(uint256) external;
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8, bytes32, bytes32);
}

/// @dev Shared deployment for the arena tests: the three ERC-8004 registries, the
///      collateral vault, the EIP-3009 fee token, and the arena wired to all of them.
contract ArenaFixture {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    IdentityRegistry identity;
    ReputationRegistry reputation;
    ValidationRegistry validation;
    AgentStakeVault vault;
    AgentArena arena;
    MockERC20 token;

    uint256 constant POSTER_PK = 0xB0B;
    uint256 constant RESOLVER_PK = 0xA11CE;
    address POSTER;
    address RESOLVER;
    address constant STRANGER = address(0xCAFE);

    uint256 agentId;

    bytes32 constant SALT = keccak256("salt-1");
    bytes32 constant REASONING = keccak256("ETH closed above 4000 on the settlement block, so YES.");

    uint256 constant BOUNTY = 100;
    uint256 constant FEE = 10;
    uint256 constant SLASH = 50;
    uint64 constant COMMIT_WINDOW = 1 hours;
    uint64 constant SETTLE_WINDOW = 2 hours;

    function _deploy() internal {
        vm.warp(1_800_000_000);
        POSTER = vm.addr(POSTER_PK);
        RESOLVER = vm.addr(RESOLVER_PK);

        token = new MockERC20("Test USD", "tUSD", 6);
        identity = new IdentityRegistry();
        reputation = new ReputationRegistry(IIdentityRegistry(address(identity)));
        validation = new ValidationRegistry(IIdentityRegistry(address(identity)));
        vault = new AgentStakeVault(IERC20(address(token)), IIdentityRegistry(address(identity)));
        arena = new AgentArena(
            IERC20(address(token)),
            IIdentityRegistry(address(identity)),
            IReputationRegistry(address(reputation)),
            IValidationRegistry(address(validation)),
            IAgentStakeVault(address(vault)),
            COMMIT_WINDOW,
            SETTLE_WINDOW
        );
        vault.setOperator(address(arena), true);

        vm.prank(RESOLVER);
        agentId = identity.register("ipfs://resolver-card");

        token.mint(POSTER, 1000);
        token.mint(RESOLVER, 1000);
        // the bounty and the collateral use allowances; the x402 fee does not.
        vm.prank(POSTER);
        token.approve(address(arena), type(uint256).max);
        vm.prank(RESOLVER);
        token.approve(address(vault), type(uint256).max);
    }

    function _assert(bool c, string memory m) internal pure {
        require(c, m);
    }

    // --- x402 helpers --------------------------------------------------------

    /// @dev Build and sign an x402 `exact` payment for a claim, exactly as the Python
    ///      client does: EIP-712 over the token's TransferWithAuthorization type, with
    ///      the nonce bound to (arena, chainId, taskId, agentId).
    function _payment(uint256 pk, uint256 taskId, uint256 aid, uint256 value)
        internal
        view
        returns (AgentArena.X402Payment memory p)
    {
        p.from = vm.addr(pk);
        p.value = value;
        p.validAfter = 0;
        p.validBefore = block.timestamp + 600;
        p.nonce = arena.claimNonce(taskId, aid);
        (p.v, p.r, p.s) = vm.sign(pk, _digest(p.from, address(arena), p.value, p.validAfter, p.validBefore, p.nonce));
    }

    function _digest(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), from, to, value, validAfter, validBefore, nonce
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
    }

    // --- flow helpers --------------------------------------------------------

    function _post(AgentArena.Verdict truth) internal returns (uint256 taskId) {
        bytes32 commit = arena.commitmentFor(truth, SALT);
        vm.prank(POSTER);
        taskId = arena.postTask(BOUNTY, FEE, SLASH, commit);
    }

    function _claim(uint256 taskId) internal {
        AgentArena.X402Payment memory p = _payment(RESOLVER_PK, taskId, agentId, FEE);
        vm.prank(RESOLVER);
        arena.claimTask(taskId, agentId, p);
    }

    function _commit(uint256 taskId, AgentArena.Verdict v) internal {
        vm.prank(RESOLVER);
        arena.commitVerdict(taskId, v, REASONING);
    }

    function _withdraw(address who) internal returns (uint256) {
        if (arena.credits(who) == 0) return 0;
        vm.prank(who);
        return arena.withdraw();
    }
}
