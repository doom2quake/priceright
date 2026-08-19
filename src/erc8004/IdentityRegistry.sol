// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title IdentityRegistry - the ERC-8004 identity layer, as a real ERC-721.
/// @author Dipankar Sarkar
/// @notice ERC-8004 ("Trustless Agents") puts agent identity in an ERC-721 registry:
///         the tokenId *is* the agentId, the token URI points at the agent card, and
///         arbitrary key/value metadata can be attached on registration. Because it is
///         a real ERC-721 the identity is transferable, approvable and indexable by any
///         wallet or explorer that already understands NFTs, which is the entire point
///         of standardising it. This is a self-contained implementation of that layer:
///         `supportsInterface` reports ERC-165, ERC-721 and ERC-721Metadata, and a
///         transferred identity carries its reputation with it because reputation is
///         keyed by agentId, not by address.
///
///         Testnet only.
contract IdentityRegistry {
    struct MetadataEntry {
        string key;
        string value;
    }

    string public constant name = "ERC-8004 Trustless Agents";
    string public constant symbol = "AGENT";

    uint256 public totalAgents;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    mapping(uint256 => string) private _tokenURIs;
    mapping(uint256 => mapping(string => string)) private _metadata;

    // ERC-721
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    // ERC-8004
    event Registered(uint256 indexed agentId, string tokenURI, MetadataEntry[] metadata);
    event MetadataSet(uint256 indexed agentId, string indexed indexedKey, string key, string value);

    error NotAuthorized();
    error UnknownAgent();
    error ZeroAddress();
    error WrongOwner();
    error UnsafeRecipient();

    /// @notice Mint a portable agent identity to the caller. Returns the agentId.
    function register(string calldata uri) external returns (uint256 agentId) {
        MetadataEntry[] memory empty;
        return _register(msg.sender, uri, empty);
    }

    function register(string calldata uri, MetadataEntry[] calldata metadata) external returns (uint256 agentId) {
        return _register(msg.sender, uri, metadata);
    }

    function _register(address to, string memory uri, MetadataEntry[] memory metadata)
        internal
        returns (uint256 agentId)
    {
        if (to == address(0)) revert ZeroAddress();
        agentId = ++totalAgents;
        _owners[agentId] = to;
        _balances[to] += 1;
        _tokenURIs[agentId] = uri;
        for (uint256 i = 0; i < metadata.length; i++) {
            _metadata[agentId][metadata[i].key] = metadata[i].value;
            emit MetadataSet(agentId, metadata[i].key, metadata[i].key, metadata[i].value);
        }
        emit Transfer(address(0), to, agentId);
        emit Registered(agentId, uri, metadata);
    }

    function setTokenURI(uint256 agentId, string calldata uri) external {
        if (!_isAuthorized(msg.sender, agentId)) revert NotAuthorized();
        _tokenURIs[agentId] = uri;
    }

    function setMetadata(uint256 agentId, string calldata key, string calldata value) external {
        if (!_isAuthorized(msg.sender, agentId)) revert NotAuthorized();
        _metadata[agentId][key] = value;
        emit MetadataSet(agentId, key, key, value);
    }

    function getMetadata(uint256 agentId, string calldata key) external view returns (string memory) {
        return _metadata[agentId][key];
    }

    // --- ERC-721 ------------------------------------------------------------

    function ownerOf(uint256 agentId) public view returns (address owner) {
        owner = _owners[agentId];
        if (owner == address(0)) revert UnknownAgent();
    }

    function exists(uint256 agentId) external view returns (bool) {
        return _owners[agentId] != address(0);
    }

    function balanceOf(address owner) external view returns (uint256) {
        if (owner == address(0)) revert ZeroAddress();
        return _balances[owner];
    }

    function tokenURI(uint256 agentId) external view returns (string memory) {
        ownerOf(agentId);
        return _tokenURIs[agentId];
    }

    function approve(address to, uint256 agentId) external {
        address owner = ownerOf(agentId);
        if (msg.sender != owner && !_operatorApprovals[owner][msg.sender]) revert NotAuthorized();
        _tokenApprovals[agentId] = to;
        emit Approval(owner, to, agentId);
    }

    function getApproved(uint256 agentId) external view returns (address) {
        ownerOf(agentId);
        return _tokenApprovals[agentId];
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) external view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 agentId) public {
        if (!_isAuthorized(msg.sender, agentId)) revert NotAuthorized();
        if (ownerOf(agentId) != from) revert WrongOwner();
        if (to == address(0)) revert ZeroAddress();
        delete _tokenApprovals[agentId];
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[agentId] = to;
        emit Transfer(from, to, agentId);
    }

    function safeTransferFrom(address from, address to, uint256 agentId) external {
        safeTransferFrom(from, to, agentId, "");
    }

    function safeTransferFrom(address from, address to, uint256 agentId, bytes memory data) public {
        transferFrom(from, to, agentId);
        if (to.code.length != 0) {
            bytes4 ret = IERC721Receiver(to).onERC721Received(msg.sender, from, agentId, data);
            if (ret != IERC721Receiver.onERC721Received.selector) revert UnsafeRecipient();
        }
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7 // ERC-165
            || id == 0x80ac58cd // ERC-721
            || id == 0x5b5e139f; // ERC-721Metadata
    }

    function _isAuthorized(address spender, uint256 agentId) internal view returns (bool) {
        address owner = ownerOf(agentId);
        return spender == owner || _tokenApprovals[agentId] == spender || _operatorApprovals[owner][spender];
    }
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}
