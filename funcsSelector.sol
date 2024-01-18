// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.22;
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract NFTCaller {
    address public owner;
    address public cosigner;
    uint256 public expireTime;
    mapping(string => bool) sigvalue;
    uint256 public constant one_minute = 1 minutes;
    error notSatifiedSig();
    error NotOwnerAuthorized();

    constructor(address _cosigner, uint256 _expireTime) payable {
        owner = msg.sender;
        cosigner = _cosigner;
        expireTime = _expireTime * one_minute;
    }
//0xc5b2d404,2
    function Expire(bytes4 _expire, uint32 expire) external  onlyOwner returns(bool success, bytes memory data)  {
         ( success, data) = address(this).call(abi.encodeWithSelector(_expire, expire));
        require(
                success && (data.length == 0 || abi.decode(data, (bool))),
                "NFT_MINT_Faliled"
            );
        //return(success, data);
    }
//0xc5b2d404
    function updateExpire(uint32 expire) public {
        expireTime = expire * one_minute;
    }

    function updateSigner(address newsigner) external onlyOwner {
        require(newsigner != address(0), "Invalid Signer");
        cosigner = newsigner;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwnerAuthorized();
        _;
    }

    function updateOwner(address newowner) external onlyOwner {
        require(newowner != address(0), "Invalid Owner");
        owner = newowner;
    }

    function batchMintNFT(bytes memory encodedsig) external {
        (
            address[] memory nftcontract,
            address[] memory receivers,
            uint64[] memory amounts
        ) = assertValidCosign(encodedsig);
        bytes4 SELECTOR = bytes4(
            keccak256(bytes("nftcallermint(address,uint256)"))
        );
        for (uint256 i = 0; i < receivers.length; i++) {
            (bool success, bytes memory data) = nftcontract[i].call(
                abi.encodeWithSelector(SELECTOR, receivers[i], amounts[i])
            );
            require(
                success && (data.length == 0 || abi.decode(data, (bool))),
                "NFT_MINT_Faliled"
            );
        }
    }

    function assertValidCosign(bytes memory data)
        internal
        returns (
            address[] memory,
            address[] memory,
            uint64[] memory
        )
    {
        (
            address[] memory nftcontract,
            address[] memory receivers,
            uint64[] memory amounts,
            string memory requestId
        ) = _assertValidCosign(data);

        sigvalue[requestId] = true;
        return (nftcontract, receivers, amounts);
    }

    function _assertValidCosign(bytes memory data)
        public
        view
        returns (
            address[] memory,
            address[] memory,
            uint64[] memory,
            string memory
        )
    {
        (
            address[] memory nftcontract,
            address[] memory receivers,
            uint64[] memory amounts,
            string memory requestId,
            uint64 timestamp,
            bytes memory sig
        ) = decode(data);
        require(receivers.length != 0, "please enter the acceptance address");
        require(nftcontract.length == amounts.length, "Unmatched length");
        require(amounts.length == receivers.length, "Unmatched length");
        require((expireTime + timestamp >= block.timestamp), "HAS_Expired");
        require((!sigvalue[requestId]), "HAS_USED");

        if (
            !SignatureChecker.isValidSignatureNow(
                cosigner,
                getCosignDigest(
                    msg.sender,
                    nftcontract,
                    receivers,
                    amounts,
                    _chainID(),
                    requestId,
                    timestamp
                ),
                sig
            )
        ) {
            revert notSatifiedSig();
        }
        return (nftcontract, receivers, amounts, requestId);
    }

    /**
     * @dev Returns data hash for the given sender, qty and timestamp.
     */
    function getCosignDigest(
        address sender,
        address[] memory nftcontract,
        address[] memory receivers,
        uint64[] memory amounts,
        uint32 chainId,
        string memory requestId,
        uint64 timestamp
    ) internal view returns (bytes32) {
        bytes32 _msgHash = keccak256(
            abi.encodePacked(
                address(this),
                sender,
                cosigner,
                nftcontract,
                receivers,
                amounts,
                chainId,
                requestId,
                timestamp
            )
        );
        return toEthSignedMessageHash(_msgHash);
    }

    /**
     * @dev Returns chain id.
     */
    function _chainID() public view returns (uint32) {
        uint32 chainID;
        assembly {
            chainID := chainid()
        }
        return chainID;
    }

    function decode(bytes memory data)
        public
        pure
        returns (
            address[] memory nftcontract,
            address[] memory receivers,
            uint64[] memory amounts,
            string memory requestId,
            uint64 timestamp,
            bytes memory sig
        )
    {
        (
            ,
            ,
            ,
            nftcontract,
            receivers,
            amounts,
            ,
            requestId,
            timestamp,
            sig
        ) = abi.decode(
            data,
            (
                address,
                address,
                address,
                address[],
                address[],
                uint64[],
                uint32,
                string,
                uint64,
                bytes
            )
        );
    }

    function gettimestamp() public view returns (uint256) {
        return block.timestamp;
    }

    function toEthSignedMessageHash(bytes32 hash)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }

    fallback() external payable {}

    receive() external payable {}
}

