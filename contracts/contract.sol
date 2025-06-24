// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4 <0.9.0;


// Copy from https://github.com/ensdomains/dnssec-oracle/blob/master/contracts/BytesUtils.sol
library BytesUtils {
    /*
    * @dev Returns the 32 byte value at the specified index of self.
    * @param self The byte string.
    * @param idx The index into the bytes
    * @return The specified 32 bytes of the string.
    */
    function readBytes32(bytes memory self, uint256 idx) internal pure returns (bytes32 ret) {
        require(idx + 32 <= self.length);
        assembly {
            ret := mload(add(add(self, 32), idx))
        }
    }

    /*
     * @dev Returns the 32 byte value at the specified index of self.
     * @param self The byte string.
     * @param idx The index into the bytes
     * @return The specified 32 bytes of the string.
     */
    function readBytes20(
        bytes memory self,
        uint256 idx
    ) internal pure returns (bytes20 ret) {
        require(idx + 20 <= self.length);
        assembly {
            ret := and(
                mload(add(add(self, 32), idx)),
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
            )
        }
    }
}


// Copy from https://github.com/automata-network/automata-dcap-attestation
struct Header {
    uint16 version;
    bytes2 attestationKeyType;
    bytes4 teeType;
    bytes2 qeSvn;
    bytes2 pceSvn;
    bytes16 qeVendorId;
    bytes20 userData;
}

interface IQuoteVerifier {
    /**
     * @notice the quote version supported by this verifier
     */
    function quoteVersion() external view returns (uint16);

    function verifyQuote(Header calldata, bytes calldata) external view returns (bool, bytes memory);

    /**
     * @notice additional check on the public output obtained from the ZK Program execution
     */
    function verifyZkOutput(bytes calldata) external view returns (bool, bytes memory);
}


/**
 * @title On-chain Bounty Task Manager
 * @notice This contract relies on V3/V4QuoteVerifier to verify the attestation quote
 */
contract BugBountyPlatform {
    using BytesUtils for bytes;

    // embedded addresses
    address[] public proofCheckers;
    address[] public bugVerifiers;

    // V3/V4QuoteVerifier
    IQuoteVerifier public v3QuoteVerifier;
    IQuoteVerifier public v4QuoteVerifier;

    // MRENCLAVE of the bug verifier
    bytes32 public BUG_VERIFIER_MRENCLAVE;


    // bug bounty struct
    struct BugBounty {
        bool exist;
        bool resolved;
        address proofChecker;
        bytes32 hash;
        string name;
        uint timestamp;
        string[] constraints;
    }
    // bug bounty mapping
    mapping(bytes32 => BugBounty) public bugBounties;

    event PublishTask(address indexed from, bytes32 indexed hash);
    event VerifyBug(address indexed from, bytes32 indexed hash);
    event VerifyAttestationQuote(address indexed from, bytes32 indexed hash);

    constructor(address[] memory _proofCheckers, address[] memory _bugVerifiers, address v3QuoteVerifierAddress, address v4QuoteVerifierAddress, bytes32 bugVerifierMrenclave) {
        proofCheckers = _proofCheckers;
        bugVerifiers = _bugVerifiers;
        v3QuoteVerifier = IQuoteVerifier(v3QuoteVerifierAddress);
        v4QuoteVerifier = IQuoteVerifier(v4QuoteVerifierAddress);
        BUG_VERIFIER_MRENCLAVE = bugVerifierMrenclave;
    }


    modifier onlyProofChecker() {
        bool isProofChecker = false;
        for (uint i = 0; i < proofCheckers.length; i++) {
            if (msg.sender == proofCheckers[i]) {
                isProofChecker = true;
                break;
            }
        }
        require(isProofChecker);
        _;
    }


    modifier onlyBugVerifier() {
        bool isBugVerifier = false;
        for (uint i=0; i < bugVerifiers.length; i++) {
            if (msg.sender == bugVerifiers[i]) {
                isBugVerifier = true;
                break;
            }
        }
        require(isBugVerifier);
        _;
    }

    /**
     * 
     * @param hash        the hash of the bounty task
     * @param name        the name of the bounty task
     * @param constraints bug bounty constraints
     */
    function publishTask(bytes32 hash, string memory name, string[] memory constraints) onlyProofChecker public {
        require(!bugBounties[hash].exist);
        
        bugBounties[hash] = BugBounty(
            true,
            false,
            msg.sender,
            hash,
            name,
            block.timestamp,
            constraints
        );

        emit PublishTask(msg.sender, hash);
    }

    /**
     * @param hash the hash of the bounty task
     * @notice only the bug verifier can verify the bug
     */
    function verifyBug(bytes32 hash) onlyBugVerifier public {
        require(bugBounties[hash].exist, "Task does not exist");

        bugBounties[hash].resolved = true;

        emit VerifyBug(msg.sender, hash);
    }

    /**
     * @param header the header of the attestation quote
     * @param quote  the attestation quote
     * @notice only the bug verifier can verify the v3 quote
     */
    function verifyBugThroughV3Quote(Header calldata header, bytes calldata quote) public {
        // verify the quote
        bool success;
        bytes memory output;
        (success, output) = v3QuoteVerifier.verifyQuote(header, quote);
        require(success, string(output));

        // check MRENCLAVE
        bytes32 mrenclave = quote.readBytes32(112); // 64+48
        require(mrenclave == BUG_VERIFIER_MRENCLAVE, "Enclave is not verified");

        // prevent front-running attack
        address sender = address(quote.readBytes20(400)); // 352+48
        require(sender == msg.sender, "Sender is not verified");

        bytes32 hash = quote.readBytes32(368); // 320+48
        require(bugBounties[hash].exist, "Task does not exist");
        bugBounties[hash].resolved = true;
        emit VerifyAttestationQuote(msg.sender, hash);
    }

    /**
     * @param header the header of the attestation quote
     * @param quote  the attestation quote
     * @notice only the bug verifier can verify the v4 quote
     */
    function verifyBugThroughV4Quote(Header calldata header, bytes calldata quote) public {
        // verify the quote
        bool success;
        bytes memory output;
        (success, output) = v4QuoteVerifier.verifyQuote(header, quote);
        require(success, string(output));

        // check MRENCLAVE
        bytes32 mrenclave = quote.readBytes32(112); // 64+48
        require(mrenclave == BUG_VERIFIER_MRENCLAVE, "Enclave is not verified");

        // prevent front-running attack
        address sender = address(quote.readBytes20(400)); // 352+48
        require(sender == msg.sender, "Sender is not verified");

        bytes32 hash = quote.readBytes32(368); // 320+48
        require(bugBounties[hash].exist, "Task does not exist");

        bugBounties[hash].resolved = true;

        emit VerifyAttestationQuote(msg.sender, hash);
    }

    /** View functions */

    /**
     * @param hash the hash of the bounty task
     * @return the name of the bounty task if exist
     */
    function retrieveName(bytes32 hash) view public returns(string memory) {
        if (bugBounties[hash].exist) {
            return bugBounties[hash].name;
        } else {
            return "";
        }
    }

    /**
     * @param hash the hash of the bounty task
     * @return the timestamp of the bounty task if exist
     */
    function retrieveTimestamp(bytes32 hash) view public returns(uint) {
        if (bugBounties[hash].exist) {
            return bugBounties[hash].timestamp;
        } else {
            return 0;
        }
    }

    /**
     * @param hash the hash of the bounty task
     * @return the constraints of the bounty task if exist
     */
    function retrieveConstraints(bytes32 hash) view public returns(string[] memory) {
        string[] memory constraints;
        if (bugBounties[hash].exist) {
            return bugBounties[hash].constraints;
        } else {
            return constraints;
        }
    }
}