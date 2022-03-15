# utils

utils是所有辅助合约的集合, 其它合约里经常引用, 阅读其他合约前最好先了解utils里的功能.

## cryptography

主要是做签名验证相关的功能合约.

### `draft-EIP712.sol`

参考[EIP712](https://eips.ethereum.org/EIPS/eip-712), 对struct data做签名的提案.

合约的核心是基于各种参数计算出一个separator, 来对struct data签名. separator的主要作用是填充签名数据, 防止跨链和跨合约的重放攻击.

separator参数包括:

1. chain id
2. 合约地址
3. 自定义domain, 自定义version


* 代码

```
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/cryptography/draft-EIP712.sol)

pragma solidity ^0.8.0;

import "./ECDSA.sol";

/**
* @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.
*
* The encoding specified in the EIP is very generic, and such a generic implementation in Solidity is not feasible,
* thus this contract does not implement the encoding itself. Protocols need to implement the type-specific encoding
* they need in their contracts using a combination of `abi.encode` and `keccak256`.
*
* This contract implements the EIP 712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
* scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA
* ({_hashTypedDataV4}).
*
* The implementation of the domain separator was designed to be as efficient as possible while still properly updating
* the chain id to protect against replay attacks on an eventual fork of the chain.
*
* NOTE: This contract implements the version of the encoding known as "v4", as implemented by the JSON RPC method
* https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].
*
* _Available since v3.4._
*/
abstract contract EIP712 {
    /* solhint-disable var-name-mixedcase */
    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;
    address private immutable _CACHED_THIS;

    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;

    /* solhint-enable var-name-mixedcase */

    /**
    * @dev Initializes the domain separator and parameter caches.
    *
    * The meaning of `name` and `version` is specified in
    * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
    *
    * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
    * - `version`: the current major version of the signing domain.
    *
    * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
    * contract upgrade].
    */
    constructor(string memory name, string memory version) {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(typeHash, hashedName, hashedVersion);
        _CACHED_THIS = address(this);
        _TYPE_HASH = typeHash;
    }

    /**
    * @dev Returns the domain separator for the current chain.

    根据参数计算一个DomainSeparator
    */
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (address(this) == _CACHED_THIS && block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
        }
    }

    //计算separator时, 参数包括(预定义hash, 版本hash, chainid, 该合约当前地址)

    function _buildDomainSeparator(
        bytes32 typeHash,
        bytes32 nameHash,
        bytes32 versionHash
    ) private view returns (bytes32) {
        return keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(this)));
    }

    /**
    * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
    * function returns the hash of the fully encoded EIP712 message for this domain.
    *
    * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
    *
    * ```solidity
    * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
    *     keccak256("Mail(address to,string contents)"),
    *     mailTo,
    *     keccak256(bytes(mailContents))
    * )));
    * address signer = ECDSA.recover(digest, signature);
    * ```
    */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}
```

* 使用方法:

```
bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
    keccak256("Mail(address to,string contents)"),
    mailTo,
    keccak256(bytes(mailContents))
)));

//ECDSA合约解析在下面
address signer = ECDSA.recover(digest, signature);
```

### `ECDSA.sol`

用来做数字签名验证的合约, solidity提供了ecrecover原语, 但是存在被恶意伪造和hack的可能, ECDSA库提供的recover库做了一些额外限定, 另外提供了标准的获取SignHash方法供使用.

* 代码

```
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.0;

import "../Strings.sol";

/**
* @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
*
* These functions can be used to verify that a message was signed by the holder
* of the private keys of a given address.
*/
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        } else if (error == RecoverError.InvalidSignatureV) {
            revert("ECDSA: invalid signature 'v' value");
        }
    }

    /**
    * @dev Returns the address that signed a hashed message (`hash`) with
    * `signature` or error string. This address can then be used for verification purposes.
    *
    * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
    * this function rejects them by requiring the `s` value to be in the lower
    * half order, and the `v` value to be either 27 or 28.
    *
    * IMPORTANT: `hash` _must_ be the result of a hash operation for the
    * verification to be secure: it is possible to craft signatures that
    * recover to arbitrary addresses for non-hashed data. A safe way to ensure
    * this is by receiving a hash of the original message (which may otherwise
    * be too long), and then calling {toEthSignedMessageHash} on it.
    *
    * Documentation for signature generation:
    * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
    * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
    *
    * _Available since v4.3._
    */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        // Check the signature length
        // - case 65: r,s,v signature (standard)
        // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098) _Available since v4.1._
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else if (signature.length == 64) {
            bytes32 r;
            bytes32 vs;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }
            return tryRecover(hash, r, vs);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
    * @dev Returns the address that signed a hashed message (`hash`) with
    * `signature`. This address can then be used for verification purposes.
    *
    * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
    * this function rejects them by requiring the `s` value to be in the lower
    * half order, and the `v` value to be either 27 or 28.
    *
    * IMPORTANT: `hash` _must_ be the result of a hash operation for the
    * verification to be secure: it is possible to craft signatures that
    * recover to arbitrary addresses for non-hashed data. A safe way to ensure
    * this is by receiving a hash of the original message (which may otherwise
    * be too long), and then calling {toEthSignedMessageHash} on it.
    */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
    * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
    *
    * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
    *
    * _Available since v4.3._
    */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address, RecoverError) {
        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    /**
    * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
    *
    * _Available since v4.2._
    */
    function recover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
    * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
    * `r` and `s` signature fields separately.
    *
    * _Available since v4.3._
    */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }
        if (v != 27 && v != 28) {
            return (address(0), RecoverError.InvalidSignatureV);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
    * @dev Overload of {ECDSA-recover} that receives the `v`,
    * `r` and `s` signature fields separately.
    */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
    * @dev Returns an Ethereum Signed Message, created from a `hash`. This
    * produces hash corresponding to the one signed with the
    * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
    * JSON-RPC method as part of EIP-191.
    *
    * See {recover}.
    */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
    * @dev Returns an Ethereum Signed Message, created from `s`. This
    * produces hash corresponding to the one signed with the
    * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
    * JSON-RPC method as part of EIP-191.
    *
    * See {recover}.
    */
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(s.length), s));
    }

    /**
    * @dev Returns an Ethereum Signed Typed Data, created from a
    * `domainSeparator` and a `structHash`. This produces hash corresponding
    * to the one signed with the
    * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
    * JSON-RPC method as part of EIP-712.
    *
    * See {recover}.
    */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
```

* 分析

核心函数是recover, 根据hash和签名计算出signer的address, 合约同时提供了`toEthSignedMessageHash`等几个方法来计算内容hash, **注意, signature是链下生成的**.

### `MerkelProof.sol`

提供默克尔树的验证相关功能, 有关Merkel树, 可以参考[Merkel树结构](https://yeasy.gitbook.io/blockchain_guide/05_crypto/merkle_trie), 简单说是可以对多个数据提供一个签名方法, 分段验证单个数据的可靠性.

Merkel树的基本使用方式是创建方基于所有数据计算出各个Merkel leaf的proofs路径然后发给各个leaf owner保存, leaf owner可以用该path去链上通过验证.

* 代码

```
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
* @dev These functions deal with verification of Merkle Trees proofs.
*
* The proofs can be generated using the JavaScript library
* https://github.com/miguelmota/merkletreejs[merkletreejs].
* Note: the hashing algorithm should be keccak256 and pair sorting should be enabled.
*
* See `test/utils/cryptography/MerkleProof.test.js` for some examples.
*
* WARNING: You should avoid using leaf values that are 64 bytes long prior to
* hashing, or use a hash function other than keccak256 for hashing leaves.
* This is because the concatenation of a sorted pair of internal nodes in
* the merkle tree could be reinterpreted as a leaf value.
*/
library MerkleProof {
    /**
    * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
    * defined by `root`. For this, a `proof` must be provided, containing
    * sibling hashes on the branch from the leaf to the root of the tree. Each
    * pair of leaves and each pair of pre-images are assumed to be sorted.
    */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
    * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
    * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
    * hash matches the root of the tree. When processing the proof, the pairs
    * of leafs & pre-images are assumed to be sorted.
    *
    * _Available since v4.4._
    */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = _efficientHash(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = _efficientHash(proofElement, computedHash);
            }
        }
        return computedHash;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
```

* 分析

默克尔树是一种对多段数据提供签名验证的算法, 该合约核心函数是`processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32)`, 内部逻辑是从proof数组0索引开始处理 computedHash[i+1] = HASH(computedHash[i], proof[i + 1]), 最后得到根部root的hash. 

验证时就是判断得到的根部root hash是否等于实际的root hash.
    

### `SignatureChecker.sol`

集成了ECDSA库的recover功能, 同时支持了[ERC1271的合约签名](https://eips.ethereum.org/EIPS/eip-1271).

验证签名时, 会首先尝试用ECDSA验证, 如果验证不通过, 再尝试ERC1271去调用合约验证签名.


* 代码
``
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/SignatureChecker.sol)

pragma solidity ^0.8.0;

import "./ECDSA.sol";
import "../Address.sol";
import "../../interfaces/IERC1271.sol";

/**
* @dev Signature verification helper that can be used instead of `ECDSA.recover` to seamlessly support both ECDSA
* signatures from externally owned accounts (EOAs) as well as ERC1271 signatures from smart contract wallets like
* Argent and Gnosis Safe.
*
* _Available since v4.1._
*/
library SignatureChecker {
    /**
    * @dev Checks if a signature is valid for a given signer and data hash. If the signer is a smart contract, the
    * signature is validated against that smart contract using ERC1271, otherwise it's validated using `ECDSA.recover`.
    *
    * NOTE: Unlike ECDSA signatures, contract signatures are revocable, and the outcome of this function can thus
    * change through time. It could return true at block N and false at block N+1 (or the opposite).
    */
    function isValidSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
        if (error == ECDSA.RecoverError.NoError && recovered == signer) {
            return true;
        }

        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
        );
        return (success && result.length == 32 && abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector);
    }
}
``

## escrow

escrow主要是基于各种需求的质押合约.

### `Escrow.sol`

一个只能让合约管理员来登记和提取质押资金的合约.

* 代码
```
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/escrow/Escrow.sol)

pragma solidity ^0.8.0;

import "../../access/Ownable.sol";
import "../Address.sol";

/**
 * @title Escrow
 * @dev Base escrow contract, holds funds designated for a payee until they
 * withdraw them.
 *
 * Intended usage: This contract (and derived escrow contracts) should be a
 * standalone contract, that only interacts with the contract that instantiated
 * it. That way, it is guaranteed that all Ether will be handled according to
 * the `Escrow` rules, and there is no need to check for payable functions or
 * transfers in the inheritance tree. The contract that uses the escrow as its
 * payment method should be its owner, and provide public methods redirecting
 * to the escrow's deposit and withdraw.
 */
contract Escrow is Ownable {
    using Address for address payable;

    event Deposited(address indexed payee, uint256 weiAmount);
    event Withdrawn(address indexed payee, uint256 weiAmount);

    mapping(address => uint256) private _deposits;

    function depositsOf(address payee) public view returns (uint256) {
        return _deposits[payee];
    }

    /**
     * @dev Stores the sent amount as credit to be withdrawn.
     * @param payee The destination address of the funds.
     */
    function deposit(address payee) public payable virtual onlyOwner {
        uint256 amount = msg.value;
        _deposits[payee] += amount;
        emit Deposited(payee, amount);
    }

    /**
     * @dev Withdraw accumulated balance for a payee, forwarding all gas to the
     * recipient.
     *
     * WARNING: Forwarding all gas opens the door to reentrancy vulnerabilities.
     * Make sure you trust the recipient, or are either following the
     * checks-effects-interactions pattern or using {ReentrancyGuard}.
     *
     * @param payee The address whose funds will be withdrawn and transferred to.
     */
    function withdraw(address payable payee) public virtual onlyOwner {
        uint256 payment = _deposits[payee];

        _deposits[payee] = 0;

        payee.sendValue(payment);

        emit Withdrawn(payee, payment);
    }
}
```

### `ConditionalEscrow.sol`


一个虚基类合约, 在Escrow.sol的基础上增加了`withdrawalAllowed`接口, 待实现类来决定业务逻辑.

* 代码

```
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/escrow/ConditionalEscrow.sol)

pragma solidity ^0.8.0;

import "./Escrow.sol";

/**
 * @title ConditionalEscrow
 * @dev Base abstract escrow to only allow withdrawal if a condition is met.
 * @dev Intended usage: See {Escrow}. Same usage guidelines apply here.
 */
abstract contract ConditionalEscrow is Escrow {
    /**
     * @dev Returns whether an address is allowed to withdraw their funds. To be
     * implemented by derived contracts.
     * @param payee The destination address of the funds.
     */
    function withdrawalAllowed(address payee) public view virtual returns (bool);

    function withdraw(address payable payee) public virtual override {
        require(withdrawalAllowed(payee), "ConditionalEscrow: payee is not allowed to withdraw");
        super.withdraw(payee);
    }
}
```

### `RefundEscrow.sol`




## introspection

### `ERC165.sol`

    ERC165就多了一个函数, 用来表示合约是否支持某一个interface.

    这里使用了一个机制 type(interface).interfaceId, interfaceId为该interface下所有function的signature(不考虑返回值)的hash结果.

    function supportsInterface(bytes4 interfaceId) 

### `ERC165Storage.sol`

    做了一个map来存储支持的interface, 其它函数可以继承该函数, 然后调用 _registerInterface来声明对某个interface的支持

### `ERC1820Impelementer.sol`


## math

### Math.sol

### SafeCast.sol

### SafeMath.sol

### SignedMath.sol

### SignedSafeMath.sol

## structs

### BitMaps.sol

### DoubleEndedQueue.sol

### EnumerableMap.sol

### EnumerableSet.sol

## Address.sol

`library Address`

1. isContract
1. sendValue // use call instead of transfer
1. function

## Array.sol

## Base64.sol

提供了base64编码的函数

## Checkpoints.sol

一个library, 可以存储和读取指定的history value 

## Context.sol

提供了msgSender和msdData的函数式访问方法

## Counters.sol

## Create2.sol

create2 library, 提供函数提前计算地址

## Multicall.sol

1. function multicall(bytes[] calldata data) external virtual retuns (bytes[] memory results) {

}

## StorageSlot.sol


基于汇编slot语法, 提供一个对于固定存储位置的访问功能.


## Strings.sol

1. toString(uint256 value) returns (string memory)

1. toHexString(uint256 value)

## Timers.sol

struct Timestamp {
    uint64 _deadline;
}

1. getDeadline(Timestamp memory timer) returns uint64

