pragma solidity 0.5.8;

contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor () internal {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(isOwner());
        _;
    }

    function isOwner() public view returns (bool) {
        return msg.sender == _owner;
    }

    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0));
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/**
 * @title RelayRegistry
 * @dev Singleton contract that registers a whitelist of relays accessed by the factory and smart wallets. Contract is owned by an external account for now but ownership should be transferred to a governance contract in the future.
 */
contract RelayRegistry is Ownable {
    
    event AddedRelay(address relay);
    event RemovedRelay(address relay);
    
    mapping (address => bool) public relays;
    
    constructor(address initialRelay) public {
        relays[initialRelay] = true;
    }
    /**
     * @dev Allows relay registry owner to add or remove a relay from the whitelist
     * @param relay Address of the selected relay
     * @param value True to add them to the whitelist, false to remove them
     */
    function triggerRelay(address relay, bool value) onlyOwner public returns (bool) {
        relays[relay] = value;
        if(value) {
            emit AddedRelay(relay);
        } else {
            emit RemovedRelay(relay);
        }
        return true;
    }
    
}

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
}

/**
 * @title Smart Wallet Contract
 * @dev All functions of this contract should be called using delegatecall from the Proxy contract. This allows us to significantly reduce the deployment costs of smart wallets. All functions of this contract are executed in the context of Proxy contract.
 */
contract SmartWallet {

    event Upgrade(address indexed newImplementation);

    /**
     * @dev Shared key value store. Data should be encoded and decoded using abi.encode()/abi.decode() by different functions. No data is actually stored in SmartWallet, instead everything is stored in the Proxy contract's context.
     */
    mapping (bytes32 => bytes) public store;
    
    modifier onlyRelay {
        RelayRegistry registry = RelayRegistry(0x4360b517f5b3b2D4ddfAEDb4fBFc7eF0F48A4Faa);
        require(registry.relays(msg.sender));
        _;
    }
    
    modifier onlyOwner {
        require(msg.sender == abi.decode(store["factory"], (address)) || msg.sender == abi.decode(store["owner"], (address)));
        _;
    }
    
    /**
     * @dev Function called once by Factory contract to initiate owner and nonce. This is necessary because we cannot pass arguments to a CREATE2-created contract without changing its address.
     * @param owner Wallet Owner
     */
    function initiate(address owner) public returns (bool) {
        // this function can only be called by the factory
        if(msg.sender != abi.decode(store["factory"], (address))) return false;
        // store current owner in key store
        store["owner"] = abi.encode(owner);
        store["nonce"] = abi.encode(0);
        return true;
    }
    
    /**
     * @dev Same as above, but also applies a feee to a relayer address provided by the factory
     * @param owner Wallet Owner
     * @param relay Address of the relayer
     * @param fee Fee paid to relayer in a token
     * @param token Address of ERC20 contract in which fee will be denominated.
     */
    function initiate(address owner, address relay, uint fee, address token) public returns (bool) {
        require(initiate(owner), "internal initiate failed");
        // Access ERC20 token
        IERC20 tokenContract = IERC20(token);
        // Send fee to relay
        tokenContract.transfer(relay, fee);
        return true;
    }
    
    /**
     * @dev Relayed token transfer. Submitted by a relayer on behalf of the wallet owner.
     * @param to Recipient address
     * @param value Transfer amount
     * @param fee Fee paid to the relayer
     * @param tokenContract Address of the token contract used for both the transfer and the fees
     * @param deadline Block number deadline for this signed message
     */
    function pay(address to, uint value, uint fee, address tokenContract, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (bool) {
        uint currentNonce = abi.decode(store["nonce"], (uint));
        require(block.number <= deadline);
        require(abi.decode(store["owner"], (address)) == recover(keccak256(abi.encodePacked("pay", msg.sender, to, tokenContract, value, fee, tx.gasprice, currentNonce, deadline)), v, r, s));
        IERC20 token = IERC20(tokenContract);
        store["nonce"] = abi.encode(currentNonce+1);
        token.transfer(to, value);
        token.transfer(msg.sender, fee);
        return true;
    }
    
    /**
     * @dev Direct token transfer. Submitted by the wallet owner
     * @param to Recipient address
     * @param value Transfer amount
     * @param tokenContract Address of the token contract used for the transfer
     */
    function pay(address to, uint value, address tokenContract) onlyOwner public returns (bool) {
        IERC20 token = IERC20(tokenContract);
        token.transfer(to, value);
        return true;
    }
    
    /**
     * @dev Same as above but allows batched transfers in multiple tokens 
     */
    function pay(address[] memory to, uint[] memory value, address[] memory tokenContract) onlyOwner public returns (bool) {
        for (uint i; i < to.length; i++) {
            IERC20 token = IERC20(tokenContract[i]);
            token.transfer(to[i], value[i]);
        }
        return true;
    }
    
    /**
     * @dev Internal function that executes a call to any contract
     * @param contractAddress Address of the contract to call
     * @param data calldata to send to contractAddress
     * @param msgValue Amount in wei to be sent with the call to the contract from the wallet's balance
     */
    function _execCall(address contractAddress, bytes memory data, uint256 msgValue) internal returns (bool result) {
        // Warning: This executes an external contract call, may pose re-entrancy risk.
        assembly {
            result := call(gas, contractAddress, msgValue, add(data, 0x20), mload(data), 0, 0)
        }
    }

    /**
     * @dev Internal function that creates any contract
     * @param data bytecode of the new contract
     */
    function _execCreate(bytes memory data) internal returns (bool result) {
        address deployedContract;
        assembly {
            deployedContract := create(0, add(data, 0x20), mload(data))
        }
        result = (deployedContract != address(0));
    }
    
    /**
     * @dev Internal function that creates any contract using create2
     * @param data bytecode of the new contract
     * @param salt Create2 salt parameter
     */
    function _execCreate2(bytes memory data, uint256 salt) internal returns (bool result) {
        address deployedContract;
        assembly {
            deployedContract := create2(0, add(data, 0x20), mload(data), salt)
        }
        result = (deployedContract != address(0));
    }
    
    /**
     * @dev Public function that allows the owner to execute a call to any contract
     * @param contractAddress Address of the contract to call
     * @param data calldata to send to contractAddress
     * @param msgValue Amount in wei to be sent with the call to the contract from the wallet's balance
     */
    function execCall(address contractAddress, bytes memory data, uint256 msgValue) onlyOwner public returns (bool) {
        require(_execCall(contractAddress, data, msgValue));
        return true;
    }
    
    /**
     * @dev Public function that allows a relayer to execute a call to any contract on behalf of the owner
     * @param contractAddress Address of the contract to call
     * @param data calldata to send to contractAddress
     * @param msgValue Amount in wei to be sent with the call to the contract from the wallet's balance
     * @param fee Fee paid to the relayer
     * @param tokenContract Address of the token contract used for the fee
     * @param deadline Block number deadline for this signed message
     */
    function execCall(address contractAddress, bytes memory data,  uint256 msgValue, uint fee, address tokenContract, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (bool) {
        uint currentNonce = abi.decode(store["nonce"], (uint));
        require(block.number <= deadline);
        require(abi.decode(store["owner"], (address)) == recover(keccak256(abi.encodePacked("execCall", msg.sender, contractAddress, tokenContract, data, msgValue, fee, tx.gasprice, currentNonce, deadline)), v, r, s));
        IERC20 token = IERC20(tokenContract);
        store["nonce"] = abi.encode(currentNonce+1);
        token.transfer(msg.sender, fee);
        require(_execCall(contractAddress, data, msgValue));
        return true;
    }
    
    /**
     * @dev Public function that allows the owner to create any contract
     * @param data bytecode of the new contract
     */
    function execCreate(bytes memory data) onlyOwner public returns (bool) {
        require(_execCreate(data));
        return true;
    }
    
    /**
     * @dev Public function that allows a relayer to create any contract on behalf of the owner
     * @param data new contract bytecode
     * @param fee Fee paid to the relayer
     * @param tokenContract Address of the token contract used for the fee
     * @param deadline Block number deadline for this signed message
     */
    function execCreate(bytes memory data, uint fee, address tokenContract, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (bool) {
        uint currentNonce = abi.decode(store["nonce"], (uint));
        require(block.number <= deadline);
        require(abi.decode(store["owner"], (address)) == recover(keccak256(abi.encodePacked("execCreate", msg.sender, tokenContract, data, fee, tx.gasprice, currentNonce, deadline)), v, r, s));
        require(_execCreate(data));
        IERC20 token = IERC20(tokenContract);
        store["nonce"] = abi.encode(currentNonce+1);
        token.transfer(msg.sender, fee);
        return true;
    }
    
    /**
     * @dev Public function that allows the owner to create any contract using create2
     * @param data bytecode of the new contract
     * @param salt Create2 salt parameter
     */
    function execCreate2(bytes memory data, uint salt) onlyOwner public returns (bool) {
        require(_execCreate2(data, salt));
        return true;
    }
    
    /**
     * @dev Public function that allows a relayer to create any contract on behalf of the owner using create2
     * @param data new contract bytecode
     * @param salt Create2 salt parameter
     * @param fee Fee paid to the relayer
     * @param tokenContract Address of the token contract used for the fee
     * @param deadline Block number deadline for this signed message
     */
    function execCreate2(bytes memory data, uint salt, uint fee, address tokenContract, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (bool) {
        uint currentNonce = abi.decode(store["nonce"], (uint));
        require(block.number <= deadline);
        require(abi.decode(store["owner"], (address)) == recover(keccak256(abi.encodePacked("execCreate2", msg.sender, tokenContract, data, salt, fee, tx.gasprice, currentNonce, deadline)), v, r, s));
        require(_execCreate2(data, salt));
        IERC20 token = IERC20(tokenContract);
        store["nonce"] = abi.encode(currentNonce+1);
        token.transfer(msg.sender, fee);
        return true;
    }
    
    /**
     * @dev Since all eth transfers to this contract are redirected to the owner. This is the only way for anyone, including the owner, to keep ETH on this contract.
     */
    function depositEth() public payable {}
    
    /**
     * @dev Allows the owner to withdraw all ETH from the contract. 
     */
    function withdrawEth() public onlyOwner() {
        address payable owner = abi.decode(store["owner"], (address));
        owner.transfer(address(this).balance);
    }
    
    /**
     * @dev Allows a relayer to change the address of the smart wallet implementation contract on behalf of the owner. New contract should have its own upgradability logic or Proxy will be stuck on it.
     * @param implementation Address of the new implementation contract to replace this one.
     * @param fee Fee paid to the relayer
     * @param feeContract Address of the fee token contract
     * @param deadline Block number deadline for this signed message
     */
    function upgrade(address implementation, uint fee, address feeContract, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (bool) {
        uint currentNonce = abi.decode(store["nonce"], (uint));
        require(block.number <= deadline);
        address owner = abi.decode(store["owner"], (address));
        require(owner == recover(keccak256(abi.encodePacked("upgrade", msg.sender, implementation, feeContract, fee, tx.gasprice, currentNonce, deadline)), v, r, s));
        store["nonce"] = abi.encode(currentNonce+1);
        store["fallback"] = abi.encode(implementation);
        IERC20 feeToken = IERC20(feeContract);
        feeToken.transfer(msg.sender, fee);
        emit Upgrade(implementation);
        return true;
        
    }
    
    /**
     * @dev Same as above, but activated directly by the owner.
     * @param implementation Address of the new implementation contract to replace this one.
     */
    function upgrade(address implementation) onlyOwner public returns (bool) {
        store["fallback"] = abi.encode(implementation);
        emit Upgrade(implementation);
        return true;
    }
    
    /**
     * @dev Internal function used to prefix hashes to allow for compatibility with signers such as Metamask
     * @param messageHash Original hash
     */
    function recover(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        bytes memory prefix = "\x19Metacash Signed Message:\n32";
        bytes32 prefixedMessageHash = keccak256(abi.encodePacked(prefix, messageHash));
        return ecrecover(prefixedMessageHash, v, r, s);
    }
    
}

/**
 * @title Proxy
 * @dev This contract is usually deployed as part of every user's first gasless transaction. It refers to a hardcoded address of the smart wallet contract and uses its functions via delegatecall.
 */
contract Proxy {
    
    /**
     * @dev Shared key value store. All data across different SmartWallet implementations is stored here. It also keeps storage across different upgrades.
     */
    mapping (bytes32 => bytes) public store;
    
    /**
     * @dev The Proxy constructor adds the hardcoded address of SmartWallet and the address of the factory (from msg.sender) to the store for later transactions
     */
    constructor() public {
        // set implementation address in storage
        store["fallback"] = abi.encode(0xEfc66C37a06507bCcABc0ce8d8bb5Ac4c1A2a8AA); // SmartWallet address
        // set factory address in storage
        store["factory"] = abi.encode(msg.sender);
    }
    
    /**
     * @dev The fallback functions forwards everything as a delegatecall to the implementation SmartWallet contract
     */
    function() external payable {
        address impl = abi.decode(store["fallback"], (address));
        assembly {
          let ptr := mload(0x40)
        
          // (1) copy incoming call data
          calldatacopy(ptr, 0, calldatasize)
        
          // (2) forward call to logic contract
          let result := delegatecall(gas, impl, ptr, calldatasize, 0, 0)
          let size := returndatasize
        
          // (3) retrieve return data
          returndatacopy(ptr, 0, size)

          // (4) forward return data back to caller
          switch result
          case 0 { revert(ptr, size) }
          default { return(ptr, size) }
        }
    }
}

/**
 * @title Smart wallet factory
 * @dev Singleton contract responsible for deploying new smart wallet instances
 */
contract Factory {
    
    event Deployed(address indexed addr, address indexed owner);

    modifier onlyRelay {
        RelayRegistry registry = RelayRegistry(0x4360b517f5b3b2D4ddfAEDb4fBFc7eF0F48A4Faa); // Relay Registry address
        require(registry.relays(msg.sender));
        _;
    }

    /**
     * @dev Internal function used for deploying smart wallets using create2
     * @param owner Address of the wallet signer address (external account) associated with the smart wallet
     */
    function deployCreate2(address owner) internal returns (address) {
        bytes memory code = type(Proxy).creationCode;
        address addr;
        assembly {
            // create2
            addr := create2(0, add(code, 0x20), mload(code), owner)
            // revert if contract was not created
            if iszero(extcodesize(addr)) {revert(0, 0)}
        }
        return addr;
    }

    /**
     * @dev Allows a relayer to deploy a smart wallet on behalf of a user
     * @param fee Fee paid from the user's newly deployed smart wallet to the relay
     * @param token Address of token contract for the fee
     * @param deadline Block number deadline for this signed message
     */
    function deployWallet(uint fee, address token, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (address) {
        require(block.number <= deadline);
        address signer = recover(keccak256(abi.encodePacked("deployWallet", msg.sender, token, tx.gasprice, fee, deadline)), v, r, s);
        address addr = deployCreate2(signer);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.initiate(signer, msg.sender, fee, token));
        emit Deployed(addr, signer);
        return addr;
    }
    
    /**
     * @dev Allows a relayer to deploy a smart wallet and send a token transfer on behalf of a user
     * @param fee Fee paid from the user's newly deployed smart wallet to the relay
     * @param token Address of token contract for the fee
     * @param to Transfer recipient address
     * @param value Transfer amount
     * @param deadline Block number deadline for this signed message
     */
    function deployWalletPay(uint fee, address token, address to, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (address addr) {
        require(block.number <= deadline);
        address signer = recover(keccak256(abi.encodePacked("deployWalletPay", msg.sender, token, to, tx.gasprice, fee, value, deadline)), v, r, s);
        addr = deployCreate2(signer);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.initiate(signer, msg.sender, fee, token));
        require(wallet.pay(to, value, token));
        emit Deployed(addr, signer);
    }
    
    /**
     * @dev Allows a user to directly deploy their own smart wallet
     */
    function deployWallet() public returns (address) {
        address addr = deployCreate2(msg.sender);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.initiate(msg.sender));
        emit Deployed(addr, msg.sender);
        return addr;
    }
    
    /**
     * @dev Same as above, but also sends a transfer from the newly-deployed smart wallet
     * @param token Address of the token contract for the transfer
     * @param to Transfer recipient address
     * @param value Transfer amount
     */
    function deployWalletPay(address token, address to, uint value) public returns (address) {
        address addr = deployCreate2(msg.sender);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.pay(to, value, token));
        require(wallet.initiate(msg.sender));
        emit Deployed(addr, msg.sender);
        return addr;
    }
    
    /**
     * @dev Allows user to deploy their wallet and execute a call operation to a foreign contract.
     * @notice The order of wallet.execCall & wallet.initiate is important. It allows the fee to be paid after the execution is finished. This allows collect-call use cases.
     * @param contractAddress Address of the contract to call
     * @param data calldata to send to contractAddress
     */
    function deployWalletExecCall(address contractAddress, bytes memory data) public payable returns (address) {
        address addr = deployCreate2(msg.sender);
        SmartWallet wallet = SmartWallet(uint160(addr));
        if(msg.value > 0) {
            wallet.depositEth.value(msg.value)();
        }
        require(wallet.execCall(contractAddress, data, msg.value));
        require(wallet.initiate(msg.sender));
        emit Deployed(addr, msg.sender);
        return addr;
    }
    
    /**
     * @dev Allows a relayer to deploy a wallet and execute a call operation to a foreign contract on behalf of a user.
     * @param contractAddress Address of the contract to call
     * @param data calldata to send to contractAddress
     * @param msgValue Amount in wei to be sent with the call to the contract from the wallet's balance
     * @param fee Fee paid to the relayer
     * @param token Address of the token contract for the fee
     * @param deadline Block number deadline for this signed message
     */
    function deployWalletExecCall(address contractAddress, bytes memory data, uint msgValue, uint fee, address token, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (address addr) {
        require(block.number <= deadline);
        address signer = recover(keccak256(abi.encodePacked("deployWalletExecCall", msg.sender, token, contractAddress, data, msgValue, tx.gasprice, fee, deadline)), v, r, s);
        addr = deployCreate2(signer);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.execCall(contractAddress, data, msgValue));
        require(wallet.initiate(signer, msg.sender, fee, token));
        emit Deployed(addr, signer);
    }
    
    /**
     * @dev Allows user to deploy their wallet and deploy a new contract through their wallet
     * @param data bytecode of the new contract
     */
    function deployWalletExecCreate(bytes memory data) public returns (address) {
        address addr = deployCreate2(msg.sender);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.execCreate(data));
        require(wallet.initiate(msg.sender));
        emit Deployed(addr, msg.sender);
        return addr;
    }
    
    /**
     * @dev Allows a relayer to deploy a wallet and deploy a new contract through the wallet on behalf of a user.
     * @param data bytecode of the new contract
     * @param fee Fee paid to the relayer
     * @param token Address of the token contract for the fee
     * @param deadline Block number deadline for this signed message
     */
    function deployWalletExecCreate(bytes memory data, uint fee, address token, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (address addr) {
        require(block.number <= deadline);
        address signer = recover(keccak256(abi.encodePacked("deployWalletExecCreate", msg.sender, token, data, tx.gasprice, fee, deadline)), v, r, s);
        addr = deployCreate2(signer);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.execCreate(data));
        require(wallet.initiate(signer, msg.sender, fee, token));
        emit Deployed(addr, signer);
    }
    
    /**
     * @dev Allows user to deploy their wallet and deploy a new contract through their wallet using create2
     * @param data bytecode of the new contract
     * @param salt create2 salt parameter
     */
    function deployWalletExecCreate2(bytes memory data, uint salt) public returns (address) {
        address addr = deployCreate2(msg.sender);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.execCreate2(data, salt));
        require(wallet.initiate(msg.sender));
        emit Deployed(addr, msg.sender);
        return addr;
    }
    
    /**
     * @dev Allows a relayer to deploy a wallet and deploy a new contract through the wallet using create2 on behalf of a user.
     * @param data bytecode of the new contract
     * @param salt create2 salt parameter
     * @param fee Fee paid to the relayer
     * @param token Address of the token contract for the fee
     * @param deadline Block number deadline for this signed message
     */
    function deployWalletExecCreate2(bytes memory data, uint salt, uint fee, address token, uint deadline, uint8 v, bytes32 r, bytes32 s) onlyRelay public returns (address addr) {
        require(block.number <= deadline);
        address signer = recover(keccak256(abi.encodePacked("deployWalletExecCreate2", msg.sender, token, data, tx.gasprice, salt, fee, deadline)), v, r, s);
        addr = deployCreate2(signer);
        SmartWallet wallet = SmartWallet(uint160(addr));
        require(wallet.execCreate2(data, salt));
        require(wallet.initiate(signer, msg.sender, fee, token));
        emit Deployed(addr, signer);
    }

    /**
     * @dev Utility view function that allows clients to fetch a smart wallet address of any signer address
     * @param owner Signer address
     */
    function getCreate2Address(address owner) public view returns (address) {
        bytes32 temp = keccak256(abi.encodePacked(bytes1(0xff), address(this), uint(owner), bytes32(keccak256(type(Proxy).creationCode))));
        address ret;
        uint mask = 2 ** 160 - 1;
        assembly {
            ret := and(temp, mask)
        }
        return ret;
    }
    
    /**
     * @dev Utility view function that allows clients to fetch own smart wallet address
     */
    function getCreate2Address() public view returns (address) {
        return getCreate2Address(msg.sender);
    }
    
    /**
     * @dev Utility view function that allows clients to query whether a signer's smart wallet can be deployed or has already been
     * @param owner Signer address
     */
    function canDeploy(address owner) public view returns (bool inexistent) {
        address wallet = getCreate2Address(owner);
        assembly {
            inexistent := eq(extcodesize(wallet), 0)
        }
    }
    
    /**
     * @dev Utility view function that allows clients to query whether their signer's smart wallet can be deployed or has already been
     */
    function canDeploy() public view returns (bool) {
        return canDeploy(msg.sender);
    }
    
    /**
     * @dev Internal function used to prefix hashes to allow for compatibility with signers such as Metamask
     * @param messageHash Original hash
     */
    function recover(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        bytes memory prefix = "\x19Metacash Signed Message:\n32";
        bytes32 prefixedMessageHash = keccak256(abi.encodePacked(prefix, messageHash));
        return ecrecover(prefixedMessageHash, v, r, s);
    }

}
