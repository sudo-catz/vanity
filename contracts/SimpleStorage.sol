// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @notice Allows users to deposit ETH and ERC20 tokens while owner/admin addresses retain full withdrawal control.
/// @dev Includes basic guards to reduce common attack surfaces.
contract SimpleStorage is ReentrancyGuard, EIP712 {
    error NotOwner();
    error NotAdmin();
    error ZeroAmount();
    error ZeroAddress();
    error AlreadyAdmin();
    error NotAdminAccount();
    error CannotRemoveOwner();
    error InsufficientBalance();
    error TransferFailed();
    error UnsupportedOperation();
    error ContractPaused();
    error ContractNotPaused();
    error AccountingMismatch(uint256 contractBalance, uint256 recordedBalance);
    error InsufficientContractBalance(uint256 available);
    error AccountingMismatchToken(address token, uint256 contractBalance, uint256 recordedBalance);
    error TokenBalanceRemaining(address token, uint256 liveBalance, uint256 recordedBalance);
    error TimelockActive(uint256 releaseTime);
    error SignatureExpired();
    error InvalidNonce();
    error InvalidSignature();

    using SafeERC20 for IERC20;

    address public owner;
    mapping(address => bool) private admins;
    mapping(address => uint256) private ethBalances;
    mapping(address => uint256) private ethLifetimeDeposits;
    mapping(address => mapping(address => uint256)) private tokenBalances;
    mapping(address => mapping(address => uint256)) private tokenLifetimeDeposits;
    mapping(address => uint256) private tokenTotals;
    address[] private knownTokens;
    mapping(address => bool) private isKnownToken;
    uint256 private totalBalances;
    uint256 private totalLifetimeDeposits;
    bool private paused;
    address public guardian;
    uint256 public withdrawalTimelock;
    mapping(address => uint256) private nextEthWithdrawalTime;
    mapping(address => mapping(address => uint256)) private nextTokenWithdrawalTime;
    address public withdrawSigner;
    mapping(address => uint256) public nonces;
    bytes32 private constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address account,address token,uint256 amount,uint256 nonce,uint256 deadline)");

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);
    event AdminAdded(address indexed account);
    event AdminRemoved(address indexed account);
    event ERC20Deposited(address indexed token, address indexed account, uint256 amount);
    event ERC20Withdrawn(address indexed token, address indexed account, uint256 amount);
    event EthReconciled(uint256 previousTotal, uint256 newTotal);
    event TokenReconciled(address indexed token, uint256 previousTotal, uint256 newTotal);
    event PausedState(address indexed account);
    event UnpausedState(address indexed account);
    event GuardianUpdated(address indexed previousGuardian, address indexed newGuardian);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TimelockUpdated(uint256 previousDuration, uint256 newDuration);
    event WithdrawSignerUpdated(address indexed previousSigner, address indexed newSigner);
    event SelfDestruct(address indexed target, uint256 balanceForwarded);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyAdmin() {
        if (!admins[msg.sender]) revert NotAdmin();
        _;
    }

    modifier onlyAuthorized() {
        if (msg.sender != owner && !admins[msg.sender]) revert NotAdmin();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier whenPaused() {
        if (!paused) revert ContractNotPaused();
        _;
    }

    constructor() EIP712("SimpleStorage", "1") {
        owner = msg.sender;
        admins[msg.sender] = true;
        emit AdminAdded(msg.sender);
    }

    /// @notice Assigns a guardian who can pause/unpause the contract.
    /// @param newGuardian The address that will be granted guardian rights.
    function setGuardian(address newGuardian) external onlyOwner {
        address previousGuardian = guardian;
        guardian = newGuardian;
        emit GuardianUpdated(previousGuardian, newGuardian);
    }

    /// @notice Sets the off-chain signer address required for withdrawals.
    /// @param newSigner The EOA whose signatures authorize withdrawals. Set to zero to disable signature checks.
    function setWithdrawSigner(address newSigner) external onlyOwner {
        address previousSigner = withdrawSigner;
        withdrawSigner = newSigner;
        emit WithdrawSignerUpdated(previousSigner, newSigner);
    }

    /// @notice Sets the global withdrawal timelock duration.
    /// @param newDuration The delay in seconds before withdrawals are allowed.
    function setWithdrawalTimelock(uint256 newDuration) external whenNotPaused {
        if (msg.sender != guardian) revert NotAdmin();
        uint256 previousDuration = withdrawalTimelock;
        withdrawalTimelock = newDuration;
        emit TimelockUpdated(previousDuration, newDuration);
    }

    /// @notice Pauses deposits and withdrawals during emergencies.
    function pause() external whenNotPaused {
        if (msg.sender != guardian) revert NotAdmin();
        paused = true;
        emit PausedState(msg.sender);
    }

    /// @notice Resumes deposits and withdrawals once the issue is resolved.
    function unpause() external whenPaused {
        if (msg.sender != guardian) revert NotAdmin();
        paused = false;
        emit UnpausedState(msg.sender);
    }

    function _validateSignature(
        address account,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) private {
        if (withdrawSigner == address(0)) {
            return;
        }
        if (deadline < block.timestamp) revert SignatureExpired();

        uint256 currentNonce = nonces[account];
        if (nonce != currentNonce) revert InvalidNonce();

        bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, account, token, amount, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = ECDSA.recover(digest, signature);
        if (recovered != withdrawSigner) revert InvalidSignature();

        nonces[account] = currentNonce + 1;
    }

    function eip712Domain()
        public
        view
        override
        returns (
            bytes1,
            string memory,
            string memory,
            uint256,
            address,
            bytes32,
            uint256[] memory
        )
    {
        revert UnsupportedOperation();
    }

    /// @notice Deposits ETH into the contract and records it against the sender.
    function deposit() external payable whenNotPaused {
        if (msg.value == 0) revert ZeroAmount();
        _recordDeposit(msg.sender, msg.value);
    }

    /// @notice Withdraws a specified amount of ETH to the caller with optional signature authorization.
    /// @param amount The amount of ETH to withdraw.
    /// @param nonce The caller's expected withdrawal nonce.
    /// @param deadline The signature expiration timestamp.
    /// @param signature Off-chain authorization signed by `withdrawSigner`.
    function withdraw(uint256 amount, uint256 nonce, uint256 deadline, bytes calldata signature)
        external
        onlyAuthorized
        nonReentrant
        whenNotPaused
    {
        if (amount == 0) revert ZeroAmount();

        uint256 releaseTime = nextEthWithdrawalTime[msg.sender];
        if (block.timestamp < releaseTime) revert TimelockActive(releaseTime);

        _validateSignature(msg.sender, address(0), amount, nonce, deadline, signature);

        uint256 currentBalance = address(this).balance;
        if (totalBalances > currentBalance) revert AccountingMismatch(currentBalance, totalBalances);
        if (currentBalance < amount) revert InsufficientContractBalance(currentBalance);
        if (totalBalances < amount) revert InsufficientBalance();

        totalBalances -= amount;
        uint256 stored = ethBalances[msg.sender];
        if (stored >= amount) {
            ethBalances[msg.sender] = stored - amount;
        } else {
            ethBalances[msg.sender] = 0;
        }

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawn(msg.sender, amount);

        if (withdrawalTimelock != 0) {
            nextEthWithdrawalTime[msg.sender] = block.timestamp + withdrawalTimelock;
        }
    }

    /// @notice Deposits ERC20 tokens into the contract.
    /// @param token The ERC20 token address.
    /// @param amount The token amount to deposit.
    function depositToken(address token, uint256 amount) external nonReentrant whenNotPaused {
        if (token == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        uint256 preBalance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 postBalance = IERC20(token).balanceOf(address(this));
        uint256 received = postBalance - preBalance;
        if (received == 0) revert ZeroAmount();
        _recordTokenDeposit(msg.sender, token, received);
    }

    /// @notice Withdraws ERC20 tokens to the caller with optional signature authorization.
    /// @param token The ERC20 token address.
    /// @param amount The token amount to withdraw.
    /// @param nonce The caller's expected withdrawal nonce.
    /// @param deadline The signature expiration timestamp.
    /// @param signature Off-chain authorization signed by `withdrawSigner`.
    function withdrawToken(address token, uint256 amount, uint256 nonce, uint256 deadline, bytes calldata signature)
        external
        onlyAuthorized
        nonReentrant
        whenNotPaused
    {
        if (token == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        uint256 releaseTime = nextTokenWithdrawalTime[msg.sender][token];
        if (block.timestamp < releaseTime) revert TimelockActive(releaseTime);

        _validateSignature(msg.sender, token, amount, nonce, deadline, signature);

        uint256 recorded = tokenTotals[token];
        if (recorded == 0) revert InsufficientBalance();

        IERC20 tokenContract = IERC20(token);
        uint256 preBalance = tokenContract.balanceOf(address(this));
        if (recorded > preBalance) revert AccountingMismatchToken(token, preBalance, recorded);
        if (preBalance < amount) revert InsufficientContractBalance(preBalance);

        tokenContract.safeTransfer(msg.sender, amount);

        uint256 postBalance = tokenContract.balanceOf(address(this));
        uint256 actualSent = preBalance - postBalance;
        if (actualSent == 0) revert TransferFailed();
        if (recorded < actualSent) revert InsufficientBalance();

        tokenTotals[token] = recorded - actualSent;

        uint256 stored = tokenBalances[msg.sender][token];
        if (stored >= actualSent) {
            tokenBalances[msg.sender][token] = stored - actualSent;
        } else {
            tokenBalances[msg.sender][token] = 0;
        }

        emit ERC20Withdrawn(token, msg.sender, actualSent);

        if (withdrawalTimelock != 0) {
            nextTokenWithdrawalTime[msg.sender][token] = block.timestamp + withdrawalTimelock;
        }
    }

    /// @notice Returns the cumulative amount deposited by a given account.
    /// @param account The address whose deposits will be returned.
    /// @return The total amount the account has deposited.
    function balanceOf(address account) external view returns (uint256) {
        return ethBalances[account];
    }

    /// @notice Returns the lifetime ETH deposited by an account.
    /// @param account The address whose lifetime deposits will be returned.
    /// @return Total ETH ever deposited by the account.
    function lifetimeEthDeposited(address account) external view returns (uint256) {
        return ethLifetimeDeposits[account];
    }

    /// @notice Returns the lifetime ETH deposited across all accounts.
    /// @return Cumulative ETH deposited into the contract.
    function totalLifetimeEthDeposited() external view returns (uint256) {
        return totalLifetimeDeposits;
    }

    /// @notice Returns the tracked net deposits remaining after withdrawals.
    /// @return Total ETH credited to the contract via deposits minus privileged withdrawals.
    function totalStored() external view returns (uint256) {
        return totalBalances;
    }

    /// @notice Returns the actual ETH balance held by the contract.
    /// @return Current contract ETH balance.
    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Adds a new admin address. Only callable by the owner.
    /// @param account The address that will gain admin permissions.
    function addAdmin(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (admins[account]) revert AlreadyAdmin();

        admins[account] = true;
        emit AdminAdded(account);
    }

    /// @notice Reports whether an address currently has admin permissions.
    /// @param account The address to check.
    /// @return True if the address is an admin.
    function isAdmin(address account) external view returns (bool) {
        return admins[account];
    }

    /// @notice Returns the cumulative amount of a token deposited by an account.
    /// @param account The address to inspect.
    /// @param token The ERC20 token address.
    /// @return The total amount of the token deposited by the account.
    function tokenBalanceOf(address account, address token) external view returns (uint256) {
        return tokenBalances[account][token];
    }

    /// @notice Returns the lifetime amount of a token deposited by an account.
    /// @param account The address to inspect.
    /// @param token The ERC20 token address.
    /// @return Total token amount ever deposited by the account.
    function tokenLifetimeDeposited(address account, address token) external view returns (uint256) {
        return tokenLifetimeDeposits[account][token];
    }

    /// @notice Returns remaining delay before an address can withdraw ETH again.
    /// @param account The address to inspect.
    /// @return Seconds left until the timelock expires (0 if unlocked).
    function ethWithdrawalTimeRemaining(address account) external view returns (uint256) {
        uint256 releaseTime = nextEthWithdrawalTime[account];
        if (releaseTime <= block.timestamp) {
            return 0;
        }
        return releaseTime - block.timestamp;
    }

    /// @notice Returns remaining delay before an address can withdraw a specific token again.
    /// @param account The address to inspect.
    /// @param token The ERC20 token to check.
    /// @return Seconds left until the timelock expires (0 if unlocked).
    function tokenWithdrawalTimeRemaining(address account, address token) external view returns (uint256) {
        uint256 releaseTime = nextTokenWithdrawalTime[account][token];
        if (releaseTime <= block.timestamp) {
            return 0;
        }
        return releaseTime - block.timestamp;
    }

    /// @notice Returns the tracked remaining balance for a token.
    /// @param token The ERC20 token address.
    /// @return Total amount of the token available for withdrawal.
    function totalStoredToken(address token) external view returns (uint256) {
        return tokenTotals[token];
    }

    /// @notice Returns the live token balance held by the contract.
    /// @param token The ERC20 token address.
    /// @return Current token balance held by the contract.
    function contractTokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    /// @notice Transfers ownership to a new account.
    /// @param newOwner The address that will become the contract owner.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();

        address previousOwner = owner;
        owner = newOwner;
        admins[newOwner] = true;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /// @notice Removes an admin. Only callable by the owner.
    /// @param account The address that will lose admin permissions.
    function removeAdmin(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (!admins[account]) revert NotAdminAccount();
        if (account == owner) revert CannotRemoveOwner();

        admins[account] = false;
        emit AdminRemoved(account);
    }

    /// @notice Sends remaining ETH to a target and invokes SELFDESTRUCT.
    /// @dev Post-Shanghai this only forwards ETH; code/storage persist.
    /// @param target The address receiving the forwarded ETH balance.
    function destroy(address payable target) external onlyOwner {
        if (target == address(0)) revert ZeroAddress();

        uint256 balance = address(this).balance;
        if (balance != 0) {
            if (totalBalances > balance) revert AccountingMismatch(balance, totalBalances);
            totalBalances = 0;
        } else if (totalBalances != 0) {
            revert AccountingMismatch(balance, totalBalances);
        }

        uint256 tokensLength = knownTokens.length;
        for (uint256 i = 0; i < tokensLength; ++i) {
            address token = knownTokens[i];
            uint256 liveBalance = IERC20(token).balanceOf(address(this));
            uint256 recorded = tokenTotals[token];
            if (liveBalance != 0 || recorded != 0) {
                revert TokenBalanceRemaining(token, liveBalance, recorded);
            }
        }

        emit SelfDestruct(target, balance);
        selfdestruct(target);
    }

    /// @notice Synchronizes recorded ETH totals with the contract's actual balance.
    /// @dev Useful if ETH is forced into the contract without using deposit().
    function reconcileEth() external onlyOwner {
        uint256 currentBalance = address(this).balance;
        uint256 previousTotal = totalBalances;
        totalBalances = currentBalance;
        emit EthReconciled(previousTotal, currentBalance);
    }

    /// @notice Synchronizes recorded token totals with the contract's actual balance.
    /// @param token The ERC20 token address to reconcile.
    function reconcileToken(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();

        uint256 currentBalance = IERC20(token).balanceOf(address(this));
        uint256 previousTotal = tokenTotals[token];
        tokenTotals[token] = currentBalance;
        if (!isKnownToken[token]) {
            isKnownToken[token] = true;
            knownTokens.push(token);
        }
        emit TokenReconciled(token, previousTotal, currentBalance);
    }

    /// @dev Records a deposit when ETH is sent directly to the contract.
    receive() external payable {
        if (msg.value == 0) revert ZeroAmount();
        _recordDeposit(msg.sender, msg.value);
    }

    /// @dev Fallback intentionally reverts to block unexpected calldata or ether paths.
    fallback() external payable {
        revert UnsupportedOperation();
    }

    function _recordDeposit(address account, uint256 amount) private {
        ethBalances[account] += amount;
        ethLifetimeDeposits[account] += amount;
        totalBalances += amount;
        totalLifetimeDeposits += amount;
        emit Deposited(account, amount);
    }

    function _recordTokenDeposit(address account, address token, uint256 amount) private {
        if (!isKnownToken[token]) {
            isKnownToken[token] = true;
            knownTokens.push(token);
        }

        tokenBalances[account][token] += amount;
        tokenLifetimeDeposits[account][token] += amount;
        tokenTotals[token] += amount;
        emit ERC20Deposited(token, account, amount);
    }
}
