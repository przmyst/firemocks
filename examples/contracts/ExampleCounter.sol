// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ExampleCounter
/// @notice Example contract showcasing two roles with guarded functions.
contract ExampleCounter {
    uint256 private _value;
    address private _admin;
    mapping(address => bool) private _operators;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    event ValueChanged(uint256 newValue, address indexed sender);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event OperatorGranted(address indexed account, address indexed sender);
    event OperatorRevoked(address indexed account, address indexed sender);

    error ExampleCounter__MissingRole(bytes32 role, address account);
    error ExampleCounter__InvalidAccount();

    modifier onlyAdmin() {
        if (msg.sender != _admin) {
            revert ExampleCounter__MissingRole(ADMIN_ROLE, msg.sender);
        }
        _;
    }

    modifier onlyOperator() {
        if (!_operators[msg.sender]) {
            revert ExampleCounter__MissingRole(OPERATOR_ROLE, msg.sender);
        }
        _;
    }

    constructor() {
        _admin = msg.sender;
        _operators[msg.sender] = true;
    }

    /// @notice Returns the address of the contract admin.
    function admin() external view returns (address) {
        return _admin;
    }

    /// @notice Checks if an account currently has a role assigned.
    /// @param role The role identifier to check.
    /// @param account The address whose role membership is being verified.
    function hasRole(bytes32 role, address account) public view returns (bool) {
        if (role == ADMIN_ROLE) {
            return account == _admin;
        }
        if (role == OPERATOR_ROLE) {
            return _operators[account];
        }
        return false;
    }

    /// @notice Checks if an account is authorized to operate the counter.
    /// @param account Address to check.
    function isOperator(address account) external view returns (bool) {
        return hasRole(OPERATOR_ROLE, account);
    }

    /// @notice Transfers admin privileges to a new account.
    /// @param newAdmin Address receiving admin permissions.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) {
            revert ExampleCounter__InvalidAccount();
        }

        address previousAdmin = _admin;
        _admin = newAdmin;

        _operators[newAdmin] = true;

        emit AdminTransferred(previousAdmin, newAdmin);
        emit OperatorGranted(newAdmin, msg.sender);
    }

    /// @notice Grants operator permissions to an account.
    /// @param account Address receiving operator permissions.
    function grantOperator(address account) external onlyAdmin {
        if (account == address(0)) {
            revert ExampleCounter__InvalidAccount();
        }

        if (!_operators[account]) {
            _operators[account] = true;
            emit OperatorGranted(account, msg.sender);
        }
    }

    /// @notice Revokes operator permissions from an account.
    /// @param account Address losing operator permissions.
    function revokeOperator(address account) external onlyAdmin {
        if (account == address(0)) {
            revert ExampleCounter__InvalidAccount();
        }

        if (_operators[account] && account != _admin) {
            _operators[account] = false;
            emit OperatorRevoked(account, msg.sender);
        }
    }

    /// @notice Returns the stored counter value.
    function value() external view returns (uint256) {
        return _value;
    }

    /// @notice Increments the counter by the provided amount.
    /// @param amount The amount to add to the counter.
    function increment(uint256 amount) external onlyOperator {
        _value += amount;
        emit ValueChanged(_value, msg.sender);
    }

    /// @notice Resets the counter back to zero.
    function reset() external onlyAdmin {
        _value = 0;
        emit ValueChanged(_value, msg.sender);
    }
}
