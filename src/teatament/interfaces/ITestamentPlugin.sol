// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

interface ITestamentPlugin {
    /// @notice This event is emitted when a testament is executed.
    /// @param account The account whose testament executed.
    /// @param inheritor The address of the inheritor.
    event TestamentExecuted(address indexed account, address indexed inheritor);

    /// @notice This event is emitted when an inheritor is added.
    /// @param account The account whose testament executed.
    /// @param inheritor The address of the inheritor.
    event InheritorAdded(address indexed account, address indexed inheritor);

    /// @notice This event is emitted when an inheritor is removed.
    /// @param account The account whose testament executed.
    /// @param inheritor The address of the inheritor.
    event InheritorRemoved(address indexed account, address indexed inheritor);

    error NotExecutable();

    error InvalidInheritor();

    /// @notice Execute the content defined in this testament.
    /// Considering the testator might not have access to the original wallet/account.
    /// This function can be called by any caller, to help executing this testament.
    function executeTestament() external;

    /// @notice Get the inheritors of the account.
    /// @return The inheritors of the account.
    function inheritors() external view returns (address[]);

    /// @notice Get the inheritors of `account`.
    /// @return The inheritors of the account.
    function inheritorsOf(address account) external view returns (address[]);
}