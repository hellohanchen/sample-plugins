// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {SingleOwnerPlugin} from "erc6900/reference-implementation/src/plugins/owner/SingleOwnerPlugin.sol";
import {ISingleOwnerPlugin} from "erc6900/reference-implementation/src/plugins/owner/ISingleOwnerPlugin.sol";
import {UpgradeableModularAccount} from "erc6900/reference-implementation/src/account/UpgradeableModularAccount.sol";
import {MSCAFactoryFixture} from "erc6900/reference-implementation/test/mocks/MSCAFactoryFixture.sol";

import {FunctionReference, FunctionReferenceLib} from "erc6900/reference-implementation/src/helpers/FunctionReferenceLib.sol";

import {InheritableOwnershipPlugin} from "../src/testament/InheritableOwnershipPlugin.sol";
import {ITestamentPlugin} from "../src/testament/interfaces/ITestamentPlugin.sol";

contract InheritableOwnershipPluginTest is Test {
    using ECDSA for bytes32;

    SingleOwnerPlugin public ownerPlugin;
    InheritableOwnershipPlugin public inheritableOwnershipPlugin;
    EntryPoint public entryPoint;
    MSCAFactoryFixture public factory;
    UpgradeableModularAccount public account;

    address public owner;
    uint256 public ownerKey;

    address public inheritor;
    uint256 public inheritorKey;

    address payable public beneficiary;

    uint256 public constant CALL_GAS_LIMIT = 150000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 3600000;

    // Event declarations (needed for vm.expectEmit)
    event TestamentExecuted(address indexed account, address indexed inheritor);
    event InheritorAdded(address indexed account, address indexed inheritor);
    event InheritorRemoved(address indexed account, address indexed inheritor);

    function setUp() public {
        ownerPlugin = new SingleOwnerPlugin();
        inheritableOwnershipPlugin = new InheritableOwnershipPlugin();

        entryPoint = new EntryPoint();
        factory = new MSCAFactoryFixture(entryPoint, ownerPlugin);

        (owner, ownerKey) = makeAddrAndKey("owner");
        (inheritor, inheritorKey) = makeAddrAndKey("inheritor");

        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);
        vm.deal(owner, 10 ether);

        // Here, SingleOwnerPlugin already installed in factory
        account = factory.createAccount(owner, 0);

        // Fund the account with some ether
        vm.deal(address(account), 1 ether);

        vm.startPrank(owner);
        FunctionReference[] memory inheritableOwnershipDependency = new FunctionReference[](2);
        inheritableOwnershipDependency[0] = FunctionReferenceLib.pack(
            address(ownerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        inheritableOwnershipDependency[1] = FunctionReferenceLib.pack(
            address(ownerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );

        bytes32 inheritableOwnershipManifestHash = keccak256(abi.encode(inheritableOwnershipPlugin.pluginManifest()));

        uint256 idleTimeLimit = 1;

        bytes memory installPluginCallData = abi.encode(inheritor, idleTimeLimit);

        vm.expectEmit();
        emit ITestamentPlugin.InheritorAdded(address(account), inheritor);

        account.installPlugin({
            plugin: address(inheritableOwnershipPlugin),
            manifestHash: inheritableOwnershipManifestHash,
            pluginInstallData: installPluginCallData,
            dependencies: inheritableOwnershipDependency
        });

        (address[] memory _inheritors) = inheritableOwnershipPlugin.inheritorsOf(address(account));

        assertEq(_inheritors.length, 1);
        assertEq(_inheritors[0], inheritor);
        vm.stopPrank();
    }

    function test_set_inheritor() public {
        address inheritor2 = makeAddr("inheritor2");

        vm.startPrank(address(account));

        (address[] memory _inheritors) = inheritableOwnershipPlugin.inheritors();

        assertEq(_inheritors.length, 1);
        assertEq(_inheritors[0], inheritor);

        vm.expectEmit(true, false, false, true);
        emit ITestamentPlugin.InheritorRemoved(address(account), inheritor);

        inheritableOwnershipPlugin.unsetInheritor();

        (address[] memory _inheritors2) = inheritableOwnershipPlugin.inheritors();
        assertEq(_inheritors2.length, 1);
        assertEq(_inheritors2[0], address(0));

        vm.expectEmit(true, false, false, true);
        emit ITestamentPlugin.InheritorAdded(address(account), inheritor2);
        inheritableOwnershipPlugin.setInheritor(inheritor2, 1);

        (address[] memory _inheritors3) = inheritableOwnershipPlugin.inheritors();
        assertEq(_inheritors3.length, 1);
        assertEq(_inheritors3[0], inheritor2);

        vm.stopPrank();
    }

    function test_execute_testament() public {
        vm.startPrank(address(account));

        (address[] memory _inheritors) = inheritableOwnershipPlugin.inheritors();

        assertEq(_inheritors.length, 1);
        assertEq(_inheritors[0], inheritor);

        vm.stopPrank();

        address thirdParty = makeAddr("thirdParty");
        vm.startPrank(thirdParty);

        address _owner = ISingleOwnerPlugin(address(account)).owner();
        assertEq(_owner, owner);

        // Simulate time passing (warp 1 day ahead)
        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, false, false, true);
        emit ITestamentPlugin.TestamentExecuted(address(account), inheritor);

        ITestamentPlugin(address(account)).executeTestament();
        address _owner2 = ISingleOwnerPlugin(address(account)).owner();
        assertEq(_owner2, inheritor);

        vm.stopPrank();

        vm.startPrank(address(account));

        (address[] memory _inheritors2) = inheritableOwnershipPlugin.inheritors();

        assertEq(_inheritors2.length, 1);
        assertEq(_inheritors2[0], address(0));

        vm.stopPrank();
    }

    function test_execute_testament_userOp() public {
        // Simulate time passing (warp 1 day ahead)
        vm.warp(block.timestamp + 1 days);

        UserOperation[] memory userOps = new UserOperation[](1);

        (, UserOperation memory userOp) = _constructUserOp();
        userOps[0] = userOp;

        vm.expectEmit(true, false, false, true);
        emit ITestamentPlugin.TestamentExecuted(address(account), inheritor);

        entryPoint.handleOps(userOps, beneficiary);

        vm.startPrank(address(account));

        address _owner2 = ISingleOwnerPlugin(address(account)).owner();
        assertEq(_owner2, inheritor);

        (address[] memory _inheritors2) = inheritableOwnershipPlugin.inheritors();

        assertEq(_inheritors2.length, 1);
        assertEq(_inheritors2[0], address(0));

        vm.stopPrank();
    }

    // Internal Function
    function _constructUserOp()
        internal
        view
        returns (bytes32, UserOperation memory)
    {
        bytes memory userOpCallData =
            abi.encodeCall(InheritableOwnershipPlugin.executeTestament, ());

        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: userOpCallData,
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        return (userOpHash, userOp);
    }
}