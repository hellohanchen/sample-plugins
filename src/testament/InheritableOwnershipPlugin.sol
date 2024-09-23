// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission,
    ManifestExecutionHook
} from "modular-account-libs/interfaces/IPlugin.sol";
import {IStandardExecutor} from "modular-account-libs/interfaces/IStandardExecutor.sol";
import {IPluginExecutor} from "modular-account-libs/interfaces/IPluginExecutor.sol";
import {BasePlugin} from "modular-account-libs/plugins/BasePlugin.sol";
import {SingleOwnerPlugin} from "erc6900/reference-implementation/src/plugins/owner/SingleOwnerPlugin.sol";
import {ISingleOwnerPlugin} from "erc6900/reference-implementation/src/plugins/owner/ISingleOwnerPlugin.sol";
import {ITestamentPlugin} from "./interfaces/ITestamentPlugin.sol";

/// @title Inheritable Ownership Plugin
/// @author MingDynastyVase
/// @notice This plugin depends on SingleOwnerPlugin (developed by ERC-6900 Authors).
/// It supports configuring an EOA or an ERC-1271 smart contract address as the inheritor
/// of this modular account. If the account hasn't been active for a period of time, the inheritor
/// can take full control of this account and transfer ownership to the inheritor.
contract InheritableOwnershipPlugin is BasePlugin, ITestamentPlugin {
    enum FunctionId {
        POST_EXECUTION_HOOK
    }

    string public constant NAME = "Inheritable Single Owner Plugin";
    string public constant VERSION = "0.0.0";
    string public constant AUTHOR = "MingDynastyVase";

    mapping(address => address) internal _inheritors;
    mapping(address => uint256) internal _lastActiveTimestamps;
    mapping(address => uint256) internal _idleTimeLimits;

    bytes4 public constant TRANSFER_OWNERSHIP_SELECTOR = ISingleOwnerPlugin.transferOwnership.selector;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ITestamentPlugin
    function inheritorsOf(address account) external view returns (address[] memory) {
        return _inheritorsOf(account);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ITestamentPlugin
    function executeTestament() external {
        _executeTestament();
    }

    /// @inheritdoc ITestamentPlugin
    function inheritors() external view returns (address[] memory) {
        return _inheritorsOf(msg.sender);
    }

    function refreshActiveTime() public {
        _refreshActiveTime();
    }

    function setInheritor(address inheritor, uint256 idleTimeLimit) public {
        _setInheritor(inheritor, idleTimeLimit);
    }

    function unsetInheritor() public {
        _unsetInheritor();
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Post Execution Hooks   ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function postExecutionHook(uint8 functionId, bytes calldata) external override {
        if (functionId == uint8(FunctionId.POST_EXECUTION_HOOK)) {
            _refreshActiveTime();
            return;
        }

        revert NotImplemented(msg.sig, functionId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {
        (address inheritor, uint256 idleTimeLimit) = abi.decode(data, (address, uint256));

        if (inheritor == address(0) || idleTimeLimit == 0) {
            revert InvalidInheritor();
        }

        _setInheritor(inheritor, idleTimeLimit);
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        _unsetInheritor();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        // depends on ISingleOwnerPlugin
        manifest.dependencyInterfaceIds = new bytes4[](1);
        manifest.dependencyInterfaceIds[0] = type(ISingleOwnerPlugin).interfaceId;

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = TRANSFER_OWNERSHIP_SELECTOR;

        // Execution functions defined in this plugin to be installed on the MSCA.
        manifest.executionFunctions = new bytes4[](5);
        manifest.executionFunctions[0] = this.executeTestament.selector;
        manifest.executionFunctions[1] = this.refreshActiveTime.selector;
        manifest.executionFunctions[2] = this.setInheritor.selector;
        manifest.executionFunctions[3] = this.unsetInheritor.selector;
        manifest.executionFunctions[4] = this.inheritors.selector;

        // user operation
        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Used as first index.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](4);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector : this.executeTestament.selector,
            associatedFunction : ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector : this.refreshActiveTime.selector,
            associatedFunction : ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector : this.setInheritor.selector,
            associatedFunction : ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector : this.unsetInheritor.selector,
            associatedFunction : ownerUserOpValidationFunction
        });

        // runtime
        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory ownerOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // Unused.
            dependencyIndex: 1 // Used as first index.
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](5);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector : this.executeTestament.selector,
            associatedFunction : alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector : this.inheritors.selector,
            associatedFunction : alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector : this.refreshActiveTime.selector,
            associatedFunction : ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector : this.setInheritor.selector,
            associatedFunction : ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector : this.unsetInheritor.selector,
            associatedFunction : ownerOrSelfRuntimeValidationFunction
        });

        // hooks
        manifest.executionHooks = new ManifestExecutionHook[](2);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: IStandardExecutor.execute.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0, // Unused.
                dependencyIndex: 0 // Unused.
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.executionHooks[1] = ManifestExecutionHook({
            executionSelector: IStandardExecutor.executeBatch.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0, // Unused.
                dependencyIndex: 0 // Unused.
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
                dependencyIndex: 0 // Unused.
            })
        });

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[0] = type(ISingleOwnerPlugin).interfaceId;
        manifest.dependencyInterfaceIds[1] = type(ISingleOwnerPlugin).interfaceId;

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;

        // Permission strings
        string memory modifyOwnershipPermission = "Modify Ownership";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: TRANSFER_OWNERSHIP_SELECTOR,
            permissionDescription : modifyOwnershipPermission
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ITestamentPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _inheritorsOf(address account) internal view returns (address[] memory) {
        address inheritor = _inheritors[account];

        address[] memory ihs = new address[](1);
        ihs[0] = inheritor;
        return ihs;
    }

    function _refreshActiveTime() internal {
        if (_inheritors[msg.sender] != address(0)) {
            _lastActiveTimestamps[msg.sender] = block.timestamp;
        }
    }

    function _setInheritor(address inheritor, uint256 idleTimeLimit) internal {
        address account = msg.sender;
        address previousInheritor = _inheritors[account];

        _inheritors[account] = inheritor;
        _idleTimeLimits[account] = idleTimeLimit;

        if (previousInheritor != address(0)) {
            emit InheritorRemoved(account, previousInheritor);
        }
        if (inheritor != address(0)) {
            _refreshActiveTime();
            emit InheritorAdded(account, inheritor);
        }
    }

    function _unsetInheritor() internal {
        _setInheritor(address(0), 0);
    }

    function _executeTestament() internal {
        address account = msg.sender;
        address inheritor = _inheritors[account];

        if (inheritor == address(0)) {
            revert InvalidInheritor();
        }

        if (block.timestamp < _lastActiveTimestamps[account] + _idleTimeLimits[account]) {
            revert NotExecutable();
        }

        bytes memory data = abi.encodeWithSelector(TRANSFER_OWNERSHIP_SELECTOR, inheritor);
        IPluginExecutor(account).executeFromPlugin(data);

        _unsetInheritor();
        emit TestamentExecuted(account, inheritor);
    }
}
