# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).



## Unreleased
#### Added
#### Fixed
#### Removed



## [1.2.0] - 2017-05-22
#### Added
- **[CORE]** Non-interactive mode: new command line interface (`python needle-cli.py`) which allows to completely script Needle 
- **[CORE]** Version checking, to ensure the latest version of Needle is being used
- **[CORE]** Add support for binary thinning
- **[MODULE]** Frida Script: hook all methods of the specified class (`hooking/frida/script_hook-all-methods-of-class`)
- **[MODULE]** Frida Script: hook a particular method of a specific class (`hooking/frida/script_hook-method-of-class`)

#### Fixed
- **[CORE]** Search PID for apps with a space in their name
- **[CORE]** Remove infinite loop from `Retry` decorator, which attempts to restore a connection with the device if it fails
- **[CORE]** Metadata parsing for app extensions
- **[CORE]** Re-added support on iOS for: `storage/data/keychain_dump`, `binary/reversing/strings`, `binary/reversing/class_dump`



## [1.1.0] - 2017-05-05
#### Added
- **[CORE]** Issue Auto-Detection: modules will now automatically detect and keep track of issues in the target app. 
All the issues are going to be stored in the `issues.db` SQLite database, contained in the chosen output directory.
Every issue will hold the following attributes: `app`, `module`, `name`, `content`, `confidence level` ('HIGH', 'MEDIUM', 'INVESTIGATE', 'INFORMATIONAL'), `outfile`
- **[CORE]** New commands: `issues` (list all the issues identified), `add_issue` (manually add an issue to the collection)

- **[CORE]** Frida Attach or Spawn: added option in Frida modules to either attach to or spawn a process
- **[CORE]** New global option: `skip_output_folder_check`. It allows to skip the check that ensures the output folder does not already contain other files
- **[MODULE]** Created the `device` category
- **[MODULE]** Dependency Installer	(`device/dependency_installer`)
- **[MODULE]** MDM Effective User Settings (`mdm/effective_user_settings`) _[from @osimonnet]_

#### Fixed
- **[CORE]** Moved installation of dependencies to its own module (`device/dependency_installer`)
- **[CORE]** Frida support for 32bit devices
- **[CORE]** Automatic reconnection if SSH/Agent connection drops (`Retry` decorator)
- **[CORE]** Re-introduce support for `ipainstaller` (iOS<10)
- **[MODULE]** Compatibility of modules requiring app decryption (iOS 10)

#### Removed
- **[CORE]** `SETUP_DEVICE` global option, in favour of `device/dependency_installer`



## [1.0.2] - 2017-03-21
#### Fixed
- **[AGENT]** Improved communication with the Agent
- **[AGENT]** Replaced `telnetlib` with `asyncore`



## [1.0.1] - 2017-03-15
#### Fixed
- **[AGENT]** Improved communication with the Agent



## [1.0.0] - 2017-03-10
#### Added
- **[AGENT]** Released Needle Agent
- **[CORE]** iOS 10 Support
- **[CORE]** Overhaul of the Core
- **[CORE]** Possibility to disable modules if running incompatible version of iOS
- **[MODULE]** Simple CLI Client (`various/agent_client`)
- **[MODULE]** Frida Jailbreak Detection Bypass (`dynamic/detection/script_jailbreak-detection-bypass.py`) _[from @HenryHoggard]_
- **[MODULE]** Frida Touch Id Bypass (`hooking/frida/script_touch-id-bypass`) _[from @HenryHoggard]_
- **[SUPPORT]** Updated documentation

#### Fixed
- **[MODULE]** Fix `storage/data/keychain_dump_frida` ACL Parsing _[from @bernard-wagner]_
- **[MODULE]** Frida modules spawn app with Frida instead of UIOpen _[from @HenryHoggard]_
- **[MODULE]** Frida enumerate methods performance enhancement _[from @HenryHoggard]_

#### Removed
- **[CORE]** Dependencies superseded by the Needle Agent



## [0.2.0] - 2017-02-16
#### Added
- **[CORE]** Preliminary support for iOS10
- **[CORE]** Support for persisting command history across sessions
- **[CORE]** Improved metadata parsing for extensions
- **[CORE]** Improved issues recognition from metadata
- **[CORE]** Improved plist parsing
- **[CORE]** Star out password _[from @tghosth]_
- **[MODULE]** Frida Script: TLS Pinning Bypass (`hooking/frida/script_pinning_bypass`)
- **[MODULE]** Frida Script: Keychain Dumper (`hooking/frida/script_dump-keychain`) _[from @bernard-wagner]_
- **[MODULE]** Frida Script: iCloud Backups (`hooking/frida/script_documents-backup-attr`) _[from @bernard-wagner]_
- **[MODULE]** Frida Script: Anti Hooking Checks (`hooking/frida/script_anti-hooking-check`) _[from @HenryHoggard]_
- **[MODULE]** Calculate binary checksums (`binary/checksums`) _[from @HenryHoggard]_
- **[MODULE]** Retrieve application container (`storage/data/container`)
- **[MODULE]** Strings: now look also in the application resources (`binary/strings`)
- **[MODULE]** Provisioning profile: Inspect the provisioning profile of the application (`binary/provisioning_profile`)

#### Fixed
- **[CORE]** Modified the organization of modules into packages
- **[CORE]** App metadata: creation of binary path from MobileInstallation.plist
- **[CORE]** Plist wrapper using biplist
- **[CORE]** Multiple plist parsing issues _[from @tghosth]_
- **[CORE]** Paramiko hanging waiting for an EOF _[from @TheBananaStand]_
- **[MODULE]** Frida Script: print view hierarchy (`hooking/frida/script_dump-ui`) _[from @HenryHoggard]_
- **[MODULE]** Improved SQLite DB identification by reducing false positives and false negatives _[from @HenryHoggard]_
- **[MODULE]** Editing with different editors _[from @tghosth]_
- **[MODULE]** Clean storage does not need to require a target

#### Removed
- **[CORE]** Unused dependencies



## [0.1.1] - 2016-11-25
#### Added
- **[CORE]** Support for plist files into print_cmd_output
- **[CORE]** `move` function for Remote operations
- **[CORE]** Automatically install Theos
- **[CORE]** Automatically install SSL Kill Switch
- **[CORE]** Add `validate_editor` (`core/framework/module`)
- **[CORE]** Parametrize `module_run` (`core/framework/module`)
- **[CORE]** Centralized utility for user interaction
- **[MODULE]** Theos integration (`hooking/theos/theos_tweak`)
- **[MODULE]** List installed Tweaks (`hooking/theos/list_tweaks`)
- **[MODULE]** Frida Script: print view hierarchy (`hooking/frida/script_dump-ui`)
- **[MODULE]** Install Burp Proxy CA Certificate (`comms/certs/install_ca_burp`)
- **[MODULE]** Allow using nano to edit hosts file (`various/hosts`) _[from @tghosth]_
- **[MODULE]** Automatically print row counts for standard tables in Cache.db files (`storage/data/files_cachedb`) _[from @tghosth]_
- **[MODULE]** Automatically print row counts for tables in SQL files (`storage/data/files_sql`) _[from @tghosth]_
- **[MODULE]** View Server Certificate (`comms/certs/view_cert`) _[from @tghosth]_
- **[MODULE]** Pull IPA: pull the binary as well as the .ipa file (`binary/pull_ipa`) _[from @tghosth]_

#### Fixed
- **[CORE]** Sanitization of parsed plist files
- **[CORE]** App metadata: show all URI handlers
- **[CORE]** Invalid characters when parsing plist files
- **[CORE]** Minor on Remote Operations' wrapper: `list_dir` and `cat_file`
- **[MODULE]** Dump entire keychain _[idea from @tghosth]_
- **[MODULE]** `storage/caching/screenshot`: OS X support for rendering preview images
- **[MODULE]** Error saving files in `storage/data/files_*` modules _[from @tghosth]_
- **[MODULE]** Run proxy regular even without selecting a target app
- **[MODULE]** File monitoring: automatically detect folder to monitor (regression)



## [0.0.4] - 2016-10-04
#### Added
- **[CORE]** OS X Support
- **[CORE]** iOS 9 compatibility support _[from @ch1kpee]_
- **[CORE]** Global output path
- **[CORE]** Support for SSH public key auth _[from @hduarte]_
- **[MODULE]** Dump contents of keyboard autocomplete cache (`storage/caching/keyboard-autocomplete`) _[from @zakm123]_
- **[MODULE]** Apple Transport Security (ATS) metadata support (`binary/metadata`) _[from @alexplaskett]_
- **[MODULE]** Circumvent Touch ID when implemented using LocalAuthentication framework (`hooking/cycript/cycript_touchid`) _[from @istais]_
- **[MODULE]** `storage/data/files_*`: now is possible to dump all files _[idea from @tghosth]_
- **[MODULE]** Support for App Extension Bundles metadata (`binary/metadata`) _[from @alexplaskett]_
- **[MODULE]** Display an applications universal links (`binary/universal_links`) _[from @alexplaskett]_
- **[MODULE]** Show the content of the device's `/etc/hosts` file, and offer the chance to edit it (`various/hosts`)
- **[SUPPORT]** Contribution guide and module templates
- **[SUPPORT]** ISSUE_TEMPLATE for github
- **[SUPPORT]** Logo and Twitter handle

#### Fixed
- **[CORE]** TCPrelay execute mode permissions
- **[CORE]** Install `coreutils` beforehand
- **[CORE]** Replaced `frida.spawn` with `uiopen`
- **[CORE]** Error on exit and `get_ip` for OS X
- **[CORE]** Fixed 2 bugs related to TCP relay and refresh of the connection parameters _[from @hduarte]_
- **[CORE]** iOS 9.3.3 search pid support inside containers _[from @n1xf1]_
- **[CORE]** Issues with paths containing spaces
- **[MODULE]** Dump keychain even when no apps are installed
- **[MODULE]** Minor edits on module descriptions _[from @tghosth]_
- **[MODULE]** `DTPlatformVersion` exception _[from @alexplaskett]_
- **[MODULE]** Keychain Dump: reverted back to `keychaineditor`
- **[MODULE]** Syslog watch (`dynamic/watch/syslog`) and monitor (`dynamic/monitor/syslog`) not working when using SSH over wi-Fi: switched to `ondeviceconsole`  

#### Removed
- **[CORE]** Dependencies check
- **[CORE]** Dependency to `libimobiledevice`
- **[MODULE]** Unstable modules (`fuzz_ipc`, `lldb_shell`)



## [0.0.3] - 2016-08-12
#### Fixed
- Ported to iOS9
 
## [0.0.2] - 2016-08-11
#### Added
- First Public Release
