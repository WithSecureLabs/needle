# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).



## Unreleased
#### Added
#### Fixed
#### Removed



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
- **[MODULE]** Automatically print row counts for standard tables in SQL files (`storage/data/files_cachedb`) _[from @tghosth]_
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
