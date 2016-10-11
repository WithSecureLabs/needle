# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).


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
