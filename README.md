![Needle](https://labs.mwrinfosecurity.com/assets/needle-logo-blue.jpg)

[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2016.svg)](https://www.blackhat.com/us-16/arsenal.html#needle)
[![Black Hat Arsenal](https://rawgit.com/toolswatch/badges/master/arsenal/2017.svg)](https://www.blackhat.com/us-17/arsenal.html#needle)

_Needle_ is an open source, modular framework to streamline the process of conducting security assessments of iOS apps.


# Description

Assessing the security of an iOS application typically requires a plethora of tools, each developed for a specific need and all with different modes of operation and syntax. The Android ecosystem has tools like "[drozer](https://mwr.to/drozer)" that have solved this problem and aim to be a ‘one stop shop’ for the majority of use cases, however iOS does not have an equivalent.

[Needle](https://github.com/mwrlabs/needle) is the MWR's iOS Security Testing Framework, released at Black Hat USA in August 2016. It is an open source modular framework which aims to streamline the entire process of conducting security assessments of iOS applications, and acts as a central point from which to do so.  Needle is intended to be useful not only for security professionals, but also for developers looking to secure their code. A few examples of testing areas covered by Needle include: data storage, inter-process communication, network communications, static code analysis, hooking and binary protections. The only requirement in order to run Needle effectively is a jailbroken device.
	
The release of version 1.0.0 provided a major overhaul of its core and the introduction of a new native agent, written entirely in Objective-C. The new [NeedleAgent](https://github.com/mwrlabs/needle-agent) is an open source iOS app complementary to Needle, that allows to programmatically perform tasks natively on the device, eliminating the need for third party tools. 
	
Needle has been presented at and used by workshops in various international conferences like Black Hat USA/EU, OWASP AppSec and DEEPSEC. It was also included by ToolsWatch in the shortlist for the [Top Security Tools of 2016](http://www.toolswatch.org/2017/02/2016-top-security-tools-as-voted-by-toolswatch-org-readers/), and it is featured in the [OWASP Mobile Testing Guide](https://github.com/OWASP/owasp-mstg).

Needle is open source software, maintained by [MWR InfoSecurity](https://www.mwrinfosecurity.com/).


# Installation

See the [Installation Guide](https://github.com/mwrlabs/needle/wiki/Installation-Guide) in the project Wiki for details.

#### Supported Platforms

* _Workstation_: Needle has been successfully tested on both Kali and macOS
* _Device_: iOS 8, 9, and 10 are currently supported 


# Usage

Usage instructions (for both standard users and contributors) can be found in the [project Wiki](https://github.com/mwrlabs/needle/wiki).


# License

Needle is released under a 3-clause BSD License. See the `LICENSE` file for full details.


# Contact

For news and updates, follow [@mwrneedle](https://twitter.com/mwrneedle) on Twitter and the _[MWR Mobile Tools](http://mobiletools.mwrinfosecurity.com/needle/blog)_ blog.

Feel free to submit issues or ping us on Twitter - [@mwrneedle](https://twitter.com/mwrneedle), [@lancinimarco](https://twitter.com/lancinimarco)
