# Microsoft-AV-and-detections




# Table of content
- [Malware naming convention](#Malware-naming-convention)
- [How Microsoft identifies malware and potentially unwanted applications](#How-Microsoft-identifies-malware-and-potentially-unwanted-applications)
- [Microsoft Event ID related to MS Windows Defender](#Microsoft-Event-ID-related-to-MS-Windows-Defender)
- [Understanding Microsoft Malware detail](#Understanding-Microsoft-Malware-detail)
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>


## Malware naming convention

 - [The format](#The-format)
 - [Type](#Type)
 - [Platforms](#Platforms)
 - [Scripting languages](#Scripting-languages)
 - [Macros](#Macros)
 - [Family](#Family)
 - [Variant letter](#Variant-letter)
 - [Suffixes](#Suffixes)

### The format
The format used is the following:
TYPE:Platform/Family.Variant!Suffixes

Example of the format use by Microsoft
![Image](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/images/namingmalware1.png)



### Type
Describes what the malware does on your computer. Worms, viruses, trojans, backdoors, and ransomware are some of the most common types of malware.

-	Adware
-	Backdoor
-	Behavior
-	BrowserModifier
-	Constructor
-	DDoS
-	Exploit
-	Hacktool
-	Joke
-	Misleading
-	MonitoringTool
-	Program
-	PWS
-	Ransom
-	RemoteAccess
-	Rogue
-	SettingsModifier
-	SoftwareBundler
-	Spammer
-	Spoofer
-	Spyware
-	Tool
-	Trojan
-	TrojanClicker
-	TrojanDownloader
-	TrojanNotifier
-	TrojanProxy
-	TrojanSpy
-	VirTool
-	Virus
-	Worm


### Platforms
Indicates the operating system (such as Windows, Mac OS X, and Android) that the malware is designed to work on. The platform is also used to indicate programming languages and file formats.

-	AndroidOS: Android operating system
-	DOS: MS-DOS platform
-	EPOC: Psion devices
-	FreeBSD: FreeBSD platform
-	iPhoneOS: iPhone operating system
-	Linux: Linux platform
-	MacOS: MAC 9.x platform or earlier
-	MacOS_X: MacOS X or later
-	OS2: OS2 platform
-	Palm: Palm operating system
-	Solaris: System V-based Unix platforms
-	SunOS: Unix platforms 4.1.3 or lower
-	SymbOS: Symbian operating system
-	Unix: general Unix platforms
-	Win16: Win16 (3.1) platform
-	Win2K: Windows 2000 platform
-	Win32: Windows 32-bit platform
-	Win64: Windows 64-bit platform
-	Win95: Windows 95, 98 and ME platforms
-	Win98: Windows 98 platform only
-	WinCE: Windows CE platform
-	WinNT: WinNT


### Scripting languages

-	ABAP: Advanced Business Application Programming scripts
-	ALisp: ALisp scripts
-	AmiPro: AmiPro script
-	ANSI: American National Standards Institute scripts
-	AppleScript: compiled Apple scripts
-	ASP: Active Server Pages scripts
-	AutoIt: AutoIT scripts
-	BAS: Basic scripts
-	BAT: Basic scripts
-	CorelScript: Corelscript scripts
-	HTA: HTML Application scripts
-	HTML: HTML Application scripts
-	INF: Install scripts
-	IRC: mIRC/pIRC scripts
-	Java: Java binaries (classes)
-	JS: Javascript scripts
-	LOGO: LOGO scripts
-	MPB: MapBasic scripts
-	MSH: Monad shell scripts
-	MSIL: .Net intermediate language scripts
-	Perl: Perl scripts
-	PHP: Hypertext Preprocessor scripts
-	Python: Python scripts
-	SAP: SAP platform scripts
-	SH: Shell scripts
-	VBA: Visual Basic for Applications scripts
-	VBS: Visual Basic scripts
-	WinBAT: Winbatch scripts
-	WinHlp: Windows Help scripts
-	WinREG: Windows registry scripts


### Macros
-	A97M: Access 97, 2000, XP, 2003, 2007, and 2010 macros
-	HE: macro scripting
-	O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and Powerpoint
-	PP97M: PowerPoint 97, 2000, XP, 2003, 2007, and 2010 macros
-	V5M: Visio5 macros
-	W1M: Word1Macro
-	W2M: Word2Macro
-	W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros
-	WM: Word 95 macros
-	X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros
-	XF: Excel formulas
-	XM: Excel 95 macros
-	Other file types
-	ASX: XML metafile of Windows Media .asf files
-	HC: HyperCard Apple scripts
-	MIME: MIME packets
-	Netware: Novell Netware files
-	QT: Quicktime files
-	SB: StarBasic (Staroffice XML) files
-	SWF: Shockwave Flash files
-	TSQL: MS SQL server files
-	XML: XML files


### Family
Grouping of malware based on common characteristics, including attribution to the same authors. Security software providers sometimes use different names for the same malware family.


### Variant letter
Used sequentially for every distinct version of a malware family. For example, the detection for the variant ".AF" would have been created after the detection for the variant ".AE".


### Suffixes
Provides extra detail about the malware, including how it is used as part of a multicomponent threat. In the example above, "!lnk" indicates that the threat component is a shortcut file used by Trojan:Win32/Reveton.T.
-	.dam: damaged malware
-	.dll: Dynamic Link Library component of a malware
-	.dr: dropper component of a malware
-	.gen: malware that is detected using a generic signature
-	.kit: virus constructor
-	.ldr: loader component of a malware
-	.pak: compressed malware
-	.plugin: plug-in component
-	.remnants: remnants of a virus
-	.worm: worm component of that malware
-	!bit: an internal category used to refer to some threats
-	!cl: an internal category used to refer to some threats
-	!dha: an internal category used to refer to some threats
-	!pfn: an internal category used to refer to some threats
-	!plock: an internal category used to refer to some threats
-	!rfn: an internal category used to refer to some threats
-	!rootkit: rootkit component of that malware
-	@m: worm mailers
-	@mm: mass mailer worm


2020-04-26
https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/malware-naming

<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>

## How Microsoft identifies malware and potentially unwanted applications
- [Malware](#Malware)
-	[Malicious software](#Malicious-software)
-	[Unwanted software](#Unwanted-software)
-	[Lack of choice](#Lack-of-choice)
-	[Lack of control](#Lack-of-control)
-	[Installation and removal](#Installation-and-removal)
-	[Advertising and advertisements](#Advertising-and-advertisements)
-	[Potentially unwanted application (PUA)](#Potentially-unwanted-application-(PUA))


### Malware
Malware is the overarching name for applications and other code, i.e. software, that Microsoft classifies more granularly as malicious software or unwanted software.


### Malicious software
Malicious software is an application or code that compromises user security. Malicious software might steal your personal information, lock your PC until you pay a ransom, use your PC to send spam, or download other malicious software. In general, malicious software tricks, cheats, or defrauds users, places users in vulnerable states, or performs other malicious activities.
Microsoft classifies most malicious software into one of the following categories:
- Backdoor: A type of malware that gives malicious hackers remote access to and control of your PC.
-	Downloader: A type of malware that downloads other malware onto your PC. It needs to connect to the internet to download files.
-	Dropper: A type of malware that installs other malware files onto your PC. Unlike a downloader, a dropper doesn’t need to connect to the internet to drop malicious files. The dropped files are typically embedded in the dropper itself.
-	Exploit: A piece of code that uses software vulnerabilities to gain access to your PC and perform other tasks, such as installing malware. See more information about exploits.
-	Hacktool: A type of tool that can be used to gain unauthorized access to your PC.
-	Macro virus: A type of malware that spreads through infected documents, such as Microsoft Word or Excel documents. The virus is run when you open an infected document.
-	Obfuscator: A type of malware that hides its code and purpose, making it more difficult for security software to detect or remove.
-	Password stealer: A type of malware that gathers your personal information, such as user names and passwords. It often works along with a keylogger, which collects and sends information about the keys you press and websites you visit.
-	Ransomware: A type of malware that encrypts your files or makes other modifications that can prevent you from using your PC. It then displays a ransom note stating you must pay money, complete surveys, or perform other actions before you can use your PC again. See more information about ransomware.
-	Rogue security software: Malware that pretends to be security software but doesn't provide any protection. This type of malware usually displays alerts about nonexistent threats on your PC. It also tries to convince you to pay for its services.
-	Trojan: A type of malware that attempts to appear harmless. Unlike a virus or a worm, a trojan doesn't spread by itself. Instead it tries to look legitimate, tricking users into downloading and installing it. Once installed, trojans perform a variety of malicious activities, such as stealing personal information, downloading other malware, or giving attackers access to your PC.
-	Trojan clicker: A type of trojan that automatically clicks buttons or similar controls on websites or applications. Attackers can use this trojan to click on online advertisements. These clicks can skew online polls or other tracking systems and can even install applications on your PC.
-	Worm: A type of malware that spreads to other PCs. Worms can spread through email, instant messaging, file sharing platforms, social networks, network shares, and removable drives. Sophisticated worms take advantage of software vulnerabilities to propagate.


### Unwanted software
Microsoft believes that you should have control over your Windows experience. Software running on Windows should keep you in control of your PC through informed choices and accessible controls. Microsoft identifies software behaviors that ensure you stay in control. We classify software that does not fully demonstrate these behaviors as "unwanted software".


### Lack of choice
You must be notified about what is happening on your PC, including what software does and whether it is active.
Software that exhibits lack of choice might:
-	Fail to provide prominent notice about the behavior of the software and its purpose and intent.
-	Fail to clearly indicate when the software is active and might also attempt to hide or disguise its presence.
-	Install, reinstall, or remove software without your permission, interaction, or consent.
-	Install other software without a clear indication of its relationship to the primary software.
-	Circumvent user consent dialogs from the browser or operating system.
-	Falsely claim to be software from Microsoft.
Software must not mislead or coerce you into making decisions about your PC. This is considered behavior that limits your choices. In addition to the previous list, software that exhibits lack of choice might:
-	Display exaggerated claims about your PC’s health.
-	Make misleading or inaccurate claims about files, registry entries, or other items on your PC.
-	Display claims in an alarming manner about your PC's health and require payment or certain actions in exchange for fixing the purported issues.
Software that stores or transmits your activities or data must:
-	Give you notice and get consent to do so. Software should not include an option that configures it to hide activities associated with storing or transmitting your data.


### Lack of control
You must be able to control software on your computer. You must be able to start, stop, or otherwise revoke authorization to software.
Software that exhibits lack of control might:
-	Prevent or limit you from viewing or modifying browser features or settings.
-	Open browser windows without authorization.
-	Redirect web traffic without giving notice and getting consent.
-	Modify or manipulate webpage content without your consent.
Software that changes your browsing experience must only use the browser's supported extensibility model for installation, execution, disabling, or removal. Browsers that do not provide supported extensibility models will be considered non-extensible and should not be modified.

### Installation and removal
You must be able to start, stop, or otherwise revoke authorization given to software. Software should obtain your consent before installing, and it must provide a clear and straightforward way for you to install, uninstall, or disable it.
Software that delivers poor installation experience might bundle or download other "unwanted software" as classified by Microsoft.
Software that delivers poor removal experience might:
-	Present confusing or misleading prompts or pop-ups while being uninstalled.
-	Fail to use standard install/uninstall features, such as Add/Remove Programs.


### Advertising and advertisements
Software that promotes a product or service outside of the software itself can interfere with your computing experience. You should have clear choice and control when installing software that presents advertisements.
The advertisements that are presented by software must:
-	Include an obvious way for users to close the advertisement. The act of closing the advertisement must not open another advertisement.
-	Include the name of the software that presented the advertisement.
The software that presents these advertisements must:
-	Provide a standard uninstall method for the software using the same name as shown in the advertisement it presents.
Advertisements shown to you must:
-	Be distinguishable from website content.
-	Not mislead, deceive, or confuse.
-	Not contain malicious code.
-	Not invoke a file download.


### Potentially unwanted application (PUA)
PUA protection aims to safeguard user productivity and ensure enjoyable Windows experiences. This optional protection, available to enterprises, helps deliver more productive, performant, and delightful Windows experiences.
PUAs are not considered malware.
Microsoft uses specific categories and the category definitions to classify software as a PUA.
-	Advertising software: Software that displays advertisements or promotions, or prompts the user to complete surveys for other products or services in software other than itself. This includes software that inserts advertisements to webpages.
-	Torrent software: Software that is used to create or download torrents or other files specifically used with peer-to-peer file-sharing technologies.
-	Cryptomining software: Software that uses your computer resources to mine cryptocurrencies.
-	Bundling software: Software that offers to install other software that is not digitally signed by the same entity. Also, software that offers to install other software that qualify as PUA based on the criteria outlined in this document.
-	Marketing software: Software that monitors and transmits the activities of the user to applications or services other than itself for marketing research.
-	Evasion software: Software that actively tries to evade detection by security products, including software that behaves differently in the presence of security products.
-	Poor industry reputation: Software that trusted security providers detect with their security products. The security industry is dedicated to protecting customers and improving their experiences. Microsoft and other organizations in the security industry continuously exchange knowledge about files we have analyzed to provide users with the best possible protection.

2020-04-27 https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/criteria

<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>

## Microsoft Event ID related to MS Windows Defender

**For Windows 8.1, look into C:\Windows\System32\winevt\Logs\System.evtx

**For Windows 10, look into C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx


| Event ID | Symbolic name | Message |
|------|------------|------------|
| 1000 |	MALWAREPROTECTION_SCAN_STARTED |	An antimalware scan started. |
| 1001 |	MALWAREPROTECTION_SCAN_COMPLETED |	An antimalware scan finished. |
| 1002 |	MALWAREPROTECTION_SCAN_CANCELLED |	An antimalware scan was stopped before it finished. |
| 1004 |	MALWAREPROTECTION_SCAN_RESUMED |	An antimalware scan was resumed. |
| 1005 |	MALWAREPROTECTION_SCAN_FAILED |	An antimalware scan failed. |
| 1006 |	MALWAREPROTECTION_MALWARE_DETECTED |	The antimalware engine found malware or other potentially unwanted software. |
| 1007 |	MALWAREPROTECTION_MALWARE_ACTION_TAKEN |	The antimalware platform performed an action to protect your system from malware or other potentially unwanted software. |
| 1008 |	MALWAREPROTECTION_MALWARE_ACTION_FAILED |	The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed. |
| 1015 |	MALWAREPROTECTION_BEHAVIOR_DETECTED |	The antimalware platform detected suspicious behavior. |
| 1116 |	MALWAREPROTECTION_STATE_MALWARE_DETECTED |	The antimalware platform detected malware or other potentially unwanted software. |
| 1117 |	MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN |	The antimalware platform performed an action to protect your system from malware or other potentially unwanted software. |
| 1118 |	MALWAREPROTECTION_STATE_MALWARE_ACTION_FAILED |	The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed. |
| 1119 |	MALWAREPROTECTION_STATE_MALWARE_ACTION_CRITICALLY_FAILED |	The antimalware platform encountered a critical error when trying to take action on malware or other potentially unwanted software. There are more details in the event message. |
| 1120 |	MALWAREPROTECTION_THREAT_HASH |	Windows Defender Antivirus has deduced the hashes for a threat resource. |
| 1150 |	MALWAREPROTECTION_SERVICE_HEALTHY |	If your antimalware platform reports status to a monitoring platform, this event indicates that the antimalware platform is running and in a healthy state. |
| 1151 |	MALWAREPROTECTION_SERVICE_HEALTH_REPORT |	Endpoint Protection client health report (time in UTC) |
| 2000 |	MALWAREPROTECTION_SIGNATURE_UPDATED |	The antimalware definitions updated successfully. |
| 2001 |	MALWAREPROTECTION_SIGNATURE_UPDATE_FAILED |	The antimalware definition update failed. |
| 2002 |	MALWAREPROTECTION_ENGINE_UPDATED |	The antimalware engine updated successfully. |
| 2004 |	MALWAREPROTECTION_SIGNATURE_REVERSION |	There was a problem loading antimalware definitions. The antimalware engine will attempt to load the last-known good set of definitions. |
| 2010 |	MALWAREPROTECTION_SIGNATURE_FASTPATH_UPDATED |	The antimalware engine used the Dynamic Signature Service to get additional definitions. |
| 2020 |	MALWAREPROTECTION_CLOUD_CLEAN_RESTORE_FILE_DOWNLOADED |	The antimalware engine downloaded a clean file. |
| 2021 |	MALWAREPROTECTION_CLOUD_CLEAN_RESTORE_FILE_DOWNLOAD_FAILED |	The antimalware engine failed to download a clean file. |
| 2040 | MALWAREPROTECTION_OS_EXPIRING |	Antimalware support for this operating system version will soon end. |


2020-04-27  https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus#windows-defender-av-ids


<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>

## Understanding Microsoft Malware detection details
- [Detection Mode](#Detection-Mode)
-	[Threat actions](#Threat-actions)

### Detection Mode
| Detection Mode | Description |
|------|------------|
| User | User initiated. |
| System |	System initiated. |
| Real-time |	Real-time component initiated. |
| IOAV |	IE Downloads and Outlook Express Attachments initiated. |
| NIS |	Network inspection system. |
| IEPROTECT |	IE - IExtensionValidation; this protects against malicious webpage controls. |
| Early Launch Antimalware (ELAM) |	This includes malware detected by the boot sequence. |
| Remote attestation |	Remote attestation. |


### Threat actions
| Actions | Description |
|------|------------|
| Failed |	Endpoint Protection failed to remediate the malware. Check your logs for details of the error. |
| Removed |	Endpoint Protection successfully removed the malware. |
| Quarantined |	Endpoint Protection moved the malware to a secure location and prevented it from running until you remove it or allow it to run. |
| Cleaned |	The malware was cleaned from the infected file. |
| Allowed |	An administrative user selected to allow the software that contains the malware to run. |
| No Action |	Endpoint Protection took no action on the malware. This might occur if the computer is restarted after malware is detected and the malware is no longer detected; for instance, if a mapped network drive on which malware is detected is not reconnected when the computer restarts. |
| Blocked |	Endpoint Protection blocked the malware from running. This might occur if a process on the computer is found to contain malware. |

Source: https://docs.microsoft.com/en-us/sccm/protect/deploy-use/monitor-endpoint-protection
Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus


