```yaml
title: Suspicious File Created Via OneNote Application
id: fcc6d700-68d9-4241-9a1a-06874d621b06
status: experimental
description: Detects suspicious files created via the OneNote application. This could indicate a potential malicious ".one"/".onepkg" file was executed as seen being used in malware activity in the wild
references:
    - https://www.bleepingcomputer.com/news/security/hackers-now-use-microsoft-onenote-attachments-to-spread-malware/
    - https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/
    - https://twitter.com/MaD_c4t/status/1623414582382567424
    - https://labs.withsecure.com/publications/detecting-onenote-abuse
    - https://www.trustedsec.com/blog/new-attacks-old-tricks-how-onenote-malware-is-evolving/
    - https://app.any.run/tasks/17f2d378-6d11-4d6f-8340-954b04f35e83/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/09
modified: 2023/02/27
tags:
    - attack.defense_evasion
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith:
            - '\onenote.exe'
            - '\onenotem.exe'
            - '\onenoteim.exe'
        TargetFilename|contains: '\AppData\Local\Temp\OneNote\'
        TargetFilename|endswith:
            # TODO: Add more suspicious extensions
            - '.bat'
            - '.chm'
            - '.cmd'
            - '.dll'
            - '.exe'
            - '.hta'
            - '.htm'
            - '.html'
            - '.js'
            - '.lnk'
            - '.ps1'
            - '.vbe'
            - '.vbs'
            - '.wsf'
    condition: selection
falsepositives:
    - False positives should be very low with the extensions list cited. Especially if you don't heavily utilize OneNote.
    - Occasional FPs might occur if OneNote is used internally to share different embedded documents
level: high
```

```yaml
title: Suspicious Microsoft OneNote Child Process
id: c27515df-97a9-4162-8a60-dc0eeb51b775
related:
    - id: 438025f9-5856-4663-83f7-52f878a70a50 # Generic rule for suspicious office application child processes
      type: derived
status: experimental
description: Detects suspicious child processes of the Microsoft OneNote application. This may indicate an attempt to execute malicious embedded objects from a .one file.
references:
    - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-e34e43eb5666427602ddf488b2bf3b545bd9aae81af3e6f6c7949f9652abdf18
    - https://micahbabinski.medium.com/detecting-onenote-one-malware-delivery-407e9321ecf0
author: Tim Rauch (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), Elastic (idea)
date: 2022/10/21
modified: 2023/02/10
tags:
    - attack.t1566
    - attack.t1566.001
    - attack.initial_access
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\onenote.exe'
    selection_opt_img:
        - OriginalFileName:
            - 'bitsadmin.exe'
            - 'CertOC.exe'
            - 'CertUtil.exe'
            - 'Cmd.Exe'
            - 'CMSTP.EXE'
            - 'cscript.exe'
            - 'curl.exe'
            - 'HH.exe'
            - 'IEExec.exe'
            - 'InstallUtil.exe'
            - 'javaw.exe'
            - 'Microsoft.Workflow.Compiler.exe'
            - 'msdt.exe'
            - 'MSHTA.EXE'
            - 'msiexec.exe'
            - 'Msxsl.exe'
            - 'odbcconf.exe'
            - 'pcalua.exe'
            - 'PowerShell.EXE'
            - 'RegAsm.exe'
            - 'RegSvcs.exe'
            - 'REGSVR32.exe'
            - 'RUNDLL32.exe'
            - 'schtasks.exe'
            - 'ScriptRunner.exe'
            - 'wmic.exe'
            - 'WorkFolders.exe'
            - 'wscript.exe'
        - Image|endswith:
            - '\AppVLP.exe'
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\certoc.exe'
            - '\certutil.exe'
            - '\cmd.exe'
            - '\cmstp.exe'
            - '\control.exe'
            - '\cscript.exe'
            - '\curl.exe'
            - '\forfiles.exe'
            - '\hh.exe'
            - '\ieexec.exe'
            - '\installutil.exe'
            - '\javaw.exe'
            - '\mftrace.exe'
            - '\Microsoft.Workflow.Compiler.exe'
            - '\msbuild.exe'
            - '\msdt.exe'
            - '\mshta.exe'
            - '\msidb.exe'
            - '\msiexec.exe'
            - '\msxsl.exe'
            - '\odbcconf.exe'
            - '\pcalua.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regasm.exe'
            - '\regsvcs.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\scrcons.exe'
            - '\scriptrunner.exe'
            - '\sh.exe'
            - '\svchost.exe'
            - '\verclsid.exe'
            - '\wmic.exe'
            - '\workfolders.exe'
            - '\wscript.exe'
    selection_opt_explorer:
        Image|endswith: '\explorer.exe'
        CommandLine|contains:
            - '.hta'
            - '.vb'
            - '.wsh'
            - '.js'
            - '.ps'
            - '.scr'
            - '.pif'
            - '.bat'
            - '.cmd'
    selection_opt_paths:
        Image|contains:
            - '\AppData\'
            - '\Users\Public\'
            - '\ProgramData\'
            - '\Windows\Tasks\'
            - '\Windows\Temp\'
            - '\Windows\System32\Tasks\'
    filter_teams:
        Image|endswith: '\AppData\Local\Microsoft\Teams\current\Teams.exe'
        CommandLine|endswith: '-Embedding'
    filter_onedrive:
        Image|contains: '\AppData\Local\Microsoft\OneDrive\'
        Image|endswith: '\FileCoAuth.exe'
        CommandLine|endswith: '-Embedding'
    condition: selection_parent and 1 of selection_opt_* and not 1 of filter_*
falsepositives:
    - File located in the AppData folder with trusted signature
level: high
```
