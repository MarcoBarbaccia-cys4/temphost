```yaml
title: Suspicious File Executed By Screensaver File
id: fcee2d25-7dc1-4fc8-ba35-c41ab2b8c0f6
status: experimental
description: Detects the execution of suspicious files executed by ".scr" files.
references:
    - https://attack.mitre.org/techniques/T1546/002/
author: CYS4
date: 2023/09/18
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1546.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '.scr'
        OriginalFileName|endswith:
            - '.exe'
            - '.bat'
    condition: selection
falsepositives:
    - unknown
level: high
```
