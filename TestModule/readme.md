# TestModule PowerShell Module
Testing

Version         | Author         | Company             | Copyright
---             | ---            | ---                 | ---
19.3.30.1912 | Dmitry Gancho | Unknown | (c) 2019. All rights reserved.

Help Info : 

[<sub>Back to MODULES</sub>](/../../#toolbox-powershell-modules)

---

# Function List
Name | Aliases | Description
--- | --- | ---
[`Invoke-Parallel`](#invoke-parallel) |  | Invoke ScriptBlock in parallel. Available methods: - Runspace (default). Each instance runs in own Runspace in the same PS instance (multi threaded) - RunspacePool. Each instance runs in own Runspace in a dedicated Runspace Pool in the same PS instance (multi threaded) - RemoteRunspace. Each instance runs in own Runspace in own PS Process (multi processed) - Process. Each instance runs in own PS Process (multi processed) - Job. Each instance runs in own PS Job (multi processed)  NOTES: - Synchronized variables are available in Runspace and RunspacePool modes only.   Supported types are [hashtable], [System.Collections.ArrayList], [System.Collections.Queue] - VMware sdk can run in RemoteRunspace, Process, Job modes only. - OutputFormat and NoCleanup are for Process mode only. - If the scriptblock is too large, it may fail with exception:   Invoke-Parallel : Exception calling "Start" with "0" argument(s): "The filename or extension is too long" - When calling from Invoke-ScheduledCommand -Method Process, use -NoCleanup, otherwise it will hang.
[`Test-Target`](#test-target) | `test`, `tt` | Performs multiply connectivity tests to a target: - ICMP Ping - DNS Resolution (A, AAAA, CNAME, PTR) - Multiply TCP Ports Tests are executed in parallel asyncronously.


---
## Invoke-Parallel


Invoke ScriptBlock in parallel. Available methods:<br/>
- Runspace (default). Each instance runs in own Runspace in the same PS instance (multi threaded)<br/>
- RunspacePool. Each instance runs in own Runspace in a dedicated Runspace Pool in the same PS instance (multi threaded)<br/>
- RemoteRunspace. Each instance runs in own Runspace in own PS Process (multi processed)<br/>
- Process. Each instance runs in own PS Process (multi processed)<br/>
- Job. Each instance runs in own PS Job (multi processed)<br/>
<br/>
NOTES:<br/>
- Synchronized variables are available in Runspace and RunspacePool modes only.<br/>
  Supported types are [hashtable], [System.Collections.ArrayList], [System.Collections.Queue]<br/>
- VMware sdk can run in RemoteRunspace, Process, Job modes only.<br/>
- OutputFormat and NoCleanup are for Process mode only.<br/>
- If the scriptblock is too large, it may fail with exception:<br/>
  Invoke-Parallel : Exception calling "Start" with "0" argument(s): "The filename or extension is too long"<br/>
- When calling from Invoke-ScheduledCommand -Method Process, use -NoCleanup, otherwise it will hang.

<sub>

Author  : Dmitry Gancho

Created : 4/16/2017

Updated : 3/23/2019

</sub>

#### Syntax
```PowerShell
Invoke-Parallel [[-ParameterSet] <Hashtable[]>] -ScriptBlock <ScriptBlock> [-CommonParameterSet <Hashtable>] [-InitializationScript <ScriptBlock>] [-TimeoutMs <UInt32>] [-Method <String>] [-OutputFormat <String>] [-SyncronizedObject <Object>] [-NoCleanup] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Testing.
(Invoke-Parallel -ScriptBlock {Get-Module -ListAvailable}).Count | Should BeGreaterThan 0


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Single-thread, no parameters.
Invoke-Parallel -ScriptBlock {ping google.com}


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Multy-thread, single parameter, single common parameter.
Invoke-Parallel -ScriptBlock {param($name, $qty); ping $name -n $qty} -ParameterSet @{name = 'google.com'}, @{name = 'facebook.com'} -CommonParameterSet @{qty = 2}


-------------------------- EXAMPLE 4 --------------------------
PS C:\># Multy-thread, multy-parameter.
Invoke-Parallel -ScriptBlock {param($name, $qty); ping $name -n $qty} -ParameterSet @{name = 'google.com'; qty = 6}, @{name = 'facebook.com'; qty = 2}


-------------------------- EXAMPLE 5 --------------------------
PS C:\># Multy-thread, with TimeOutMs (one instance will timeout).
Invoke-Parallel -ScriptBlock {param($name, $qty); ping $name -n $qty} -ParameterSet @{name = 'google.com'; qty = 6}, @{name = 'facebook.com'; qty = 2} -TimeOutMs 2000


-------------------------- EXAMPLE 6 --------------------------
PS C:\># Test all streams.
Invoke-Parallel -ScriptBlock {
    [CmdletBinding()] param ()
    '1. Output Stream'      | Write-Output
    '2. Error Stream'       | Write-Error
    '3. Warning Stream'     | Write-Warning
    '4. Debug Stream'       | Write-Debug
    '5. Verbose Stream'     | Write-Verbose
    '6. Information Stream' | % {Write-Information -MessageData $_}
} -Verbose -Debug -ErrorAction Continue -WarningAction Continue -InformationAction Continue


-------------------------- EXAMPLE 7 --------------------------
PS C:\># Use InitializationScript.
Invoke-Parallel -InitializationScript {ipmo VMware.VimAutomation.Core} -ScriptBlock {gmo} -Method Runspace


-------------------------- EXAMPLE 8 --------------------------
PS C:\># Use syncronized [hashtable].
$var = [System.Collections.Hashtable]::new()
Invoke-Parallel -ParameterSet @{}, @{} -ScriptBlock {
    $SyncronizedObject.one ++
} -Method RunspacePool -SyncronizedObject $var
$var
$var = @{one = 0}
Invoke-Parallel -ParameterSet @{}, @{} -ScriptBlock {
    #[System.Threading.Monitor]::Enter($SyncronizedObject) # optional to lock
    $SyncronizedObject.one ++
    #[System.Threading.Monitor]::Exit($SyncronizedObject) # optional to unlock
} -Method RunspacePool -SyncronizedObject $var
$var


-------------------------- EXAMPLE 9 --------------------------
PS C:\># Use syncronized [ArrayList].
$var = [System.Collections.ArrayList]::new()
Invoke-Parallel -ParameterSet @{}, @{} -ScriptBlock {
    [void]$SyncronizedObject.Add('a')
    $SyncronizedObject.Count
} -Method RunspacePool -SyncronizedObject $var
$var


-------------------------- EXAMPLE 10 --------------------------
PS C:\># Use syncronized [Queue].
$var = [System.Collections.Queue]::new()
Invoke-Parallel -ParameterSet @{}, @{} -ScriptBlock {
    $SyncronizedObject.Enqueue($pid)
    $SyncronizedObject.Count
} -Method RunspacePool -SyncronizedObject $var
$var


-------------------------- EXAMPLE 11 --------------------------
PS C:\># Test: First instance should throw, second should complete, third should timeout
Invoke-Parallel -ParameterSet @(
    @{
        target = 'non_existing_domain.c_o_m'
        sleep  = 2
    }
    @{
        target = 'google.com'
        sleep  = 2
    }
    @{
        target = 'www.ctl.io'
        sleep  = 10
    }
) -ScriptBlock {
    param (
        $target,
        $sleep
    )
    [net.dns]::GetHostByName($target).AddressList[0]
    sleep $sleep
} -TimeoutMs 3000 -Method Process -Out Xml
```

#### Related Links<br/>
https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Test-Target
Aliases : `test`, `tt`

Performs multiply connectivity tests to a target:<br/>
- ICMP Ping<br/>
- DNS Resolution (A, AAAA, CNAME, PTR)<br/>
- Multiply TCP Ports<br/>
Tests are executed in parallel asyncronously.

<sub>

Author  : Dmitry Gancho

Created : 3/12/2016

Updated : 3/26/2019

</sub>

#### Syntax
```PowerShell
Test-Target [[-Target] <String[]>] [-PingCount <UInt16>] [-TcpPort <UInt16[]>] [<CommonParameters>]

Test-Target [[-Target] <String[]>] [-PingCount <UInt16>] [-WellKnownTcpPorts] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$res = Test-Target
$res.Ping | select -uniq | Should Be 0


-------------------------- EXAMPLE 2 --------------------------
PS C:\>Test-Target microsoft.com


-------------------------- EXAMPLE 3 --------------------------
PS C:\>Test-Target 8.8.4.4 -Scan
```

#### Related Links<br/>
https://serverfault.com/questions/648424/windows-server-2012-r2-runs-out-of-ephemeral-ports-though-it-shouldnt

[<sub>Back to FUNCTIONS</sub>](#function-list)
