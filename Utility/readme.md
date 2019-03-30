# Utility PowerShell Module
Collection of general-purpose helper functions

Version         | Author         | Company             | Copyright
---             | ---            | ---                 | ---
19.3.29.1910 | Dmitry Gancho | CenturyLink Cloud | (c) 2019. All rights reserved.

Help Info : https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to MODULES</sub>](/../../#toolbox-powershell-modules)

---

# Function List
Name | Aliases | Description
--- | --- | ---
[`Add-EnvironmentVariableValue`](#add-environmentvariablevalue) |  | Add a value to an environment variable.
[`Add-PSModulePath`](#add-psmodulepath) |  | Add a Path to $env:PSModulePath if not yet there.
[`Clear-Garbage`](#clear-garbage) |  | Invoke garbage collection to release unused memory. This is an expensive operation, takes about a second. Potentially may result in deadlocks. Don't overuse.
[`Compare-ObjectProperty`](#compare-objectproperty) |  | Deep compare PS objects.
[`Compress-ScriptBlock`](#compress-scriptblock) |  | Compress a scriptblock by removing comments, empty lines, trailing and leading spaces. Used in Invoke-Parallel to maximize script payload to PsProcess.
[`ConvertFrom-PSCredential`](#convertfrom-pscredential) |  | Convert from [PSCredential] to plain text [pscustomobject].
[`ConvertTo-Ascii`](#convertto-ascii) |  | Convert string encoding
[`ConvertTo-Base64`](#convertto-base64) |  | Convert string to base64. Used in Http request headers.
[`ConvertTo-HashTable`](#convertto-hashtable) |  | Convert an object to a HashTable
[`ConvertTo-PSCredential`](#convertto-pscredential) | `ctcr` | Convert plain-text UserName and Password to [PSCredential] object.
[`ConvertTo-Regex`](#convertto-regex) |  | Convert string to regex-compatible by prefixing special regex charachters with escape charachter '\'.
[`ConvertTo-Utf8`](#convertto-utf8) |  | Converts an existing file to UTF-8 encoding. Converted file overwrites existing file.
[`Expand-Gzip`](#expand-gzip) |  | Expand gzip file content.
[`Expand-Object`](#expand-object) | `exp`, `expand` | Deep list PS object properties.
[`Find-LinesBetween`](#find-linesbetween) |  | Returns strings from a string array that are between two matching strings
[`Find-MatchingLine`](#find-matchingline) |  | Returns matching strings from a string array
[`Get-ComputerPerformance`](#get-computerperformance) |  | Get average performance data for computer(s).
[`Get-EnvironmentVariable`](#get-environmentvariable) |  | Get environment variable.
[`Get-InvocationLine`](#get-invocationline) |  | Get invocation line in the form: [string]'ModuleName\FunctionName -Param1 Value -Param2 Value..' Used in Write-Progress
[`Get-ObjectDefaultDisplayProperty`](#get-objectdefaultdisplayproperty) |  | Get list of object DefaultDisplayPropery names.
[`Get-ParameterValidValues`](#get-parametervalidvalues) |  | Get valid values for a function parameter. Use inside a function.
[`Get-PerformanceCounter`](#get-performancecounter) |  | Get performance counter data for computer(s).
[`Group-Counter`](#group-counter) |  | Group CounterSets by ComputerName.
[`Invoke-Parallel`](#invoke-parallel) |  | Invoke ScriptBlock in parallel. Available methods: - Runspace (default). Each instance runs in own Runspace in the same PS instance (multi threaded) - RunspacePool. Each instance runs in own Runspace in a dedicated Runspace Pool in the same PS instance (multi threaded) - RemoteRunspace. Each instance runs in own Runspace in own PS Process (multi processed) - Process. Each instance runs in own PS Process (multi processed) - Job. Each instance runs in own PS Job (multi processed)  NOTES: - Synchronized variables are available in Runspace and RunspacePool modes only.   Supported types are [hashtable], [System.Collections.ArrayList], [System.Collections.Queue] - VMware sdk can run in RemoteRunspace, Process, Job modes only. - OutputFormat and NoCleanup are for Process mode only. - If the scriptblock is too large, it may fail with exception:   Invoke-Parallel : Exception calling "Start" with "0" argument(s): "The filename or extension is too long" - When calling from Invoke-ScheduledCommand -Method Process, use -NoCleanup, otherwise it will hang.
[`Invoke-Retry`](#invoke-retry) |  | Invoke a command with retries. Default is 3 retries. Delay is exponential from 1 sec up.
[`Invoke-ScheduledCommand`](#invoke-scheduledcommand) |  | Invoke ScriptBlock at an interval. Used as a workaround in Containers as Scheduled Tasks are not supported.  NOTES: - Output Stream redirected to Information Stream in host instance. - Error Stream redirected to Warning Stream in host instance. - All other Streams are not redirected and received by host instance.
[`Join-Object`](#join-object) |  | Join data from two sets of objects based on a common value
[`New-DynamicParameter`](#new-dynamicparameter) |  | Create RuntimeDefinedParameter object for RuntimeDefinedParameterDictionary. Must be called from DynamicParam {} scriptblock of an advanced function. Begin {} and/or Process {} and/or End {} scriptblocks are mantatory in function body.
[`Out-Clip`](#out-clip) |  | Takes object from pipeline, converts to string and copies to clipboard. The object is passed further down the pipeline intact.
[`Out-Voice`](#out-voice) |  | Outputs string to voice using self-removed background job.
[`Publish-Module`](#publish-module) | `pmo` | Generates module manifest and readme.md for module currently opened in PS ISE. Manifest is based on content of comment_based_help in the beginning of the module. If param Destination is specified, content of the folder is copied to Destination. Files matching '_*.*' are excluded.
[`Register-JobRemove`](#register-jobremove) |  | Remove jobs when state changed. Jobs streams forwarded to Host with switch -ReceiveJob and can not be captured to a variable or pipeline. Used to fire-and-forget background jobs, such as 'Sync-ToolboxCredential'.
[`Register-TabExpansion2`](#register-tabexpansion2) | `rtb` | Register function TabExpansion2.  The script replaces the built-in function TabExpansion2, creates the table TabExpansionOptions, and does nothing else. Initialization is performed on the first code completion via profiles *ArgumentCompleters.ps1.  $TabExpansionOptions consists of empty entries:      CustomArgumentCompleters = @{}     NativeArgumentCompleters = @{}     ResultProcessors = @()     InputProcessors = @()  Initialization via profiles. When TabExpansion2 is called the first time it invokes scripts like *ArgumentCompleters.ps1 found in the path. They add their completers to the options.  TabExpansion2.ps1 (with extension if it is in the path) should be invoked in the beginning of an interactive session. Modules and other tools on loading may check for existence of the table and add their completers.  Any found profile and completer issues are written as silent errors. Examine the variable $Error on troubleshooting.  Extra table options:      IgnoreHiddenShares         $true tells to ignore hidden UNC shares.      LiteralPaths         $true tells to not escape special file characters.      RelativePaths         $true tells to replace paths with relative paths.         $false tells to replace paths with absolute paths.  Consider to use Register-ArgumentCompleter instead of adding completers to options directly. In this case *ArgumentCompleters.ps1 are compatible with v5 native and TabExpansionPlusPlus registrations.  Consider to use Register-InputCompleter and Register-ResultCompleter instead of adding completers to options directly.
[`Remove-EnvironmentVariableValue`](#remove-environmentvariablevalue) |  | Remove a value from an environment variable.
[`Reset-PsPrompt`](#reset-psprompt) |  | Reset PS prompt to default value, such as 'PS C:\> '.
[`Resolve-Target`](#resolve-target) |  | Find a target which responds first: - to ICMP Ping, if no TCP port provided - to TCP port connection request if port is provided.
[`Set-EnvironmentVariable`](#set-environmentvariable) |  | Set environment variable.
[`Set-ObjectDefaultDisplayProperty`](#set-objectdefaultdisplayproperty) |  | Set DefaultDisplayPropery for an object. If Object.PsStandardMembers.DefaultDisplayPropertySet already exists, it's not modified. May be exisiting property or calculated property, see examples.
[`Set-ScriptSignature`](#set-scriptsignature) | `sign` | Digitally sign a PowerShell script with code-signing certificate.
[`Set-TimedJob`](#set-timedjob) |  | Set a self-removed job started by a timer. Jobs streams forwarded to Host with switch -ReceiveJob and can not be captured to a variable or pipeline. Used to start delayed and recurring jobs. Default Interval (delay) is 10 sec. Default Repeat is 1. WARNING: Progress Stream always received.
[`Split-Collection`](#split-collection) |  | Split a collection into chunks.
[`Test-Computer`](#test-computer) |  | Test basic health of a computer.
[`Test-Elevated`](#test-elevated) |  | Test whether current PS session is elevated (aka 'as administrator').
[`Test-EventLog`](#test-eventlog) |  | Test whether EventLog (and EventSouce) exist.
[`Test-Numeric`](#test-numeric) |  | Returns false if value is null, empty or not a number, otherwise it returns true
[`Test-Ping`](#test-ping) | `tping` | Tests for device response to ICMP ping.
[`Test-Target`](#test-target) | `test`, `tt` | Performs multiply connectivity tests to a target: - ICMP Ping - DNS Resolution (A, AAAA, CNAME, PTR) - Multiply TCP Ports Tests are executed in parallel asyncronously.
[`Test-TcpPort`](#test-tcpport) | `tcp` | Tests for device response on a single TCP Port.
[`Write-UsageLog`](#write-usagelog) |  | Logs the current invocation of a function to Elasticsearch


---
## Add-EnvironmentVariableValue


Add a value to an environment variable.

<sub>

Author  : Dmitry Gancho

Created : 1/17/2017

Updated : 1.1

</sub>

#### Syntax
```PowerShell
Add-EnvironmentVariableValue [-Name] <String> [-Scope] {Process | User | Machine} [-Value] <String[]> [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Add-EnvironmentVariableValue -Name ToolboxPaths -Scope $Scope -Value $Path
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Add-PSModulePath


Add a Path to $env:PSModulePath if not yet there.

<sub>

Author  : Dmitry Gancho

Created : 11/20/2015

Updated : 11/20/2015

</sub>

#### Syntax
```PowerShell
Add-PSModulePath [-Path] <String> [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Add-PsModulePath "$env:USERPROFILE\Documents\GitHub\toolbox\Modules" -PassThru
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Clear-Garbage


Invoke garbage collection to release unused memory.<br/>
This is an expensive operation, takes about a second.<br/>
Potentially may result in deadlocks. Don't overuse.

<sub>

Author  : Dmitry Gancho

Created : 11/8/2018

Updated : 11/8/2018

</sub>

#### Syntax
```PowerShell
Clear-Garbage [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Clear-Garbage -Verbose
```

#### Related Links<br/>
https://stackoverflow.com/questions/12265598/is-correct-to-use-gc-collect-gc-waitforpendingfinalizers

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Compare-ObjectProperty


Deep compare PS objects.

<sub>

Author  : Dmitry Gancho

Created : 8/29/2018

Updated : 10/7/2018

</sub>

#### Syntax
```PowerShell
Compare-ObjectProperty [-ReferenceObject] <PSObject> [-DifferenceObject] <PSObject> [-IncludeProperty <String[]>] [-ExcludeProperty <String[]>] [-IncludeEqual] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$ReferenceObject  = Get-Process powershell_ise
$DifferenceObject = Get-Process notepad
Compare-ObjectProperty -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject | ft -a
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Compress-ScriptBlock


Compress a scriptblock by removing comments, empty lines, trailing and leading spaces.<br/>
Used in Invoke-Parallel to maximize script payload to PsProcess.

<sub>

Author  : Dmitry Gancho

Created : 3/31/2018

Updated : 9/25/2018

</sub>

#### Syntax
```PowerShell
Compress-ScriptBlock [-ScriptBlock] <ScriptBlock> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Compress-ScriptBlock -ScriptBlock ${function:Compress-ScriptBlock}


-------------------------- EXAMPLE 2 --------------------------
PS C:\>${function:Compress-ScriptBlock} | Compress-ScriptBlock
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## ConvertFrom-PSCredential


Convert from [PSCredential] to plain text [pscustomobject].

<sub>

Author  : Dmitry Gancho

Created : 10/29/2017

Updated : 10/29/2017

</sub>

#### Syntax
```PowerShell
ConvertFrom-PSCredential [-Credential] <PSCredential> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Import-Credential -FriendlyName T3N | ConvertFrom-PSCredential
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## ConvertTo-Ascii


Convert string encoding

<sub>

Author  : Dmitrty Gancho

Created : 4/6/2015

</sub>

#### Syntax
```PowerShell
ConvertTo-Ascii [-String] <String[]> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>@'
���� ����������
'@ | ConvertTo-Ascii
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## ConvertTo-Base64


Convert string to base64. Used in Http request headers.

<sub>

Author  : Dmitrty Gancho

Created : 8/29/2018

Updated : 8/29/2018

</sub>

#### Syntax
```PowerShell
ConvertTo-Base64 [-String] <String> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$string = "{0}:{1}" -f $Credential.UserName, $Credential.GetNetworkCredential().Password
$string | ConvertTo-Base64
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## ConvertTo-HashTable


Convert an object to a HashTable

<sub>

Convert an object to a HashTable excluding certain types.

For example, ListDictionaryInternal doesn't support serialization therefore can't be converted to JSON.

</sub>

#### Syntax
```PowerShell
ConvertTo-HashTable [-InputObject] <Object> [[-ExcludeTypeName] <String[]>] [[-MaxDepth] <Byte>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$bios = Get-CimInstance -ClassName Win32_Bios
$bios | ConvertTo-HashTable
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## ConvertTo-PSCredential
Aliases : `ctcr`

Convert plain-text UserName and Password to [PSCredential] object.

<sub>

Author  : Dmitry Gancho

Created : 11/29/2016

Updated : 10/29/2017

</sub>

#### Syntax
```PowerShell
ConvertTo-PSCredential [-UserName] <String> [-Password] <String> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>ConvertTo-PSCredential -UserName UserName -Password Password


-------------------------- EXAMPLE 2 --------------------------
PS C:\>[pscustomobject]@{
UserName = 'UserName'
    Password = 'Password'
} | ConvertTo-PSCredential
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## ConvertTo-Regex


Convert string to regex-compatible by prefixing special regex charachters with escape charachter '\'.

<sub>

Author  : Dmitry Gancho

Created : 3/14/2015

</sub>

#### Syntax
```PowerShell
ConvertTo-Regex [-String] <String[]> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>ConvertTo-Regex -String 192.168.1.1
192\.168\.1\.1


-------------------------- EXAMPLE 2 --------------------------
PS C:\>'10.88.10.220','10.88.10.221' | ConvertTo-Regex
192\.168\.1\.1
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## ConvertTo-Utf8


Converts an existing file to UTF-8 encoding.<br/>
Converted file overwrites existing file.

<sub>

Author   : Dmitry Gancho

Last edit: 12/8/2015

</sub>

#### Syntax
```PowerShell
ConvertTo-Utf8 [-Path] <String> [-IncludeBOM] [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>ConvertTo-Utf8 -Path Z:\CTL\Utility\Utility.psd1
```

#### Related Links<br/>
http://www.fileformat.info/info/unicode/utf8.htm

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Expand-Gzip


Expand gzip file content.

<sub>

Author  : Dmitry Gancho

Created : 5/21/2016

</sub>

#### Syntax
```PowerShell
Expand-Gzip [-Path] <String> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Expand Gzip to output stream
Expand-Gzip -Path Z:\config.gzip


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Expand Gzip and save to a file
Expand-Gzip -Path Z:\config.gzip > config.txt
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Expand-Object
Aliases : `exp`, `expand`

Deep list PS object properties.

<sub>

Author  : Dmitry Gancho

Created : 10/7/2018

Updated : 1/8/2018

</sub>

#### Syntax
```PowerShell
Expand-Object [-InputObject] <PSObject[]> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Get-Process powershell_ise | Expand-Object | ft -a
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Find-LinesBetween


Returns strings from a string array that are between two matching strings

<sub>

Author    : Chris Blydenstein

Last edit : 01/28/2016

Version   : 1.0

</sub>

#### Syntax
```PowerShell
Find-LinesBetween [-StringArray] <Array> [-FirstLine] <String> [-LastLine] <String> [-CombineLines] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$myArray = "Erik", "Chris", "Fred", "Jim", "Christopher"
$result = Find-LinesBetween $myArray "Chris" "Christopher"
$result


-------------------------- EXAMPLE 2 --------------------------
PS C:\>$myArray = "Erik", "Chris", "Fred", "Jim", "Christopher"
$result = Find-LinesBetween $myArray "Chris" "Christopher" -CombineLines
$result
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Find-MatchingLine


Returns matching strings from a string array

<sub>

Author    : Chris Blydenstein

Last edit : 01/28/2016

Version   : 1.0

</sub>

#### Syntax
```PowerShell
Find-MatchingLine [-StringArray] <Array> [-SearchForString] <String> [[-BeginSearchAtString] <String>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$myArray = "Erik", "Chris", "Fred", "Christopher"
Find-MatchingLine $myArray "Chris"


-------------------------- EXAMPLE 2 --------------------------
PS C:\>$myArray = "Erik", "Chris", "Fred", "Christopher"
Find-MatchingLine $myArray "Chris" -BeginSearchAtString "Fred"
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Get-ComputerPerformance


Get average performance data for computer(s).

<sub>

Author  : Dmitry Gancho

Created : 5/14/2017

</sub>

#### Syntax
```PowerShell
Get-ComputerPerformance [[-ComputerName] <String[]>] [-Object <String[]>] [-IntervalSec <UInt32>] [-SampleIntervalSec <UInt16>] [-Credential <PSCredential>] [-Summary] [<CommonParameters>]

Get-ComputerPerformance [-IntervalSec <UInt32>] [[-FilePath] <FileInfo>] [-Summary] [<CommonParameters>]

Get-ComputerPerformance [[-SampleSet] <PerformanceCounterSampleSet[]>] [-Summary] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Get performance data from localhost.
Get-ComputerPerformance


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Get performance data from remote computers.
Get-ComputerPerformance -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Get-EnvironmentVariable


Get environment variable.

<sub>

Author  : Dmitry Gancho

Created : 12/19/2016

Updated :

</sub>

#### Syntax
```PowerShell
Get-EnvironmentVariable [[-Name] <String[]>] [[-Scope] {Process | User | Machine}] [-Raw] [-ValueOnly] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Get-EnvironmentVariable


-------------------------- EXAMPLE 2 --------------------------
PS C:\>Get-EnvironmentVariable -Name PsModulePath


-------------------------- EXAMPLE 3 --------------------------
PS C:\>Get-EnvironmentVariable -Scope Machine


-------------------------- EXAMPLE 4 --------------------------
PS C:\>Get-EnvironmentVariable -Name PsModulePath -Scope User -ValueOnly
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Get-InvocationLine


Get invocation line in the form:<br/>
[string]'ModuleName\FunctionName -Param1 Value -Param2 Value..'<br/>
Used in Write-Progress

<sub>

Author  : Dmitry Gancho

Created : 3/25/2017

</sub>

#### Syntax
```PowerShell
Get-InvocationLine [[-Invocation] <InvocationInfo>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Get-InvocationLine
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Get-ObjectDefaultDisplayProperty


Get list of object DefaultDisplayPropery names.

<sub>

Author  : Dmitry Gancho

Created : 3/5/2016

</sub>

#### Syntax
```PowerShell
Get-ObjectDefaultDisplayProperty [-Object] <Object> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$branches = Invoke-GitHubApi -_branches list-branches -owner tier3 -repo toolbox
$branches | Get-ObjectDefaultDisplayProperty
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Get-ParameterValidValues


Get valid values for a function parameter.<br/>
Use inside a function.

<sub>

Author  : Dmitry Gancho

Created : 9/6/2018

Updated : 10/1/2018

</sub>

#### Syntax
```PowerShell
Get-ParameterValidValues [-ParameterMetadata] <ParameterMetadata> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Inside a function:
Get-ParameterValidValues -ParameterMetadata $MyInvocation.MyCommand.Parameters['ParameterName']


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Inside a function:
$MyInvocation.MyCommand.Parameters['ParameterName'] | Get-ParameterValidValues
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Get-PerformanceCounter


Get performance counter data for computer(s).

<sub>

Author  : Dmitry Gancho

Created : 5/14/2017

</sub>

#### Syntax
```PowerShell
Get-PerformanceCounter [[-ComputerName] <String[]>] [-Counter <String[]>] [-SampleInterval <UInt16>] [-MaxSamples <UInt32>] [-Credential <PSCredential>] [-OutFile <String>] [-AsJob] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Get performance data from localhost.
Get-PerformanceCounter


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Get performance data from remote computers.
Get-PerformanceCounter -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Save performance data from remote computers to a PerformanceMonitor-compatible .BLG file.
Get-PerformanceCounter -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01 -OutFile E:\PerfCounter.blg
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Group-Counter


Group CounterSets by ComputerName.

<sub>

Author  : Dmitry Gancho

Created : 5/15/2017

Updated : 9/12/2018

</sub>

#### Syntax
```PowerShell
Group-Counter [-CounterSampleSet] <PerformanceCounterSampleSet[]> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Split Counter Sets from 2 computers.
$counters = @(
    '\Memory\Available Bytes'
    '\Memory\Committed Bytes'
    '\Processor(*)\% Processor Time'
    '\LogicalDisk(*:)\% Free Space'
    '\Process(*)\ID Process'
    '\Process(*)\% Processor Time'
    '\Process(*)\Working Set - Private'
)
$counters = Get-Counter -ComputerName WA1T3NCCNOC01, WA1T3NCCNOC02 -Counter $counters -SampleInterval 2 -MaxSamples 1 -ErrorAction Ignore
$groups   = $counters | Group-Counter | Select-Object -ExpandProperty Samples | Group-Object -Property CounterSetName
$token = Get-CcapiToken
foreach ($group in $groups) {
#        $group.Group | Write-PlatformLog -IndexName test_performance -TypeName $_.Name
    $group.Group | Write-CcApi -IndexName test_performance -TypeName $group.Name -Token $token -Verbose
}
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

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
## Invoke-Retry


Invoke a command with retries.<br/>
Default is 3 retries.<br/>
Delay is exponential from 1 sec up.

<sub>

Author  : Dmitry Gancho

Created : 6/11/2018

Updated : 6/13/2018

</sub>

#### Syntax
```PowerShell
Invoke-Retry [-Command] <String> [[-ParameterSet] <Hashtable>] [-MaxRetry <Byte>] [-RetryIntervalMs <UInt16>] [<CommonParameters>]

Invoke-Retry [-ScriptBlock] <ScriptBlock> [-MaxRetry <Byte>] [-RetryIntervalMs <UInt16>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Using a Command.
Invoke-Retry -Command Get-Module


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Using a scriptblock.
Invoke-Retry -scriptblock {Get-Module}


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Using a scriptblock with variables from the current scope.
$name = 'Tool*'
Invoke-Retry -ScriptBlock {Get-Module -Name $name}


-------------------------- EXAMPLE 4 --------------------------
PS C:\># Using a command with parameterset.
$params = @{
    Name = 'Tool*'
}
Invoke-Retry -Command Get-Module -ParameterSet $params


-------------------------- EXAMPLE 5 --------------------------
PS C:\># Usage with API calls
$params = @{
    Method           = $method
    Uri              = $uri
    Headers          = $headers
    Body             = $body
    TimeoutSec       = $TimeOutSec
    DisableKeepAlive = $true
}
Invoke-Retry -Command Invoke-RestMethod -ParameterSet $params -MaxRetry 5
# OR
Invoke-Retry -ScriptBlock {Invoke-RestMethod @params} -MaxRetry 5
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Invoke-ScheduledCommand


Invoke ScriptBlock at an interval.<br/>
Used as a workaround in Containers as Scheduled Tasks are not supported.<br/>
<br/>
NOTES:<br/>
- Output Stream redirected to Information Stream in host instance.<br/>
- Error Stream redirected to Warning Stream in host instance.<br/>
- All other Streams are not redirected and received by host instance.

<sub>

Author  : Dmitry Gancho

Created : 10/9/2017

Updated : 12/16/2018

</sub>

#### Syntax
```PowerShell
Invoke-ScheduledCommand -ScriptBlock <ScriptBlock> [-ArgumentList <Object[]>] -Interval <TimeSpan> [-StartTime <DateTime>] [-EndTime <DateTime>] [-RunNow] [-RunAsync] [-JobName <String>] [-Passthru] [<CommonParameters>]

Invoke-ScheduledCommand -ScriptBlock <ScriptBlock> [-ArgumentList <Object[]>] -Interval <TimeSpan> [-StartTime <DateTime>] [-RunCount <UInt64>] [-RunNow] [-RunAsync] [-JobName <String>] [-Passthru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Simplest
Invoke-ScheduledCommand -ScriptBlock {'test'} -Interval 0:0:10 -EndTime ([datetime]::Now.AddSeconds(30)) -verbose


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Testing schedule.
Invoke-ScheduledCommand -RunNow -Interval 0:0:1 -EndTime ([datetime]::Now.AddSeconds(5)) -ScriptBlock {
    [datetime]::Now.ToString('HH:mm:ss.fff')
    $timer = $input.Sender
    $timer.Autoreset
}


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Use with Invoke-Parallel -Method Process
$script = {
    Invoke-Parallel -ParameterSet @(
        @{
            target = 'google.com'
        }
    ) -ScriptBlock {
        param (
            $target
        )
        [string][net.dns]::GetHostByName($target).AddressList[0]
    } -TimeoutMs 3000 -Method Process #-Verbose -NoCleanup
}
Invoke-ScheduledCommand -Verbose -InformationAction Continue -ScriptBlock $script -Interval 0:0:5 -EndTime ([datetime]::Now.AddSeconds(7))


-------------------------- EXAMPLE 4 --------------------------
PS C:\># Test all Streams:
$ScriptBlock = {
    '0. Host Message'        | Write-Host -ForegroundColor Yellow
    '1. Output Message'      | Write-Output
    '2. Error Message'       | Write-Error -ErrorAction Continue
    '3. Warning Message'     | Write-Warning
    '4. Debug Message'       | Write-Debug
    '5. Verbose Message'     | Write-Verbose
    '6. Information Message' | % {Write-Information -MessageData $_}
    '7. Progress Message'    | % {Write-Progress -Activity $_}
    "2. Error Action       : $ErrorActionPreference" | Write-Host -fore Magenta
    "3. Warning Action     : $WarningPreference"     | Write-Host -fore Magenta
    "4. Debug Action       : $DebugPreference"       | Write-Host -fore Magenta
    "5. Verbose Action     : $VerbosePreference"     | Write-Host -fore Magenta
    "6. Information Action : $InformationPreference" | Write-Host -fore Magenta
    "7. Progress Action    : $ProgressPreference"    | Write-Host -fore Magenta
}
Invoke-ScheduledCommand -Verbose -Debug -InformationAction Continue -ScriptBlock $ScriptBlock -Interval 0:0:5 -EndTime ([datetime]::Now.AddSeconds(16))


-------------------------- EXAMPLE 5 --------------------------
PS C:\># Test precision, start time 100 years ago. Also randomly skips events due to intentional delay.
$ScriptBlock = {
    1/0
    [datetime]::Now.ToString('HH:mm:ss.fff') | Write-Host -ForegroundColor Yellow
#        $delayMs = Get-Random -Minimum 1000 -Maximum 2500
#        Start-Sleep -Milliseconds $delayMs
}
Invoke-ScheduledCommand `
-ScriptBlock $ScriptBlock `
-Interval    ([timespan]::FromSeconds(1)) `
-StartTime   ([datetime]::Now.AddYears(-100)).Date `
-EndTime     ([datetime]::Now.AddSeconds(10))


-------------------------- EXAMPLE 6 --------------------------
PS C:\># Report $Event values from within the payload script.
Invoke-ScheduledCommand -Interval 0:0:10 -RunCount 2 -ScriptBlock {
    "Signaled : {0}" -f $Event.SourceEventArgs.SignalTime.ToString('HH:mm:ss.fff') | Write-Verbose -Verbose
    "Triggered: {0}" -f $Event.TimeGenerated.ToString('HH:mm:ss.fff')              | Write-Verbose -Verbose
    "Started  : {0}" -f [datetime]::UtcNow.ToString('HH:mm:ss.fff')                | Write-Verbose -Verbose
    icm -cn WA1T3NCCNOC01 {hostname} | Write-Host -fore Yellow
    "Ended    : {0}" -f [datetime]::UtcNow.ToString('HH:mm:ss.fff')                    | Write-Verbose -Verbose
    "Counter  : {0} of {1}" -f $Event.MessageData.Counter, $Event.MessageData.RunCount | Write-Verbose -Verbose
    "Interval : {0}" -f $Event.MessageData.Interval.ToString('d\.hh\:mm\:ss')          | Write-Verbose -Verbose
    "NextRun  : {0}" -f $Event.MessageData.NextRun.ToString('HH:mm:ss.fff')            | Write-Verbose -Verbose
    "EndTime  : {0}" -f $Event.MessageData.EndTime.ToString('HH:mm:ss.fff')            | Write-Verbose -Verbose
    "Timer.IntervalMs: {0}" -f $Event.Sender.Interval               | Write-Verbose -Verbose
    "Timer.Enabled   : {0}" -f $Event.Sender.Enabled                | Write-Verbose -Verbose
    "SourceIdentifier: {0}" -f $Event.SourceIdentifier              | Write-Verbose -Verbose
    $Event | fl * | Out-String
    $Event.SourceEventArgs.SignalTime
    Get-EventSubscriber -SourceIdentifier $Event.SourceIdentifier | fl * | Out-String
} -Verbose
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Join-Object


Join data from two sets of objects based on a common value

<sub>

Join data from two sets of objects based on a common value

For more details, see the accompanying blog post:

http://ramblingcookiemonster.github.io/Join-Object/

For even more details, see the original code and discussions that this borrows from:

Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections

Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

</sub>

#### Syntax
```PowerShell
Join-Object [-Left] <Object[]> [-Right] <Object[]> [-LeftJoinProperty] <String> [-RightJoinProperty] <String> [[-LeftProperties] <Object[]>] [[-RightProperties] <Object[]>] [[-Type] <String>] [[-Prefix] <String>] [[-Suffix] <String>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>#
#Define some input data.
$l = 1..5 | Foreach-Object {
    [pscustomobject]@{
        Name = "jsmith$_"
        Birthday = (Get-Date).adddays(-1)
    }
}
$r = 4..7 | Foreach-Object {
    [pscustomobject]@{
        Department = "Department $_"
        Name = "Department $_"
        Manager = "jsmith$_"
    }
}
#We have a name and Birthday for each manager, how do we find their department, using an inner join?
Join-Object -Left $l -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type OnlyIfInBoth -RightProperties Department
    # Name    Birthday             Department
    # ----    --------             ----------
    # jsmith4 4/14/2015 3:27:22 PM Department 4
    # jsmith5 4/14/2015 3:27:22 PM Department 5


-------------------------- EXAMPLE 2 --------------------------
PS C:\>#
#Define some input data.
$l = 1..5 | Foreach-Object {
    [pscustomobject]@{
        Name = "jsmith$_"
        Birthday = (Get-Date).adddays(-1)
    }
}
$r = 4..7 | Foreach-Object{
    [pscustomobject]@{
        Department = "Department $_"
        Name = "Department $_"
        Manager = "jsmith$_"
    }
}
#We have a name and Birthday for each manager, how do we find all related department data, even if there are conflicting properties?
$l | Join-Object -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type AllInLeft -Prefix j_
    # Name    Birthday             j_Department j_Name       j_Manager
    # ----    --------             ------------ ------       ---------
    # jsmith1 4/14/2015 3:27:22 PM
    # jsmith2 4/14/2015 3:27:22 PM
    # jsmith3 4/14/2015 3:27:22 PM
    # jsmith4 4/14/2015 3:27:22 PM Department 4 Department 4 jsmith4
    # jsmith5 4/14/2015 3:27:22 PM Department 5 Department 5 jsmith5


-------------------------- EXAMPLE 3 --------------------------
PS C:\>#
#Hey!  You know how to script right?  Can you merge these two CSVs, where Path1's IP is equal to Path2's IP_ADDRESS?
#Get CSV data
$s1 = Import-CSV $Path1
$s2 = Import-CSV $Path2
#Merge the data, using a full outer join to avoid omitting anything, and export it
Join-Object -Left $s1 -Right $s2 -LeftJoinProperty IP_ADDRESS -RightJoinProperty IP -Prefix 'j_' -Type AllInBoth |
    Export-CSV $MergePath -NoTypeInformation


-------------------------- EXAMPLE 4 --------------------------
PS C:\>#
# "Hey Warren, we need to match up SSNs to Active Directory users, and check if they are enabled or not.
#  I'll e-mail you an unencrypted CSV with all the SSNs from gmail, what could go wrong?"
# Import some SSNs.
$SSNs = Import-CSV -Path D:\SSNs.csv
#Get AD users, and match up by a common value, samaccountname in this case:
Get-ADUser -Filter "samaccountname -like 'wframe*'" |
    Join-Object -LeftJoinProperty samaccountname -Right $SSNs `
                -RightJoinProperty samaccountname -RightProperties ssn `
                -LeftProperties samaccountname, enabled, objectclass
```

#### Related Links<br/>
http://ramblingcookiemonster.github.io/Join-Object/

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## New-DynamicParameter


Create RuntimeDefinedParameter object for RuntimeDefinedParameterDictionary.<br/>
Must be called from DynamicParam {} scriptblock of an advanced function.<br/>
Begin {} and/or Process {} and/or End {} scriptblocks are mantatory in function body.

<sub>

Author  : Dmitry Gancho

Created : 3/11/2017

</sub>

#### Syntax
```PowerShell
New-DynamicParameter [-Name] <String> [-Alias <String[]>] [-Type <Type>] [-ParameterSetName <String>] [-Position <Byte>] [-HelpMessage <String>] [-HelpMessageBaseName <String>] [-HelpMessageResourceId <String>] [-DefaultValue <Object>] [-ValidateCount <Int32[]>] [-ValidateLength <Int32[]>] [-ValidatePattern <String>] [-ValidateScript <ScriptBlock>] [-ValidateSet <String[]>] [-ValidateRange <Object[]>] [-AllowNull] [-AllowEmptyString] [-AllowEmptyCollection] [-Mandatory] [-ValueFromPipeline] [-ValueFromPipelineByPropertyName] [-ValueFromRemainingArguments] [-DontShow] [-ValidateNotNull] [-ValidateNotNullOrEmpty] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># New-DynamicParameter in an advanced function.
function Test-DynamicParameter {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]$StaticStringParameter,
        [Parameter()]
        [switch]$StaticSwitchParameter
    )
    DynamicParam {
        # create array of dynamic parameters
        $parameters = @(
            New-DynamicParameter -Name DynamicStringParameter
            New-DynamicParameter -Name DynamicSwitchParameter -Type ([switch])
        )
        # add dynamic parameters to dictionary object and return it
        $dictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        $parameters.ForEach{$dictionary.Add($_.Name,$_)}
        $dictionary
    }
    End {
        # create named variables from dictionary of dynamic parameters to use them as usual
        $dictionary.Values.ForEach{Set-Variable -Name $_.Name -Value ($_.Value -as $_.ParameterType) -Force}
        # return variable names and values
        Get-Variable -Name *Parameter -Scope Local
    }
}
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Out-Clip


Takes object from pipeline, converts to string and copies to clipboard.<br/>
The object is passed further down the pipeline intact.

<sub>

Author  : Dmitry Gancho

Created : 17/1/2015

Updated : 3/29/2019

</sub>

#### Syntax
```PowerShell
Out-Clip [[-InputObject] <Object>] [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Get-Process notepad | Out-Clip -Passthru
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Out-Voice


Outputs string to voice using self-removed background job.

<sub>

Author  : Dmitry Gancho, dmitry@ganco.com

Created : 9/16/2016

</sub>

#### Syntax
```PowerShell
Out-Voice [[-Text] <String>] [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Out-Voice -Text 'Hello world'


-------------------------- EXAMPLE 2 --------------------------
PS C:\>'Hello world' | Out-Voice -Passthru
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Publish-Module
Aliases : `pmo`

Generates module manifest and readme.md for module currently opened in PS ISE.<br/>
Manifest is based on content of comment_based_help in the beginning of the module.<br/>
If param Destination is specified, content of the folder is copied to Destination.<br/>
Files matching '_*.*' are excluded.

<sub>

Author  : Dmitry Gancho

Created : 3/31/2017

Updated : 11/18/2018

</sub>

#### Syntax
```PowerShell
Publish-Module [-NoReadme] [<CommonParameters>]

Publish-Module [[-Name] <String>] [-NoReadme] [<CommonParameters>]

Publish-Module [[-ModuleInfo] <PSModuleInfo>] [-NoReadme] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Publish module currently opened in PowerShell_ISE.exe editor.
Publish-Module


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Publish module by Name.
Publish-Module -Name Utility


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Publish imported module.
Get-Module -Name Utility | Publish-Module
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Register-JobRemove


Remove jobs when state changed.<br/>
Jobs streams forwarded to Host with switch -ReceiveJob and can not be captured to a variable or pipeline.<br/>
Used to fire-and-forget background jobs, such as 'Sync-ToolboxCredential'.

<sub>

Author  : Dmitry Gancho

Created : 9/22/2016

Updated :

</sub>

#### Syntax
```PowerShell
Register-JobRemove [-Job] <Job[]> [-ReceiveJob] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Job will be removed when completed without any output.
Start-Job -ScriptBlock {ping google.com} | Register-JobRemove


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Job will be removed when completed with output to Host.
Start-Job -ScriptBlock {ping google.com} | Register-JobRemove -ReceiveJob


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Trace route to google.com from CCNOC servers in a single job.
# Job will be removed when completed with output to Host.
$sessions = Connect-Ccnoc -Wait -PassThru
Invoke-Command -AsJob -Session $sessions -ScriptBlock {trace google.com} | Register-JobRemove -ReceiveJob


-------------------------- EXAMPLE 4 --------------------------
PS C:\># Trace route to google.com from CCNOC servers in individual jobs.
# Jobs will be removed when completed with output to Host.
Connect-Ccnoc -Wait -PassThru | Foreach-Object -Process {
    Invoke-Command -AsJob -Session $_ -JobName $_.Name -ScriptBlock {
        trace google.com
    } | Register-JobRemove -ReceiveJob
}


-------------------------- EXAMPLE 5 --------------------------
PS C:\># Test ping from CCNOC servers to each other CCNOC server.
# Jobs will be removed when completed with output to Host.
Connect-Ccnoc -Wait -PassThru | Foreach-Object -Process {
    Invoke-Command -AsJob -Session $_ -JobName $_.Name -ScriptBlock {
        Test-InfrastructurePing -Type CCNOC | Out-String
} | Register-JobRemove -ReceiveJob}


-------------------------- EXAMPLE 6 --------------------------
PS C:\># Test mtr from CCNOC servers to the same target.
# Jobs will be removed when completed with output to Host.
Connect-Ccnoc -Wait -PassThru | Foreach-Object -Process {
    Invoke-Command -AsJob -Session $_ -JobName $_.Name -ScriptBlock {
        Invoke-Mtr -Target 8.22.8.80 -DataCenter $env:COMPUTERNAME.Substring(0,3)
    } | Register-JobRemove -ReceiveJob
}


-------------------------- EXAMPLE 7 --------------------------
PS C:\># Test all output streams
Start-Job -ScriptBlock {
    # 1   Success output
    # 2   Errors
    # 3   Warning messages
    # 4   Verbose output
    # 5   Debug messages
    # 6   Informational messages
    $ErrorActionPreference = 'Continue'
    $WarningPreference = 'Continue'
    $DebugPreference = 'Continue'
    $InformationPreference = 'Continue'
    Write-Host -Object "`nHOST Message" -ForegroundColor Magenta
    Write-Output -InputObject 'OUTPUT Stream (1)'
    Write-Error -Message 'ERROR Stream (2)'
    Write-Warning -Message 'WARNING Stream (3)'
    Write-Verbose -Message 'VERBOSE Stream (4)' -Verbose
    Write-Debug -Message 'DEBUG Stream (5)'
    Write-Information -MessageData 'INFORMATION Stream (6)'
    Write-Progress -Activity 'PROGRESS Stream'
} | Register-JobRemove -ReceiveJob


-------------------------- EXAMPLE 8 --------------------------
PS C:\># Six ways to invoke the same script and inherit environment pereferences
$script = {
    $VerbosePreference      = $args[2]
    $ErrorActionPereference = $args[3]
    $args[0..1] -join ' ' | Write-Verbose -Verbose
}
$argumentList = 'Hello', 'World', $VerbosePreference, $ErrorActionPereference
# In the current scope (same as dot-source .{})
Invoke-Command -ScriptBlock $script -ArgumentList $argumentList -NoNewScope
# In new not-child scope (same as &{})
Invoke-Command -ScriptBlock $script -ArgumentList $argumentList
# On remote machine
Invoke-Command -ScriptBlock $script -ArgumentList $argumentList -ComputerName WA1T3NCCNOC01
# In an immediate job (blocking)
Start-Job -ScriptBlock $script -ArgumentList $argumentList | Receive-Job -Wait -AutoRemoveJob
# In an immediate job (not blocking)
Start-Job -ScriptBlock $script -ArgumentList $argumentList | Register-JobRemove -ReceiveJob
# In a scheduled job (not blocking)
Set-TimedJob -ScriptBlock $script -ArgumentList $argumentList -Interval 10 -ReceiveJob
```

#### Related Links<br/>
https://blogs.technet.microsoft.com/heyscriptingguy/2011/06/17/manage-event-subscriptions-with-powershell/

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Register-TabExpansion2
Aliases : `rtb`

Register function TabExpansion2.<br/>
<br/>
The script replaces the built-in function TabExpansion2, creates the table<br/>
TabExpansionOptions, and does nothing else. Initialization is performed on<br/>
the first code completion via profiles *ArgumentCompleters.ps1.<br/>
<br/>
$TabExpansionOptions consists of empty entries:<br/>
<br/>
    CustomArgumentCompleters = @{}<br/>
    NativeArgumentCompleters = @{}<br/>
    ResultProcessors = @()<br/>
    InputProcessors = @()<br/>
<br/>
Initialization via profiles. When TabExpansion2 is called the first time it<br/>
invokes scripts like *ArgumentCompleters.ps1 found in the path. They add<br/>
their completers to the options.<br/>
<br/>
TabExpansion2.ps1 (with extension if it is in the path) should be invoked<br/>
in the beginning of an interactive session. Modules and other tools on<br/>
loading may check for existence of the table and add their completers.<br/>
<br/>
Any found profile and completer issues are written as silent errors.<br/>
Examine the variable $Error on troubleshooting.<br/>
<br/>
Extra table options:<br/>
<br/>
    IgnoreHiddenShares<br/>
        $true tells to ignore hidden UNC shares.<br/>
<br/>
    LiteralPaths<br/>
        $true tells to not escape special file characters.<br/>
<br/>
    RelativePaths<br/>
        $true tells to replace paths with relative paths.<br/>
        $false tells to replace paths with absolute paths.<br/>
<br/>
Consider to use Register-ArgumentCompleter instead of adding completers to<br/>
options directly. In this case *ArgumentCompleters.ps1 are compatible with<br/>
v5 native and TabExpansionPlusPlus registrations.<br/>
<br/>
Consider to use Register-InputCompleter and Register-ResultCompleter<br/>
instead of adding completers to options directly.

<sub>

Author  : Roman Kuzmin

Updated : Dmitry Gancho, 3/5/2017

</sub>

#### Syntax
```PowerShell
Register-TabExpansion2 [-ClearCache] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Register-TabExpansion2
```

#### Related Links<br/>
wiki https://github.com/nightroman/FarNet/wiki/TabExpansion2<br/>
https://www.powershellgallery.com/packages/TabExpansion2

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Remove-EnvironmentVariableValue


Remove a value from an environment variable.

<sub>

Author  : Dmitry Gancho

Created : 3/11/2017

Updated : 1.1

</sub>

#### Syntax
```PowerShell
Remove-EnvironmentVariableValue [-Name] <String> [-Scope] {Process | User | Machine} [-Value] <String[]> [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Remove-EnvironmentVariableValue -Name Path -Value *\Toolbox\* -Scope Process
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Reset-PsPrompt


Reset PS prompt to default value, such as 'PS C:\> '.

<sub>

Author  : Dmitry Gancho

Created : 2/28/2017

Updated :

</sub>

#### Syntax
```PowerShell
Reset-PsPrompt [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Reset-PsPrompt
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Resolve-Target


Find a target which responds first:<br/>
- to ICMP Ping, if no TCP port provided<br/>
- to TCP port connection request if port is provided.

<sub>

Author  : Dmitry Gancho

Created : 2/9/2018

Updated :

</sub>

#### Syntax
```PowerShell
Resolve-Target [[-Target] <String[]>] [-TcpPort <UInt16>] [-TimeoutMs <UInt16>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Resolve-Target -Target T3N.dom


-------------------------- EXAMPLE 2 --------------------------
PS C:\>Resolve-Target -Target T3N.dom -TcpPort 5985 -Verbose


-------------------------- EXAMPLE 3 --------------------------
PS C:\>Resolve-Target -Target ccmssql -TcpPort 1433 -TimeoutMs 1000
```

#### Related Links<br/>
https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/<br/>
https://learn-powershell.net/2016/02/14/another-way-to-get-output-from-a-powershell-runspace/

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Set-EnvironmentVariable


Set environment variable.

<sub>

Author  : Dmitry Gancho

Created : 3/11/2017

Updated :

</sub>

#### Syntax
```PowerShell
Set-EnvironmentVariable [-Name] <String> [-Scope] {Process | User | Machine} [-Default] [-PassThru] [<CommonParameters>]

Set-EnvironmentVariable [-Name] <String> [-Scope] {Process | User | Machine} [-Value] <String[]> [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># reset PsModulePath to default value.
Set-EnvironmentVariable -Name PsModulePath -default


-------------------------- EXAMPLE 2 --------------------------
PS C:\># remove the variable
Set-EnvironmentVariable -Name ToolboxPath -Scope Process -Value '' -PassThru
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Set-ObjectDefaultDisplayProperty


Set DefaultDisplayPropery for an object.<br/>
If Object.PsStandardMembers.DefaultDisplayPropertySet already exists, it's not modified.<br/>
May be exisiting property or calculated property, see examples.

<sub>

Author  : Dmitry Gancho

Created : 3/5/2016

</sub>

#### Syntax
```PowerShell
Set-ObjectDefaultDisplayProperty -Object <Object[]> [-PropertyName] <String[]> [-PassThru] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Display Name and Sha of the latest commit of GitHub repo branches.
$branches = Invoke-GitHubApi -_branches list-branches -owner tier3 -repo toolbox
$branches | Select-Object -Property *, @{Name = 'Sha'; Expression = {$_.commit.sha}} | Set-ObjectDefaultDisplayProperty Name, Sha -PassThru
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Set-ScriptSignature
Aliases : `sign`

Digitally sign a PowerShell script with code-signing certificate.

<sub>

Author  : Dmitry Gancho

Created : 2/14/2016

</sub>

#### Syntax
```PowerShell
Set-ScriptSignature -Path <String> -Certificate <X509Certificate2> [<CommonParameters>]

Set-ScriptSignature -Path <String> -CertificateSerialNumber <String> [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Sign module and module manifest scrip files.
Set-ScriptSignature -Path "$HOME\Documents\toolbox\Modules\ClcControl\ClcControl.psm1" -CertificateSerialNumber 01C685F0348E17E57ABF24E8FD6AFDDF
Set-ScriptSignature -Path "$HOME\Documents\toolbox\Modules\ClcControl\ClcControl.psd1" -CertificateSerialNumber 01C685F0348E17E57ABF24E8FD6AFDDF
```

#### Related Links<br/>
http://www.hanselman.com/blog/SigningPowerShellScripts.aspx

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Set-TimedJob


Set a self-removed job started by a timer.<br/>
Jobs streams forwarded to Host with switch -ReceiveJob and can not be captured to a variable or pipeline.<br/>
Used to start delayed and recurring jobs.<br/>
Default Interval (delay) is 10 sec. Default Repeat is 1.<br/>
WARNING: Progress Stream always received.

<sub>

Author  : Dmitry Gancho

Created : 9/23/2016

</sub>

#### Syntax
```PowerShell
Set-TimedJob [-ScriptBlock] <ScriptBlock> [[-ArgumentList] <Object[]>] [[-Interval] <UInt16>] [[-Repeat] <UInt64>] [-ReceiveJob] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Ping google.com twice and receive output.
Set-TimedJob -ScriptBlock {ping google.com} -Repeat 2 -ReceiveJob


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Ping google.com twice and receive output.
Set-TimedJob -ScriptBlock {ping $args[0] -n $args[1]} -ArgumentList google.com, 2 -Repeat 2 -ReceiveJob


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Set PS window title to current time and repeat 10 times.
Set-TimedJob -Repeat 10 -ScriptBlock {$Host.UI.RawUI.set_WindowTitle([datetime]::Now.ToString('G'))}


-------------------------- EXAMPLE 4 --------------------------
PS C:\># Test all output streams
Set-TimedJob -ScriptBlock {
    # 1   Success output
    # 2   Errors
    # 3   Warning messages
    # 4   Verbose output
    # 5   Debug messages
    # 6   Informational messages
    $ErrorActionPreference = 'Continue'
    $WarningPreference = 'Continue'
    $DebugPreference = 'Continue'
    $InformationPreference = 'Continue'
    Write-Host -Object "`nHOST Message" -ForegroundColor Magenta
    Write-Output -InputObject 'OUTPUT Stream (1)'
    Write-Error -Message 'ERROR Stream (2)'
    Write-Warning -Message 'WARNING Stream (3)'
    Write-Verbose -Message 'VERBOSE Stream (4)' -Verbose
    Write-Debug -Message 'DEBUG Stream (5)'
    Write-Information -MessageData 'INFORMATION Stream (6)'
    Write-Progress -Activity 'PROGRESS Stream'
} -ReceiveJob
```

#### Related Links<br/>
https://blogs.technet.microsoft.com/heyscriptingguy/2011/06/17/manage-event-subscriptions-with-powershell/

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Split-Collection


Split a collection into chunks.

<sub>

Author  : Dmitry Gancho

Created : 12/18/2017

Updated : 5/10/2018

</sub>

#### Syntax
```PowerShell
Split-Collection [-Collection] <Array> [-Count <UInt16>] [<CommonParameters>]

Split-Collection [-Collection] <Array> [-Size <UInt16>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>$r = 1 .. 2 | Split-Collection -Count 1
$r.Count


-------------------------- EXAMPLE 2 --------------------------
PS C:\>$r = 1 .. 10 | Split-Collection -Size 3
$r.Count


-------------------------- EXAMPLE 3 --------------------------
PS C:\>$r = 1 .. 10 | Split-Collection -Count 3
$r.Count
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Test-Computer


Test basic health of a computer.

<sub>

Author  : Dmitry Gancho

Created : 4/17/2017

Updated : 3/30/2018

</sub>

#### Syntax
```PowerShell
Test-Computer [[-ComputerName] <String[]>] [-Credential <PSCredential>] [-TimeOutSec <Byte>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\># Test localhost.
Test-Computer


-------------------------- EXAMPLE 2 --------------------------
PS C:\># Test remote computers.
Test-Computer -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Test-Elevated


Test whether current PS session is elevated (aka 'as administrator').

<sub>

Author  : Dmitry Gancho

Created : 7/5/2014

Updated :

</sub>

#### Syntax
```PowerShell
Test-Elevated [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Test-Elevated
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Test-EventLog


Test whether EventLog (and EventSouce) exist.

<sub>

Author  : Dmitry Gancho

Created : 5/24/2017

</sub>

#### Syntax
```PowerShell
Test-EventLog [[-LogName] <String>] [[-Source] <String>] [[-ComputerName] <String>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Test-EventLog -EventLog Toolbox


-------------------------- EXAMPLE 2 --------------------------
PS C:\>Test-EventLog -EventLog Toolbox -EventSource test_source
```



[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Test-Numeric


Returns false if value is null, empty or not a number, otherwise it returns true

<sub>

Author    : Chris Blydenstein

Last edit : 01/28/2016

Version   : 1.0

</sub>

#### Syntax
```PowerShell
Test-Numeric [[-Value] <String>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Test-Numeric "ABC"


-------------------------- EXAMPLE 2 --------------------------
PS C:\>Test-Numeric "123"
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Test-Ping
Aliases : `tping`

Tests for device response to ICMP ping.

<sub>

Author  : Dmitry Gancho

Created : 6/18/2017

Updated : 11/13/2018

</sub>

#### Syntax
```PowerShell
Test-Ping [[-ComputerName] <String>] [-TimeOutMs <UInt16>] [-Count <Byte>] [-IntervalMs <UInt16>] [-Mode <String>] [-PacketSize <UInt16>] [-DontFragment] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Test-Ping facebook.com -TimeOutMs 10 -Count 100 -IntervalMs 50 -Mode And


-------------------------- EXAMPLE 2 --------------------------
PS C:\>Test-Ping facebook.com -TimeOutMs 10 -Count 100 -IntervalMs 50 -Mode Or


-------------------------- EXAMPLE 3 --------------------------
PS C:\># Max packet size when MTU = 1500
Test-Ping google.com -PacketSize 1473 -DontFragment -Verbose
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

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

---
## Test-TcpPort
Aliases : `tcp`

Tests for device response on a single TCP Port.

<sub>

Author  : Dmitry Gancho

Created : 6/19/2017

Updated : 6/14/2018

</sub>

#### Syntax
```PowerShell
Test-TcpPort [[-ComputerName] <String[]>] [[-TcpPort] <UInt16>] [[-TimeOutMs] <UInt16>] [-RetryCount <Byte>] [-RetryIntervalMs <UInt16>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Test-TCPPort facebook.com


-------------------------- EXAMPLE 2 --------------------------
PS C:\>Test-TCPPort www.google.com:443


-------------------------- EXAMPLE 3 --------------------------
PS C:\>Test-TCPPort -ComputerName WA1T3NCCNOC01 -TCPPort 5985


-------------------------- EXAMPLE 4 --------------------------
PS C:\>Test-TCPPort -ComputerName WA1-SRX-CORE -TCPPort 22
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)

---
## Write-UsageLog


Logs the current invocation of a function to Elasticsearch

<sub>

Author  : James Rodgers

Created : 12/3/2016

</sub>

#### Syntax
```PowerShell
Write-UsageLog [-Invocation] <PSObject> [[-address] <String>] [<CommonParameters>]
```

#### Examples
```PowerShell
-------------------------- EXAMPLE 1 --------------------------
PS C:\>Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
```

#### Related Links<br/>
https://support.ctl.io/hc/en-us/articles/207170083

[<sub>Back to FUNCTIONS</sub>](#function-list)
