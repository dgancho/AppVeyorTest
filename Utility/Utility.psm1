<#
.CompanyName
    CenturyLink Cloud

.Author
    Dmitry Gancho

.Description
    Collection of general-purpose helper functions.

.HelpInfoUri
    https://support.ctl.io/hc/en-us/articles/207170083

.RequiredModules

.FormatsToProcess
    Utility.Format.ps1xml

.FunctionsToExport
    #region PS USER ENVIRONMENT
    Add-PSModulePath
    Get-EnvironmentVariable
    Set-EnvironmentVariable
    Add-EnvironmentVariableValue
    Remove-EnvironmentVariableValue
    Test-Elevated
    Register-TabExpansion2
    Reset-PsPrompt

    #region NETWORK TOOLS
    Test-Ping
    Test-TCPPort
    Test-Target
    Resolve-Target

    #region CODE PROCESSING
    Get-InvocationLine
    Get-ParameterValidValues
    Publish-Module
    Set-ScriptSignature
    New-DynamicParameter
    Register-JobRemove
    Set-TimedJob
    Compress-ScriptBlock
    Invoke-Parallel
    Invoke-Retry
    Invoke-ScheduledCommand
    Clear-Garbage

    #region OBJECT PROCESSING
    Join-Object
    Get-ObjectDefaultDisplayProperty
    Set-ObjectDefaultDisplayProperty
    Split-Collection
    Expand-Object
    Compare-ObjectProperty

    #region DATA CONVERSION
    ConvertTo-PSCredential
    ConvertFrom-PSCredential
    ConvertTo-Regex
    ConvertTo-Utf8
    Expand-Gzip
    ConvertTo-Ascii
    ConvertTo-Base64
    ConvertTo-HashTable

    #region DATA REDIRECTION
    Out-Clip
    Out-Voice

    #region STRING MANIPULATION
    Test-Numeric 
    Find-MatchingLine 
    Find-LinesBetween

    #region LOGGING
    Test-EventLog
    Write-UsageLog

    #region COMPUTER TOOLS
    Test-Computer
    Get-PerformanceCounter
    Group-Counter
    Get-ComputerPerformance

.AliasesToExport
    reboot
    resolve
    flushdns
    tping
    tcp
    test
    tt
    pmo
    sign
    ctcr
    rtb
    expand
    exp

.SERVICE
    # List functions from this module that are not in use in any other toolbox module.
    $all = gcm -mod Utility | select -exp Name
    $used = $all | ? {(Search-File $_) -notmatch 'Utility\.psm1'}
    compare $all $used | select -exp InputObject

.SERVICE
    # F8 line below in PowerShell_ISE to generate module manifest.
    Publish-Module
#>


#Requires -Version 5.0

# namespace for SuppressMessageAttribute
Using Namespace System.Diagnostics.CodeAnalysis


$script:NewAliasCommonParams = @{
    Scope = 'Global'
    Force = $true
    Description = $MyInvocation.MyCommand.Definition
}

# commonly used alias
New-Alias @script:NewAliasCommonParams -Name reboot -Value Restart-Computer

# these functions are in Microsoft DnsClient module
# C:\windows\system32\windowspowershell\v1.0\modules\DnsClient
# http://go.microsoft.com/fwlink/?linkid=390768
New-Alias @script:NewAliasCommonParams -Name resolve -Value Resolve-DnsName
New-Alias @script:NewAliasCommonParams -Name flushdns -Value Clear-DnsClientCache


#region PS USER ENVIRONMENT

function Add-PSModulePath {
<#
.SYNOPSIS
    Add a Path to $env:PSModulePath if not yet there.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 11/20/2015
    Updated : 11/20/2015

.PARAMETER Path
    Required.

.PARAMETER PassThru
    Optional.

.EXAMPLE
    Add-PsModulePath "$env:USERPROFILE\Documents\GitHub\toolbox\Modules" -PassThru

.INPUTS
    [string]

.OUTPUTS
    [string[]]
.LINK
    https://support.ctl.io/hc/en-us/articles/207170083

#>
    [CmdletBinding()]

    param (
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [string]$Path,

        [Parameter()]
        [switch]$PassThru
    )

    if ($env:PSModulePath -notmatch ($Path -replace '\\','\\')) {
        $env:PSModulePath += ";$Path"
    }

    if ($PassThru) {
        $env:PSModulePath -split ';'
    }
}


function Get-EnvironmentVariable {
<#
.SYNOPSIS
    Get environment variable.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 12/19/2016
    Updated :

.EXAMPLE
    Get-EnvironmentVariable

.EXAMPLE
    Get-EnvironmentVariable -Name PsModulePath

.EXAMPLE
    Get-EnvironmentVariable -Scope Machine

.EXAMPLE
    Get-EnvironmentVariable -Name PsModulePath -Scope User -ValueOnly

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>
    [CmdletBinding()]

    param (
        [Parameter(Position = 0)]
        [ValidateSet('Path','PsModulePath','ToolboxPath','ToolboxPaths')]
        [string[]]$Name,

        [Parameter(Position = 1)]
        [System.EnvironmentVariableTarget[]]$Scope,

        [Parameter()]
        [switch]$Raw,

        [Parameter()]
        [switch]$ValueOnly
    )

    if (-not $Name) {
        $Name = $MyInvocation.MyCommand.Parameters['Name'].Attributes.Where{
            $_ -is [ValidateSet]
        }.ValidValues
    }

    if (-not [string]$Scope) {
        $Scope = [System.Enum]::GetValues([System.EnvironmentVariableTarget])
    }

    $results = foreach ($nm in $Name) {
        foreach ($sc in $Scope) {
            [pscustomobject]@{
                Variable = $nm
                Scope = $sc
                Value = [System.Environment]::GetEnvironmentVariable($nm,$sc)
            }
        }
    }

    if ($Raw) {
        if ($ValueOnly) {
            $results.Value
        } else {
            $results
        }
    } else {
        if ($ValueOnly) {
            $results.Value -split ';'
        } else {
            $results | Format-Table -AutoSize -Wrap -Property Variable, Scope, @{
                Label = 'Values'
                Expression = {
                    $_.Value -replace ';',"`n" | Out-String
                }
            }
        }
    }
}


function Set-EnvironmentVariable {
<#
.SYNOPSIS
    Set environment variable.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/11/2017
    Updated :

.EXAMPLE
    # reset PsModulePath to default value.
    Set-EnvironmentVariable -Name PsModulePath -default

.EXAMPLE
    # remove the variable
    Set-EnvironmentVariable -Name ToolboxPath -Scope Process -Value '' -PassThru

.LINK
#>

    [CmdletBinding(DefaultParameterSetName = 'default')]
    [SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]

    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('Path','PsModulePath','ToolboxPath')]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [System.EnvironmentVariableTarget]$Scope,

        [Parameter(Mandatory, Position = 2, ParameterSetName = 'explicit')]
        [AllowEmptyString()]
        [string[]]$Value,

        [Parameter(ParameterSetName = 'default')]
        [switch]$Default,

        [Parameter()]
        [switch]$PassThru
    )

    # define defaults
    $defaults = @{
        Path = @{
            Machine = @(
                "$env:HOMEDRIVE\iperf"
                "$env:windir"
                "$env:windir\System32"
                "$env:windir\System32\Wbem"
                "$env:windir\idmu\common"
                "$PSHOME"
                "$PSHOME\Scripts"
                "$env:ProgramFiles\Toolbox\Scripts"
                "$env:ProgramFiles\WindowsPowerShell\Scripts"
                "${env:ProgramFiles(x86)}\Microsoft VS Code\bin"
                "$env:HOMEDRIVE\gnuwin\bin"
                "${env:ProgramFiles(x86)}\putty"
                "$env:ProgramData\chocolatey\bin"
            )

            User = @(
                "$HOME\AppData\Local\Microsoft\WindowsApps"
                "$HOME\Documents\WindowsPowerShell\Scripts"
            )
        }

        PsModulePath = @{
            Machine = @(
                "$PSHOME\Modules"
                "$env:ProgramFiles\Toolbox\Modules"
                "$env:ProgramFiles\WindowsPowerShell\Modules"
                "${env:ProgramFiles(x86)}\VMware\Infrastructure\vSphere PowerCLI\Modules"
            )

            User = @(
                "$HOME\Documents\WindowsPowerShell\Modules"
            )
        }

        ToolboxPath = @{
            Machine = @(
                $env:ToolboxPath
            )

            User = @(
                $env:ToolboxPath
            )
        }
    }

    $defaults.Path.Process = $defaults.Path.Machine + $defaults.Path.User
    $defaults.PsModulePath.Process = $defaults.PsModulePath.Machine + $defaults.PsModulePath.User
    $defaults.ToolboxPath.Process = $defaults.ToolboxPath.User

    if ($Default) {
        $Value = $defaults.$Name.[string]$Scope
    }

    $newValue = $Value -join ';'
    $curValue = [System.Environment]::GetEnvironmentVariable($Name,$Scope)

    if ($newValue -ne $curValue) {
        [System.Environment]::SetEnvironmentVariable($Name,$newValue,$Scope)
    }

    if ($PassThru) {
        Get-EnvironmentVariable -Name $Name -Scope $Scope
    }
}


function Add-EnvironmentVariableValue {
<#
.SYNOPSIS
    Add a value to an environment variable.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 1/17/2017
    Updated : 1.1

.EXAMPLE
    Add-EnvironmentVariableValue -Name ToolboxPaths -Scope $Scope -Value $Path

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('Path','PsModulePath','ToolboxPaths')]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [System.EnvironmentVariableTarget]$Scope,

        [Parameter(Mandatory, Position = 2)]
        [string[]]$Value,

        [Parameter()]
        [switch]$PassThru
    )

    # define defaults
    $curValue = [System.Environment]::GetEnvironmentVariable($Name,$Scope)

    [array]$newValues = if ($curValue) {
        $curValue -split ';+' | Select-Object -Unique
    } else {
        @()
    }

    foreach ($val in @($Value)) {
        if ($newValues -notcontains $val) {
            $newValues += $val
        }
    }
    [string]$newValue = $newValues -join ';'

    if ($newValue -ne $curValue) {
        [System.Environment]::SetEnvironmentVariable($Name,$newValue,$Scope)
    }

    if ($PassThru) {
        Get-EnvironmentVariable -Name $Name -Scope $Scope
    }
}


function Remove-EnvironmentVariableValue {
<#
.SYNOPSIS
    Remove a value from an environment variable.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/11/2017
    Updated : 1.1

.EXAMPLE
    Remove-EnvironmentVariableValue -Name Path -Value *\Toolbox\* -Scope Process

#>

    [CmdletBinding()]
    [SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]

    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('Path','PsModulePath','ToolboxPath','ToolboxPaths')]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [System.EnvironmentVariableTarget]$Scope,

        [Parameter(Mandatory, Position = 2)]
        [string[]]$Value,

        [Parameter()]
        [switch]$PassThru
    )

    $curValue = [System.Environment]::GetEnvironmentVariable($Name,$Scope)

    [array]$newValues = if ($curValue) {
        $curValue -split ';+' | Select-Object -Unique
    } else {
        @()
    }

    # remove values
    foreach ($val in $Value) {
        $newValues = $newValues.Where{$_ -notlike $val}
    }
    [string]$newValue = $newValues -join ';'

    if ($newValue -ne $curValue) {
        [System.Environment]::SetEnvironmentVariable($Name,$newValue,$Scope)
    }

    if ($PassThru) {
        Get-EnvironmentVariable -Name $Name -Scope $Scope
    }
}


function Test-Elevated {
<#
.SYNOPSIS
    Test whether current PS session is elevated (aka 'as administrator').

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 7/5/2014
    Updated :

.EXAMPLE
    Test-Elevated

.INPUTS
    none

.OUTPUTS
    [bool]

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>
    [CmdletBinding()]param()

    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


New-Alias @script:NewAliasCommonParams -Name rtb -Value Register-TabExpansion2

function Register-TabExpansion2 {
<#
.SYNOPSIS
    Register function TabExpansion2.

    The script replaces the built-in function TabExpansion2, creates the table
    TabExpansionOptions, and does nothing else. Initialization is performed on
    the first code completion via profiles *ArgumentCompleters.ps1.

    $TabExpansionOptions consists of empty entries:

        CustomArgumentCompleters = @{}
        NativeArgumentCompleters = @{}
        ResultProcessors = @()
        InputProcessors = @()

    Initialization via profiles. When TabExpansion2 is called the first time it
    invokes scripts like *ArgumentCompleters.ps1 found in the path. They add
    their completers to the options.

    TabExpansion2.ps1 (with extension if it is in the path) should be invoked
    in the beginning of an interactive session. Modules and other tools on
    loading may check for existence of the table and add their completers.

    Any found profile and completer issues are written as silent errors.
    Examine the variable $Error on troubleshooting.

    Extra table options:

        IgnoreHiddenShares
            $true tells to ignore hidden UNC shares.

        LiteralPaths
            $true tells to not escape special file characters.

        RelativePaths
            $true tells to replace paths with relative paths.
            $false tells to replace paths with absolute paths.

    Consider to use Register-ArgumentCompleter instead of adding completers to
    options directly. In this case *ArgumentCompleters.ps1 are compatible with
    v5 native and TabExpansionPlusPlus registrations.

    Consider to use Register-InputCompleter and Register-ResultCompleter
    instead of adding completers to options directly.

.DESCRIPTION
    Author  : Roman Kuzmin
    Updated : Dmitry Gancho, 3/5/2017

.EXAMPLE
    Register-TabExpansion2

.LINK
    wiki https://github.com/nightroman/FarNet/wiki/TabExpansion2

.LINK
    https://www.powershellgallery.com/packages/TabExpansion2

.NOTES
    Download: Save-Script -Name TabExpansion2 -Path <path>
    LicenseUri: http://www.apache.org/licenses/LICENSE-2.0
    ProjectUri: https://github.com/nightroman/FarNet/blob/master/PowerShellFar/TabExpansion2.ps1
#>

    [CmdletBinding()]
    [SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    [SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]

    param (
        [switch]$ClearCache
    )

    Reset-PsPrompt

    if ($ClearCache) {
        # remove all cashed data
        Remove-Item -Path $env:LOCALAPPDATA\Microsoft\Windows\PowerShell\CommandAnalysis\* -Force -ErrorAction Ignore
    }

    # The global option table
    New-Variable -Force -Name TabExpansionOptions -Scope Global -Description 'Custom completers and options.' -Value @{
        CustomArgumentCompleters = @{}
        NativeArgumentCompleters = @{}
        ResultProcessors = @()
        InputProcessors = @()
    }

    # Temporary initialization variable
    $global:TabExpansionProfile = $true

    function global:Register-ArgumentCompleter {
        <#
        .Synopsis
            Registers argument completers.
        .Description
            This command registers a script block as a completer for specified commands
            or parameter. It is compatible with v5 native and TabExpansionPlusPlus.
        .Example
            Register-ArgumentCompleter
        #>

        [CmdletBinding(DefaultParameterSetName = 'PowerShellSet')]
        [SuppressMessageAttribute('PSAvoidDefaultValueForMandatoryParameter', '')]
        [SuppressMessageAttribute('PSAvoidGlobalFunctions', '')]

        param(
            [Parameter(ParameterSetName = 'NativeSet', Mandatory = $true)]
            [Parameter(ParameterSetName = 'PowerShellSet')]
            [string[]]$CommandName = '',

            [Parameter(ParameterSetName = 'PowerShellSet', Mandatory = $true)]
            [string]$ParameterName,

            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,

            [Parameter(ParameterSetName = 'NativeSet')]
            [switch]$Native
        )

        $key = if ($Native) {'NativeArgumentCompleters'} else {'CustomArgumentCompleters'}
        foreach ($command in $CommandName) {
            if ($command -and $ParameterName) {$command += ":"}
            $TabExpansionOptions[$key]["${command}${ParameterName}"] = $ScriptBlock
        }
    }

    function global:Register-InputCompleter {
        <#
        .Synopsis
            Registers input completers.
        .Description
            Input completers work before native. Each completer is invoked with the
            arguments $ast, $tokens, $positionOfCursor, $options. It returns either
            nothing in order to continue or a CommandCompletion instance which is
            used as the result.

            Register-InputCompleter is only used with this TabExpansion2.ps1,
            unlike Register-ArgumentCompleter which may be used in other cases.
        .Outputs
            [System.Management.Automation.CommandCompletion]
        #>

        [CmdletBinding()]
        [SuppressMessageAttribute('PSAvoidGlobalFunctions', '')]

        param(
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock
        )

        $TabExpansionOptions.InputProcessors += $ScriptBlock
    }

    function global:Register-ResultCompleter {
        <#
        .Synopsis
            Registers result completers.
        .Description
            Result completers work after native. They are invoked with the arguments
            $result $ast $tokens $positionOfCursor $options. They should not return
            anything, they should either do nothing or alter the $result.

            Register-InputCompleter is only used with this TabExpansion2.ps1,
            unlike Register-ArgumentCompleter which may be used in other cases.
        #>

        [CmdletBinding()]
        [SuppressMessageAttribute('PSAvoidGlobalFunctions', '')]

        param(
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock
        )

        $TabExpansionOptions.ResultProcessors += $ScriptBlock
    }

    function global:TabExpansion2 {

        [CmdletBinding(DefaultParameterSetName = 'ScriptInputSet')]
        [OutputType([System.Management.Automation.CommandCompletion])]
        [SuppressMessageAttribute('PSAvoidGlobalFunctions', '')]

        param(
            [Parameter(ParameterSetName = 'ScriptInputSet', Mandatory= $true, Position = 0)]
            [string]$inputScript,

            [Parameter(ParameterSetName = 'ScriptInputSet', Mandatory = $true, Position = 1)]
            [int]$cursorColumn,

            [Parameter(ParameterSetName = 'AstInputSet', Mandatory = $true, Position = 0)]
            [System.Management.Automation.Language.Ast]$ast,

            [Parameter(ParameterSetName = 'AstInputSet', Mandatory = $true, Position = 1)]
            [System.Management.Automation.Language.Token[]]$tokens,

            [Parameter(ParameterSetName = 'AstInputSet', Mandatory = $true, Position = 2)]
            [System.Management.Automation.Language.IScriptPosition]$positionOfCursor,

            [Parameter(ParameterSetName = 'ScriptInputSet', Position = 2)]
            [Parameter(ParameterSetName = 'AstInputSet', Position = 3)]
            [Hashtable]$options
        )

        $private:_inputScript = $inputScript
        $private:_cursorColumn = $cursorColumn
        $private:_ast = $ast
        $private:_tokens = $tokens
        $private:_positionOfCursor = $positionOfCursor
        $private:_options = $options
        Remove-Variable inputScript, cursorColumn, ast, tokens, positionOfCursor, options

        # take/init global options
        if (-not $_options) {
            $_options = $PSCmdlet.GetVariableValue('TabExpansionOptions')
            if ($PSCmdlet.GetVariableValue('TabExpansionProfile')) {
                Remove-Variable -Name TabExpansionProfile -Scope Global
                foreach($_ in Get-Command -Name *ArgumentCompleters.ps1 -CommandType ExternalScript -All) {
                    if (& $_.Definition) {
                        Write-Error -ErrorAction 0 "TabExpansion2: Unexpected output. Profile: $($_.Definition)"
                    }
                }
            }
        }

        # parse input
        if ($psCmdlet.ParameterSetName -eq 'ScriptInputSet') {
            $_ = [System.Management.Automation.CommandCompletion]::MapStringInputToParsedInput($_inputScript, $_cursorColumn)
            $_ast = $_.Item1
            $_tokens = $_.Item2
            $_positionOfCursor = $_.Item3
        }

        # input processors
        foreach($_ in $_options['InputProcessors']) {
            if ($private:result = & $_ $_ast $_tokens $_positionOfCursor $_options) {
                if ($result -is [System.Management.Automation.CommandCompletion]) {
                    return $result
                }
                Write-Error -ErrorAction 0 "TabExpansion2: Invalid result. Input processor: $_"
            }
        }

        # native
        $private:result = [System.Management.Automation.CommandCompletion]::CompleteInput($_ast, $_tokens, $_positionOfCursor, $_options)

        # result processors?
        if (!($private:processors = $_options['ResultProcessors'])) {
            return $result
        }

        # work around read only
        if ($result.CompletionMatches.IsReadOnly) {
            if ($result.CompletionMatches) {
                return $result
            }
            function TabExpansion {'*'}
            $result = [System.Management.Automation.CommandCompletion]::CompleteInput("$_ast", $_positionOfCursor.Offset, $null)
            $result.CompletionMatches.Clear()
        }

        # result processors
        foreach($_ in $processors) {
            if (& $_ $result $_ast $_tokens $_positionOfCursor $_options) {
                Write-Error -ErrorAction 0 "TabExpansion2: Unexpected output. Result processor: $_"
            }
        }

        $result
    }
}


function Reset-PsPrompt {
<#
.SYNOPSIS
    Reset PS prompt to default value, such as 'PS C:\> '.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 2/28/2017
    Updated :

.EXAMPLE
    Reset-PsPrompt
#>

    [CmdletBinding()]
    [SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]

    param()

    function global:prompt {
        "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
        #.Link
        # http://go.microsoft.com/fwlink/?LinkID=225750
        #.ExternalHelp System.Management.Automation.dll-help.xml
    }
}

#endregion



#region NETWORK TOOLS

New-Alias @script:NewAliasCommonParams -Name tping -Value Test-Ping

function Test-Ping {
<#
.SYNOPSIS
    Tests for device response to ICMP ping.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 6/18/2017
    Updated : 11/13/2018

.PARAMETER ComputerName
    Optional. Default 'localhost'
    Device name or IP address.

.PARAMETER TimeOutMs
    Optional. Default 1000
    Timeout in milliseconds.

.PARAMETER Count
    Optional. Default 1
    Ping count.

.PARAMETER IntervalMs
    Optional. Default 100
    Ping interval.

.PARAMETER Mode
    Optional. Default 'And'
    Valid values 'And', 'Or'.

.PARAMETER PacketSize
    Optional. Default 32
    Valid values 1 through 65500

.PARAMETER DontFragment
    Switch. Default $False

.EXAMPLE
    Test-Ping facebook.com -TimeOutMs 10 -Count 100 -IntervalMs 50 -Mode And

.EXAMPLE
    Test-Ping facebook.com -TimeOutMs 10 -Count 100 -IntervalMs 50 -Mode Or

.EXAMPLE
    # Max packet size when MTU = 1500
    Test-Ping google.com -PacketSize 1473 -DontFragment -Verbose

.OUTPUTS
    [bool]

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083

.NOTES
    ping google.com -f -l 1472

    $opt = [System.Net.NetworkInformation.PingOptions]::new()
    $opt.DontFragment = $true
    $ping = [System.Net.NetworkInformation.Ping]::new()
    $ping.Send('google.com', 1000, [byte[]]::new(1472), $opt)
    
#>

    [CmdletBinding()]

    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Alias('cn','name','device','target')]
        [string]$ComputerName = 'localhost',

        [Parameter()]
        [Alias('to')]
        [ValidateRange(1, [uint16]::MaxValue)]
        [uint16]$TimeOutMs = 1000,

        [Parameter()]
        [ValidateRange(1, [byte]::MaxValue)]
        [byte]$Count = 1,

        [Parameter()]
        [ValidateRange(1, [uint16]::MaxValue)]
        [uint16]$IntervalMs = 100,

        [Parameter()]
        [ValidateSet('And', 'Or')]
        [string]$Mode = 'And',

        [Parameter()]
        [ValidateRange(1, 65500)]
        [uint16]$PacketSize = 32,

        [Parameter()]
        [switch]$DontFragment
    )
    
    $buffer   = [byte[]]::new($PacketSize)
    $optionts = [System.Net.NetworkInformation.PingOptions]::new()
    $optionts.DontFragment = $DontFragment

    $results = for ($i = 1; $i -le $Count; $i++) {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $result = $ping.Send($ComputerName, $TimeOutMs, $buffer, $optionts)
        $result | Out-String | Write-Verbose

        if ($result.Status -ne 'Success') {
            $result.Status | Write-Warning
        }

        $result.Status -eq 'Success'
        Start-Sleep -Milliseconds $IntervalMs
    }

    switch ($Mode) {
        And {
            $results -notcontains $false
        }

        Or {
            $results -contains $true
        }
    }
}


New-Alias @script:NewAliasCommonParams -Name tcp -Value Test-TcpPort

function Test-TcpPort {
<#
.SYNOPSIS
    Tests for device response on a single TCP Port.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 6/19/2017
    Updated : 6/14/2018

.PARAMETER ComputerName
    Optional. Default 'localhost'
    Device name or IP address.

.PARAMETER TcpPort
    Optional. Default 5985
    TCP Port.

.PARAMETER TimeOutMs
    Optional. Default 1000
    Timeout in milliseconds.

.EXAMPLE
    Test-TCPPort facebook.com

.EXAMPLE
    Test-TCPPort www.google.com:443

.EXAMPLE
    Test-TCPPort -ComputerName WA1T3NCCNOC01 -TCPPort 5985

.EXAMPLE
    Test-TCPPort -ComputerName WA1-SRX-CORE -TCPPort 22

.INPUTS
    [string]
    [int32]
    [int16]

.OUTPUTS
    [bool]

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>

    [CmdletBinding()]

    param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('cn', 'name', 'device', 'target')]
        [string[]]$ComputerName = 'localhost',

        [Parameter(Position = 1)]
        [Alias('port')]
        [ValidateRange(1, [uint16]::MaxValue)]
        [uint16]$TcpPort = 5985,

        [Parameter(Position = 2)]
        [Alias('to')]
        [ValidateRange(1, [uint16]::MaxValue)]
        [uint16]$TimeOutMs = 1000,

        [Parameter()]
        [ValidateRange(1, [byte]::MaxValue)]
        [byte]$RetryCount = 1,

        [Parameter()]
        [ValidateRange(1, [uint16]::MaxValue)]
        [Alias('interval')]
        [uint16]$RetryIntervalMs = 100
    )
    
    function InvokeTcpConnect ($ip, $port, $timeout) {
        $tcpClient = New-Object -TypeName System.Net.Sockets.TCPClient
        $socket = $tcpClient.BeginConnect($ip, $port, $null, $null)

        if ($socket.AsyncWaitHandle.WaitOne($timeout)) {
            try {
                [void]$tcpClient.EndConnect($socket)
            }

            catch {}
        }

        $connected = $tcpClient.Connected
        $tcpClient.Close()
        $tcpClient.Dispose()
        $connected
    }

    foreach ($target in $ComputerName) {
        "Target: {0}" -f $target | Write-Verbose

        if ($target -match ':\d+$') {
            $target, $TcpPort = $target -split ':'
        }

        if ($target -eq '.') {
            $target =  'localhost'
        }

        try {
            $ip = [System.Net.Dns]::Resolve($target).AddressList[0].IPAddressToString
        }

        catch {
            $message = "DNS: Can't resolve '{0}'. {1}" -f $target, $_.Exception.InnerException.Message
            throw $message
        }

        for ($i = 1; $i -le $RetryCount; $i ++) {
            "Connecting to {0}:{1}, to {2} ms, attempt {3}" -f $ip, $TcpPort, $TimeOutMs, $i | Write-Verbose

            $result = InvokeTcpConnect -ip $ip -port $TcpPort -timeout $TimeOutMs

            "Connected: {0}" -f $result | Write-Verbose

            if ($result) {
                break
            }

            else {
                Start-Sleep -Milliseconds $RetryIntervalMs
            }
        }

        # report
        $result
    }
}


New-Alias @script:NewAliasCommonParams -Name test -Value Test-Target
New-Alias @script:NewAliasCommonParams -Name tt -Value Test-Target

function Test-Target {
<#
.SYNOPSIS
    Performs multiply connectivity tests to a target:
    - ICMP Ping
    - DNS Resolution (A, AAAA, CNAME, PTR)
    - Multiply TCP Ports
    Tests are executed in parallel asyncronously.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/12/2016
    Updated : 3/26/2019

.PARAMETER Target
    Optional.
    Target Name or IP address.
    If not provided, defaults to localhost.

.EXAMPLE
    $res = Test-Target
    $res.Ping | select -uniq | Should Be 0
        
.EXAMPLE
    Test-Target microsoft.com

.EXAMPLE
    Test-Target 8.8.4.4 -Scan

.OUTPUTS
    [PSCustomObject]

.LINK
    https://serverfault.com/questions/648424/windows-server-2012-r2-runs-out-of-ephemeral-ports-though-it-shouldnt

.NOTES
    Uses 'Utility.TestTarget' from 'Utility.Format.ps1xml' to format output.

#>

    [CmdletBinding(DefaultParameterSetname = 'specified')]
    [SuppressMessageAttribute('PSAvoidInvokingEmptyMembers', '')]

    param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('cn')]
        [string[]]$Target = 'localhost',

        [Parameter()]
        [Alias('n')]
        [ValidateRange(1, 100)]
        [uint16]$PingCount = 4,

        [Parameter(ParameterSetName = 'specified')]
        [Alias('p', 'port')]
        [ValidateRange(1, [uint16]::MaxValue)]
        [uint16[]]$TcpPort,

        [Parameter(ParameterSetName = 'all')]
        [Alias('scan')]
        [switch]$WellKnownTcpPorts
    )

    begin {
        function StartAsync ([scriptblock]$scriptblock, [object]$param) {
            # create a runspace
            $runspace = [RunspaceFactory]::CreateRunspace()
            $runspace.ThreadOptions = 'ReuseThread'
#            $runspace.ApartmentState = 'STA'
            $runspace.Open()

            # set variables
            $runspace.SessionStateProxy.SetVariable('param', $param)
            $runspace.SessionStateProxy.SetVariable('sw', $stopwatch)

            # create a pipeline
            $pipeline = $runspace.CreatePipeline()

            # add ScripBlock
            $pipeline.Commands.AddScript($scriptblock)

            # start StopWatch
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            # begin execution
            $pipeline.InvokeAsync()

            # return
            @{
                pl = $pipeline
                sw = $stopwatch
            }
        }

        function StopAsync ([System.Collections.Hashtable]$handle, [System.TimeSpan]$to) {
            # wait
            do {
                Start-Sleep -Milliseconds 10
                $state = $handle.pl.PipelineStateInfo.State
            }
            
            until (
                $handle.sw.Elapsed -ge $to -or
                $state -eq 'Completed'
            )

            # stop pipeline
            $handle.pl.StopAsync()

            # stop stopwatch
            $handle.sw.Stop()

            # read result
            $data = if ($state -eq 'Completed') {
                $handle.pl.Output.ReadToEnd()
                [void]$handle.pl.Runspace.CloseAsync()
                [void]$handle.pl.Dispose()
            }

            # return
            @{
                data    = $data
                state   = $state
                elapsed = $handle.sw.Elapsed
            }
        }

        function ResolveDns ([string]$target) {
            $to = [timespan]::FromMilliseconds(5000)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()

            $handle = [Net.Dns]::BeginGetHostEntry($target, $null, $null)

            do {
                Start-Sleep -Milliseconds 10
            }

            until (
                $handle.IsCompleted -or
                $sw.Elapsed -ge $to
            )

            if ($handle.IsCompleted) {
                try   {[Net.Dns]::EndGetHostEntry($handle)}
                catch {$_}
            }

            else {
                'failed to resolve'
            }
        }

        $pngScript = {
            # output [System.Net.NetworkInformation.PingReply[]] or [string[]]
            [string]$ip  = $param.ip
            [byte]$count = $param.count

            # set output variable to collect results
            $tasks = for ($i = 0; $i -le $count; $i ++) {
                $ping = [System.Net.NetworkInformation.Ping]::new()
                $ping.SendPingAsync($ip, 1000)

                Start-Sleep -Milliseconds 100
            }

            $outputs = foreach ($task in $tasks) {
                do    {Start-Sleep -Milliseconds 10}
                until ($task.IsCompleted)

                $task.Result
                $task.Dispose()
            }

            # ignore first warm-up ping
            $outputs[1 .. $count]
        }

        $tcpScript = {
            # returns [hashtable] of port # : $true or $false
            [string]$ip      = $param.ip
            [uint16[]]$ports = $param.ports
            $waitSec         = 3

            # create array of TCP Clients
            [array]$handles = $ports.ForEach{
                $client = [System.Net.Sockets.TcpClient]::new()
                [void]$client.ConnectAsync($ip, $_)

                @{
                    port   = $_
                    client = $client
                }
            }

            # wait
            Start-Sleep -Seconds $waitSec

            # return
            $handles.ForEach{
                [pscustomobject]@{
                    port      = $_.port
                    connected = $_.client.Connected
                }

                $_.client.Close()
                $_.client.Dispose()
            }
        }

        # define list of TCP Ports to test
        if ($WellKnownTcpPorts) {
            # http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
            $TcpPort += 21   # FTP
            $TcpPort += 22   # SSH: secure logins, file transfers (scp, sftp) and port forwarding
            $TcpPort += 23   # TELNET
            $TcpPort += 25   # SMTP
            $TcpPort += 53   # DNS Server
            $TcpPort += 80   # HTTP
            $TcpPort += 88   # DC Kerberos
            $TcpPort += 101  # NIC host name
            $TcpPort += 110  # POP3
            $TcpPort += 135  # DCE/RPC Locator service
            $TcpPort += 137  # NetBIOS Name Service
            $TcpPort += 139  # NetBIOS Datagram Service
            $TcpPort += 143  # IMAP
            $TcpPort += 156  # SQL Service
            $TcpPort += 161  # SSH: SNMP Service (trap)
            $TcpPort += 162  # SSH: SNMP Service
            $TcpPort += 199  # SSH: SNMP Service
            $TcpPort += 389  # DC LDAP (Lightweight Directory Access Protocol)
            $TcpPort += 443  # HTTPS
            $TcpPort += 445  # SMB over IP / Microsoft DS
            $TcpPort += 465  # SMTP secure
            $TcpPort += 514  # Shell—used to execute non-interactive commands on a remote system (Remote Shell, rsh, remsh)
            $TcpPort += 546  # DHCP Client
            $TcpPort += 547  # DHCP Server
            $TcpPort += 636  # LDAPS Servce
            $TcpPort += 830  # NETCONF over SSH
            $TcpPort += 902  # ESXi host - Client access to virtual machine consoles
            $TcpPort += 992  # TELNET protocol over TLS/SSL
            $TcpPort += 993  # IMAP secure
            $TcpPort += 995  # POP3 secure
            $TcpPort += 1433 # SQL Default Service
            $TcpPort += 1434 # SQL Browser Service (to named instances)
            $TcpPort += 1688 # KMS Service
            $TcpPort += 1723 # MS VPN (PPTP)
            $TcpPort += 2012 # RPC port for VMware Directory Service (vmdir)
            $TcpPort += 2013 # Control interface RPC for Kerberos, used by vCenter Single Sign-On
            $TcpPort += 2014 # RPC port for VMware Certificate Authority (VMCA) service
            $TcpPort += 2020 # RPC port for VMware Authentication Framework Service (vmafd)
            $TcpPort += 2179 # VMConnect to Hyper-V hosts (RDP protocol)
            $TcpPort += 2383 # SQL Server Analysis Services Port (SQL 2005 / 2008)
            $TcpPort += 2525 # SMTP alternative
            $TcpPort += 3268 # DC Global Catalog
            $TcpPort += 3306 # MySQL database system
            $TcpPort += 3389 # Terminal Server (RDP protocol)
            $TcpPort += 3516 # Smartcard Port
            $TcpPort += 5500 # VNC remote desktop protocol — for incoming listening viewer
            $TcpPort += 5723 # SCOM Channel
            $TcpPort += 5985 # Windows PowerShell Default psSession Port
            $TcpPort += 5986 # Windows PowerShell Default psSession Port (secure)
            $TcpPort += 5988 # ESXi Host - CIM transactions over HTTP
            $TcpPort += 5989 # ESXi Host - CIM XML transactions over HTTPS
            $TcpPort += 8000 # ESXi Host - Requests from vMotion
            $TcpPort += 8080 # Alternate HTTP
            $TcpPort += 8091 # Couchbase Server
            $TcpPort += 8100 # ESXi Host - Traffic between hosts for vSphere Fault Tolerance (FT)
            $TcpPort += 8182 # ESXi Host - Traffic between hosts for vSphere High Availability (HA)
            $TcpPort += 8109 # VMware Syslog Collector
            $TcpPort += 8200 # ESXi Host - Traffic between hosts for vSphere Fault Tolerance (FT)
            $TcpPort += 8888 # Alternate HTTP
            $TcpPort += 9119 # PasswordState servers API
            $TcpPort += 9200 # ElasticSearch Infra DB API
            $TcpPort += 9443 # VCenter WebClient HTTPS - vSphere Web Client HTTP access to ESXi hosts
            $TcpPort += 10080 # VCenter Inventory service
            $TcpPort += 15915 # CLC simple backup agent web client
            $TcpPort += 46900 # CLC port forward to CFW
            $TcpPort += 46901 # CLC port forward to EFW
        }
    }

    process {
        foreach ($targ in $Target) {
            # define hash table
            $output = [ordered]@{
                TimeStamp        = [datetime]::UtcNow
                Target           = $targ
                DnsHostName      = $null
                DnsIpAddressList = $null
                Ping             = $null
            }

            # DNS resolution
            $result = ResolveDns -target $targ

            if ($result -is [System.Net.IPHostEntry]) {
                $output.DnsHostName      = $result.HostName
                $output.DnsIpAddressList = $result.AddressList.Where{$_.AddressFamily -eq 'InterNetwork'}
            }

            elseif ($result -is [System.Management.Automation.ErrorRecord]) {
                $output.DnsHostName      = $result.Exception.InnerException.Message
                $output.DnsIpAddressList = @()
            }

            else {
                $output.DnsHostName      = $result
                $output.DnsIpAddressList = @()
            }

            # select IP address
            [ipaddress]$ip = if ([ipaddress]::TryParse($targ, [ref][ipaddress]::None)) {
                $targ
            }

            elseif ([ipaddress]::TryParse($output.DnsIpAddressList[0], [ref][ipaddress]::None)) {
                $output.DnsIpAddressList[0]
            }
            
            if ($ip) {
                # ICMP ping test
                $pngHandle = StartAsync -scriptblock $pngScript -param @{
                    ip    = $ip
                    count = $PingCount
                }

                # TCP port test
                $tcpHandle = if ($TcpPort) {
                    StartAsync -scriptblock $tcpScript -param @{
                        ip    = $ip
                        ports = $TcpPort
                    }
                }

                # receive ping
                $pngTo = [timespan]::FromMilliseconds(500 * $PingCount)
                $pngResult = StopAsync -handle $pngHandle -to $pngTo

                $output.Ping = foreach ($data in $pngResult.data) {
                    if ($data.Status -eq 'TimedOut') {
                        'to'
                    }

                    else {
                        $data.RoundTripTime
                    }
                }

                # receive tcp
                if ($tcpHandle) {
                    $tcpTo          = [timespan]::FromMilliseconds(5000)
                    $tcpResult      = StopAsync -handle $tcpHandle -to $tcpTo
                    $ports          = $tcpResult.data | Sort-Object -Property port
                    $output.TcpPort = @($ports).Where{$_.Connected}.port
                }
            }

            # apply formatting
            $output = [pscustomobject]$output

            if ($TcpPort) {
                $output.PsObject.TypeNames.Insert(0, 'Utility.TestTarget.Default')
                $output.PsObject.TypeNames.Insert(1, 'Deserialized.Utility.TestTarget.Default')
            }

            else {
                $output.PsObject.TypeNames.Insert(0, 'Utility.TestTarget.NoTcp')
                $output.PsObject.TypeNames.Insert(1, 'Deserialized.Utility.TestTarget.NoTcp')
            }

            # return
            $output
        }
    }
}


function Resolve-Target {
<#
.SYNOPSIS
    Find a target which responds first:
    - to ICMP Ping, if no TCP port provided
    - to TCP port connection request if port is provided.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 2/9/2018
    Updated : 

.PARAMETER Target
    Optional.
    Target Name or IP address.
    If not provided, defaults to localhost.

.EXAMPLE
    Resolve-Target -Target T3N.dom
        
.EXAMPLE
    Resolve-Target -Target T3N.dom -TcpPort 5985 -Verbose

.EXAMPLE
    Resolve-Target -Target ccmssql -TcpPort 1433 -TimeoutMs 1000

.LINK
    https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/

.LINK
    https://learn-powershell.net/2016/02/14/another-way-to-get-output-from-a-powershell-runspace/
#>

    [CmdletBinding()]

    param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('cn')]
        [string[]]$Target = $env:COMPUTERNAME,

        [Parameter()]
        [Alias('port')]
        [ValidateRange(1, [uint16]::MaxValue)]
        [uint16]$TcpPort,

        [Parameter()]
        [Alias('to')]
        [ValidateRange(1, [uint16]::MaxValue)]
        [uint16]$TimeoutMs = 1000
    )

    begin {
        $ipAddressList = [System.Collections.ArrayList]::new()
    }

    process {
        $Target | ForEach-Object -Process {
            [System.Net.Dns]::GetHostAddresses($_).ForEach{
                [void]$ipAddressList.Add($_.IPAddressToString)
            }
        }
    }

    end {
        $script = {
            param (
                [string]$ip
            )

            $to = $Synchronized.TimeOutMs
            $sw = [System.Diagnostics.Stopwatch]::StartNew()

            if ($Synchronized.TcpPort) {
                # TCP port
                $port = $Synchronized.TcpPort

                $tcpClient = [System.Net.Sockets.TCPClient]::new()
                $socket = $tcpClient.BeginConnect($ip, $port, $null, $null)

                if ($socket.AsyncWaitHandle.WaitOne($to)) {
                    try {[void]$tcpClient.EndConnect($socket)} catch {}
                }

                $sw.Stop()
                $elapsed = $sw.Elapsed.TotalMilliseconds

                $connected = $tcpClient.Connected
                $tcpClient.Close()
                $tcpClient.Dispose()

                $success = $connected -eq $true

                $info = "ip: $ip, port: $port, connected: $connected, elapsed: $elapsed"
                $Synchronized.Host.ui.WriteVerboseLine($info)
            }

            else {
                # ICMP ping
                $ping = [System.Net.NetworkInformation.Ping]::new()
                $result = $ping.Send($ip, $to)

                $sw.Stop()
                $elapsed = $sw.Elapsed.TotalMilliseconds

                $status  = $result.Status
                $success = $status -eq 'Success'

                $info = "ip: $ip, ping status: $status, elapsed: $elapsed"
                $Synchronized.Host.ui.WriteVerboseLine($info)
            }

            # update Syncronized variable
            [void]$Synchronized.Results.Add([pscustomobject]@{
                IpAddress = $ip
                Success   = $success
                Elapsed   = $elapsed
            })
        }

        # create a runspace pool
        $runspacecount = $ipAddressList.Count
        $sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $runspacecount, $sessionstate, $Host)

        # create syncronized variable
        $syncronized = [hashtable]::Synchronized(@{
            Host      = $Host
            TimeoutMs = $TimeoutMs
            TcpPort   = $TcpPort
            Results   = [system.collections.arraylist]::new()
        })
        $variable = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('Synchronized', $syncronized, $null)
        [void]$runspacePool.InitialSessionState.Variables.Add($variable)

        # open runspacepool
        $runspacepool.Open()

        # create and invoke ps instances in runspace pool
        $handles = $ipAddressList.ForEach{
            $ip = $_

            # create powershell instance
            $powershell = [powershell]::Create()

            # add scirpt and parameters
            [void]$powershell.AddScript($script)
            [void]$powershell.AddParameters([System.Collections.IDictionary]@{
                ip = $ip
            })

            # add runspace into powershell instance
            $powershell.RunspacePool = $runspacepool

            # create and return handle
            @{
                ps  = $powershell
                job = $powershell.BeginInvoke()
            }
        }


        # start stopwatch
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        # wait for an IP
        do {
            $completed = @($handles).Where{$_.job.IsCompleted}
            $handles = @($handles).Where{-not $_.job.IsCompleted}

            # cleanup completed jobs
            if ($completed) {
                $completed.ForEach{
                    $_.ps.EndInvoke($_.job)
                    $_.ps.Dispose()
                }
            }
        }

        until (
            @($syncronized.Results.Success) -contains $true -or
            $sw.ElapsedMilliseconds -ge $TimeoutMs
        )
        
        # cleanup remaining jobs
        if ($handles) {
            @($handles).ForEach{
                $_.ps.Dispose()
            }
        }

        $runspacepool.Dispose()


        # sort and filter
        $results = $syncronized.Results
        $results | Out-String | Write-Verbose

        $sorted = @($results).Where{$_.Success} | Sort-Object -Property Elapsed

        # return
        @($sorted)[0].IpAddress
   } 
} 

#endregion



#region CODE PROCESSING

function Get-InvocationLine {
<#
.SYNOPSIS
    Get invocation line in the form:
    [string]'ModuleName\FunctionName -Param1 Value -Param2 Value..'
    Used in Write-Progress

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/25/2017

.EXAMPLE
    Get-InvocationLine

#>

    [CmdletBinding()]
    [OutputType([System.String])]

    param (
        [Parameter()]
        [System.Management.Automation.InvocationInfo]$Invocation
    )

    if (-not $Invocation) {
        $stack = Get-PSCallStack
        $Invocation = $stack[1].InvocationInfo
    }

    $moduleName  = $Invocation.MyCommand.ModuleName
    $commandName = $Invocation.MyCommand.Name
    $invocationLine = "{0}\{1}" -f $moduleName, $commandName

    $Invocation.BoundParameters.GetEnumerator().ForEach{
        $invocationLine += " -{0} {1}" -f $_.Key, ($_.Value -join ',')
    }

    $invocationLine
}


function Get-ParameterValidValues {
<#
.SYNOPSIS
    Get valid values for a function parameter.
    Use inside a function.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 9/6/2018
    Updated : 10/1/2018

.EXAMPLE
    # Inside a function:
    Get-ParameterValidValues -ParameterMetadata $MyInvocation.MyCommand.Parameters['ParameterName']

.EXAMPLE
    # Inside a function:
    $MyInvocation.MyCommand.Parameters['ParameterName'] | Get-ParameterValidValues

#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [System.Management.Automation.ParameterMetadata]$ParameterMetadata
    )

    $ParameterMetadata.Attributes.Where{
        $_ -is [System.Management.Automation.ValidateSetAttribute]
    }.ValidValues
}


New-Alias @script:NewAliasCommonParams -Name pmo -Value Publish-Module

function Publish-Module {
<#
.SYNOPSIS
    Generates module manifest and readme.md for module currently opened in PS ISE.
    Manifest is based on content of comment_based_help in the beginning of the module.
    If param Destination is specified, content of the folder is copied to Destination.
    Files matching '_*.*' are excluded.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/31/2017
    Updated : 11/18/2018

.EXAMPLE
    # Publish module currently opened in PowerShell_ISE.exe editor.
    Publish-Module

.EXAMPLE
    # Publish module by Name.
    Publish-Module -Name Utility

.EXAMPLE
    # Publish imported module.
    Get-Module -Name Utility | Publish-Module

.INPUTS
    [string]

.OUTPUTS
    [PsModuleInfo]

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>

    [CmdletBinding(DefaultParameterSetName = 'ise')]

    param (
        [Parameter(Position = 0, ValueFromPipeline, ParameterSetName = 'name')]
        [string]$Name,

        [Parameter(Position = 0, ValueFromPipeline, ParameterSetName = 'module')]
        [System.Management.Automation.PSModuleInfo]$ModuleInfo,

        [Parameter()]
        [switch]$NoReadme
    )

    if ($env:ToolboxUsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }

    # function to get all sections from module help to a hashtable
    function GetHeaderValues ([string]$path) {
        $output = [ordered]@{}

        # get content of .psm1 file
        $modContent = [System.IO.File]::ReadAllText($path)

        # capture header comment
        # https://www.rexegg.com/regex-quickstart.html
        $regex  = [regex]::new('(?s)\<#.*?#\>')
        $result = $regex.Match($modContent)
        $modHeader = $result.Value -replace '\<#|#\>'

        # capture section names in the header
        $regex    = [regex]::new('(?m)^\s?\.(?<name>\b.*\b)')
        $results  = $regex.Matches($modHeader)
        $sections = $results.ForEach{$_.Groups['name'].Value}

        # foeach section, capture content
        foreach ($section in $sections) {
            # capture lines until next section or end
            $regex  = [regex]::new("(?s)(?:\.$section\s?\r?\n)((?<value>.*?))(?:\W+\.\w+|$)")
            $result = $regex.Match($modHeader)
            $value  = $result.Groups['value'].Value -split "`n" -replace "^\s+|\s+$" -join "`n"

            # some sections are multiline, capture each line, excluding commented
            if ($section -in @(
                'RequiredModules'
                'RequiredAssemblies'
                'ScriptsToProcess'
                'TypesToProcess'
                'FormatsToProcess'
                'NestedModules'
                'FunctionsToExport'
                'CmdletsToExport'
                'VariablesToExport'
                'AliasesToExport'
                'DscResourcesToExport'
                'ModuleList'
                'FileList'
            )) {
                $regex = [regex]::new('(?m)^\s?(?<value>[^#]\S+)\s?$')
                $results = $regex.Matches($value)
                $value   = $results.ForEach{$_.Groups['value'].Value}
            }

            $output.$section = $value
        }

        $output
    }
    
    switch ($PSCmdlet.ParameterSetName) {
        ise {
            # current file, editor, current cursor line
            $currentFile = $psISE.CurrentFile
            $editor = $currentFile.Editor
            $currentLine = $editor.CaretLine

            # replace tab characters with 4 whitespaces
            if ([regex]::Match($editor.Text,'\t').Success) {
                $editor.Text = $editor.Text -replace '\t','    '
            }

            # save current file
            if (-not $currentFile.IsSaved) {
                $currentFile.Save()
            }

            $modInfo = Get-Module -FullyQualifiedName $currentFile.FullPath -ListAvailable
        }

        name {
            $modInfo = Get-Module -Name $Name -ListAvailable
        }

        module {
            $modInfo = $ModuleInfo
        }
    }

    if ($modInfo -isnot [psmoduleinfo]) {
        throw "Unexpected Module type :`n$module"
    }

    # collect module data into variables
    $modName          = $modInfo.Name
    $moduleFilePath   = $modInfo.Path -replace '\.psd1', '.psm1'
    $manifestFilePath = $modInfo.Path -replace '\.psm1', '.psd1'
    $moduleFolderPath = $modInfo.ModuleBase
    $modFileName      = Split-Path -Path $moduleFilePath -Leaf

    # get or generate Guid
    $guid = if ($modInfo.Guid -ne [guid]::Empty) {
        $modInfo.Guid
    }

    else {
        [guid]::NewGuid()
    }

    # list parameters of New-ModuleManifest
    $parameters = Get-Command -Name New-ModuleManifest | Select-Object -ExpandProperty Parameters
    [array]$parameterNames = $parameters.Keys

    # create and fill $params
    $params = @{
        Guid       = $guid
        Path       = $manifestFilePath
        RootModule = $modName
        Copyright  = "(c) {0}. All rights reserved." -f [datetime]::UtcNow.Year
    }

    # get values from module help header
    [hashtable]$modHeaderValues = GetHeaderValues -path $moduleFilePath

    # add version if missing
    if (-not $modHeaderValues.ContainsKey('ModuleVersion')) {
        $modHeaderValues.ModuleVersion = [version][datetime]::UtcNow.ToString('yy.M.d.Hmm')
    }

    # add params from module help header
    $parameterNames.ForEach{
        if ($modHeaderValues.ContainsKey($_)) {
            $params.$_ = $modHeaderValues.$_
        }
    }

    # generate manifest
    New-ModuleManifest @params

    # convert manifest file to UTF-8 no-BOM encoding for GitHub compatibility
    ConvertTo-Utf8 -Path $manifestFilePath

    # digitally sign the module file and the manifest file
    if ($modHeaderValues.ContainsKey('CertificateSerialNumber')) {
        $certificateSn = $modHeaderValues.CertificateSerialNumber

        # sign the .psm1 and .psd1 files
        Set-ScriptSignature -Path $moduleFilePath -CertificateSerialNumber $certificateSn | Write-Verbose
        Set-ScriptSignature -Path $manifestFilePath -CertificateSerialNumber $certificateSn | Write-Verbose

        if ($PSCmdlet.ParameterSetName -eq 'ise') {
            # reopen file in the ISE
            $psISE.CurrentPowerShellTab.Files.Remove($currentFile) | Write-Verbose
            $psISE.CurrentPowerShellTab.Files.Add($moduleFilePath) | Write-Verbose
        }
    }

    # re-import the module (don't use -PassThru!)
    Import-Module -FullyQualifiedName $manifestFilePath -Global -Force -ErrorAction Stop
    $modInfo = Get-Module -Name $modName

    # generate .md files
    if (-not $NoReadme) {
        New-GitHubModuleReadme -Name $modInfo.Name
        New-GitHubToolboxReadme
    }

    # report
    $modInfo | Format-List -Property Name, Description, Version, Author, CompanyName, Moduletype, ModuleBase, Path, @{
        Label = 'ExportedCommands'
        Expression = {
            $_.ExportedCommands.Keys -join "`n"
        }
    }

    if ($PSCmdlet.ParameterSetName -eq 'ise') {
        # reset cursor to previous position in Editor pane
        $editor.SetCaretPosition($currentLine,1)

        # activate Console pane
        $psISE.CurrentPowerShellTab.ConsolePane.Select(1,1,1,1)
    }

    # reset prompt and intellisence
    Register-TabExpansion2
}


New-Alias @script:NewAliasCommonParams -Name sign -Value Set-ScriptSignature

function Set-ScriptSignature {
<#
.SYNOPSIS
    Digitally sign a PowerShell script with code-signing certificate.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 2/14/2016

.EXAMPLE
    # Sign module and module manifest scrip files.
    Set-ScriptSignature -Path "$HOME\Documents\toolbox\Modules\ClcControl\ClcControl.psm1" -CertificateSerialNumber 01C685F0348E17E57ABF24E8FD6AFDDF
    Set-ScriptSignature -Path "$HOME\Documents\toolbox\Modules\ClcControl\ClcControl.psd1" -CertificateSerialNumber 01C685F0348E17E57ABF24E8FD6AFDDF

.LINK
    http://www.hanselman.com/blog/SigningPowerShellScripts.aspx

#>

    [CmdletBinding()]
    [SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]

    param (
        [Parameter(Mandatory)]
        [ValidateScript({Test-Path -Path $_})]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, ParameterSetName = 'SerialNumber')]
        [Alias('sn')]
        [string]$CertificateSerialNumber
    )

    end {
        if (-not $Certificate) {
            # find certificate by SN in the store
            $certificate = Get-ChildItem -Path Cert: -Recurse |
            Where-Object -Property SerialNumber -eq $CertificateSerialNumber
            if (-not $certificate) {
                throw "Certificate with SN '$certificateSn' not found in certification store."
            }
        }

        # sign the code
        Set-AuthenticodeSignature -Certificate $certificate -FilePath $Path
    }
}


# add type [qstring] ### TODO: decomm, this is solved in PS 5+
if (-not ([System.Management.Automation.PSTypeName]'qstring').Type) {
<#
Type [qstring] is used in ValidateSet attribute of DynamicParameters when valid values contain spaces or quotes.
See usage example fo [qstring] type in New-DynamicParameter:
    Get-Help New-DynamicParameter -Examples
#>
    $signature = @"
        public class qstring {
            public qstring(string quotedString) : this(quotedString, "'") {}
            public qstring(string quotedString, string quoteCharacter) {
                OriginalString = quotedString;
                _quoteCharacter = quoteCharacter;
            }
            public string OriginalString { get; set; }
            string _quoteCharacter;
            public override string ToString() {
                if (OriginalString.Contains(" ")) {
                    return string.Format("{1}{0}{1}", OriginalString, _quoteCharacter);
                } else {
                    return OriginalString;
                }
            }
        }
"@
    Add-Type -Language CSharp -TypeDefinition $signature -ErrorAction Continue
}


function New-DynamicParameter {
<#
.SYNOPSIS
    Create RuntimeDefinedParameter object for RuntimeDefinedParameterDictionary.
    Must be called from DynamicParam {} scriptblock of an advanced function.
    Begin {} and/or Process {} and/or End {} scriptblocks are mantatory in function body.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/11/2017

.EXAMPLE
    # New-DynamicParameter in an advanced function.

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


.NOTES

#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Alias,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [type]$Type = [string],

        [Parameter()]
        [AllowEmptyString()]
        [string]$ParameterSetName,

        [Parameter()]
        [byte]$Position,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$HelpMessage,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$HelpMessageBaseName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$HelpMessageResourceId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [object]$DefaultValue,

        [Parameter()]
        [ValidateCount(2,2)]
        [int[]]$ValidateCount,

        [Parameter()]
        [ValidateCount(2,2)]
        [int[]]$ValidateLength,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,

        [Parameter()]
        [Alias('values')]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        # can be [string[]] only: https://msdn.microsoft.com/en-us/library/ms714434
        [string[]]$ValidateSet,

        [Parameter()]
        [ValidateCount(2,2)]
        [object[]]$ValidateRange,

        [Parameter()]
        [switch]$AllowNull,

        [Parameter()]
        [switch]$AllowEmptyString,

        [Parameter()]
        [switch]$AllowEmptyCollection,

        [Parameter()]
        [switch]$Mandatory,

        [Parameter()]
        [switch]$ValueFromPipeline,

        [Parameter()]
        [switch]$ValueFromPipelineByPropertyName,

        [Parameter()]
        [switch]$ValueFromRemainingArguments,

        [Parameter()]
        [switch]$DontShow,

        [Parameter()]
        [switch]$ValidateNotNull,

        [Parameter()]
        [switch]$ValidateNotNullOrEmpty
    )

    # create attribute collection object
    $collection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

    # set Mandatory to $false if [switch]$Help is set in caller scope
    $mandatoryValue = if (
        (Test-Path -Path Variable:Help) -and
        $Help -is [switch] -and
        $Help.IsPresent
    ) {
        $false
    } else {
        $Mandatory.IsPresent
    }
    
    # create Parameter attribute and set [bool] properties
    $attribute = New-Object -TypeName System.Management.Automation.ParameterAttribute -Property @{
        Mandatory                       = $mandatoryValue
        ValueFromPipeline               = $ValueFromPipeline.IsPresent
        ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName.IsPresent
        ValueFromRemainingArguments     = $ValueFromRemainingArguments.IsPresent
        DontShow                        = $DontShow.IsPresent
    }

    # set other Parameter attribute properties
    @(
        'Position'
        'ParameterSetName'
        'HelpMessage'
        'HelpMessageBaseName'
        'HelpMessageResourceId'
    ).Where{
        $PsBoundParameters.ContainsKey($_)
    }.ForEach{
        $attribute.$_ = Get-Variable -Name $_ -ValueOnly
    }
    
    # add attribute to collection
    $collection.Add($attribute)

    # add other attributes if provided
    @(
        if ($PsBoundParameters.ContainsKey('Alias')) {
            New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList $Alias
        }

        if ($AllowEmptyCollection.IsPresent) {
            New-Object -TypeName System.Management.Automation.AllowEmptyCollectionAttribute
        }

        if ($AllowEmptyString.IsPresent) {
            New-Object -TypeName System.Management.Automation.AllowEmptyStringAttribute
        }

        if ($AllowNull.IsPresent) {
            New-Object -TypeName System.Management.Automation.AllowNullAttribute
        }

        if ($PsBoundParameters.ContainsKey('ValidateCount')) {
            New-Object -TypeName System.Management.Automation.ValidateCountAttribute -ArgumentList $ValidateCount
        }

        if ($PsBoundParameters.ContainsKey('ValidateLength')) {
            New-Object -TypeName System.Management.Automation.ValidateLengthAttribute -ArgumentList $ValidateLength
        }

        if ($ValidateNotNull.IsPresent) {
            New-Object -TypeName System.Management.Automation.ValidateNotNullAttribute
        }

        if ($ValidateNotNullOrEmpty.IsPresent) {
            New-Object -TypeName System.Management.Automation.ValidateNotNullOrEmptyAttribute
        }

        if ($PsBoundParameters.ContainsKey('ValidatePattern')) {
            New-Object -TypeName System.Management.Automation.ValidatePatternAttribute -ArgumentList $ValidatePattern
        }

        if ($PsBoundParameters.ContainsKey('ValidateRange')) {
            New-Object -TypeName System.Management.Automation.ValidateRangeAttribute -ArgumentList $ValidateRange
        }

        if ($PsBoundParameters.ContainsKey('ValidateScript')) {
            New-Object -TypeName System.Management.Automation.ValidateScriptAttribute -ArgumentList $ValidateScript
        }

        if ($PsBoundParameters.ContainsKey('ValidateSet')) {
            # ValidateSetAttribute does not accept values of $null and @(), so convert to empty string
            if (-not $ValidateSet) {$ValidateSet = [string]::Empty}
            New-Object -TypeName System.Management.Automation.ValidateSetAttribute -ArgumentList $ValidateSet
        }
    ).ForEach{
        $collection.Add($_)
    }

    # create parameter object
    $parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList $Name, $Type, $collection

    # set parameter default value if provided
    if ($PSBoundParameters['DefaultValue']) {
        $parameter.Value = $DefaultValue -as $Type
    }

    # return parameter object
    $parameter
}


function Register-JobRemove {
<#
.SYNOPSIS
    Remove jobs when state changed.
    Jobs streams forwarded to Host with switch -ReceiveJob and can not be captured to a variable or pipeline.
    Used to fire-and-forget background jobs, such as 'Sync-ToolboxCredential'.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 9/22/2016
    Updated : 

.EXAMPLE
    # Job will be removed when completed without any output.
    Start-Job -ScriptBlock {ping google.com} | Register-JobRemove

.EXAMPLE
    # Job will be removed when completed with output to Host.
    Start-Job -ScriptBlock {ping google.com} | Register-JobRemove -ReceiveJob

.EXAMPLE
    # Trace route to google.com from CCNOC servers in a single job.
    # Job will be removed when completed with output to Host.
    $sessions = Connect-Ccnoc -Wait -PassThru
    Invoke-Command -AsJob -Session $sessions -ScriptBlock {trace google.com} | Register-JobRemove -ReceiveJob

.EXAMPLE
    # Trace route to google.com from CCNOC servers in individual jobs.
    # Jobs will be removed when completed with output to Host.
    Connect-Ccnoc -Wait -PassThru | Foreach-Object -Process {
        Invoke-Command -AsJob -Session $_ -JobName $_.Name -ScriptBlock {
            trace google.com
        } | Register-JobRemove -ReceiveJob
    }

.EXAMPLE
    # Test ping from CCNOC servers to each other CCNOC server.
    # Jobs will be removed when completed with output to Host.
    Connect-Ccnoc -Wait -PassThru | Foreach-Object -Process {
        Invoke-Command -AsJob -Session $_ -JobName $_.Name -ScriptBlock {
            Test-InfrastructurePing -Type CCNOC | Out-String
    } | Register-JobRemove -ReceiveJob}

.EXAMPLE
    # Test mtr from CCNOC servers to the same target.
    # Jobs will be removed when completed with output to Host.
    Connect-Ccnoc -Wait -PassThru | Foreach-Object -Process {
        Invoke-Command -AsJob -Session $_ -JobName $_.Name -ScriptBlock {
            Invoke-Mtr -Target 8.22.8.80 -DataCenter $env:COMPUTERNAME.Substring(0,3)
        } | Register-JobRemove -ReceiveJob
    }

.EXAMPLE
    # Test all output streams
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

.EXAMPLE
    # Six ways to invoke the same script and inherit environment pereferences

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

.LINK
    https://blogs.technet.microsoft.com/heyscriptingguy/2011/06/17/manage-event-subscriptions-with-powershell/

#>

    [CmdletBinding()]
    [SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]

    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [System.Management.Automation.Job[]]$Job,

        [Parameter()]
        [switch]$ReceiveJob
    )
    
    process {
        foreach ($j in $Job) {
            # params
            $param = @{
                InputObject = $j
                EventName = 'StateChanged'
                SourceIdentifier = "Job$($j.Id)-Remove"
                MessageData = @{
                    ReceiveJob = $ReceiveJob.IsPresent
                }
                Action = {
                    # remove event job
                    Unregister-Event -SourceIdentifier $event.SourceIdentifier -Force
                    Remove-Job -Name $event.SourceIdentifier -Force
                    # remove sender job
                    if ($event.MessageData.ReceiveJob) {
                        $res = Receive-Job -Job $sender *>&1
                        if ($res) {
                            $res | Out-Host
                            Write-Host -Object "Press ENTER to continue" -ForegroundColor Yellow
                        }
                    }
                    Remove-Job -Job $sender -Force
                }
            }

            # register job remove
            Register-ObjectEvent @param | Out-String | Write-Verbose
        }
    }
}


function Set-TimedJob {
<#
.SYNOPSIS
    Set a self-removed job started by a timer.
    Jobs streams forwarded to Host with switch -ReceiveJob and can not be captured to a variable or pipeline.
    Used to start delayed and recurring jobs.
    Default Interval (delay) is 10 sec. Default Repeat is 1.
    WARNING: Progress Stream always received.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 9/23/2016

.EXAMPLE
    # Ping google.com twice and receive output.
    Set-TimedJob -ScriptBlock {ping google.com} -Repeat 2 -ReceiveJob

.EXAMPLE
    # Ping google.com twice and receive output.
    Set-TimedJob -ScriptBlock {ping $args[0] -n $args[1]} -ArgumentList google.com, 2 -Repeat 2 -ReceiveJob

.EXAMPLE
    # Set PS window title to current time and repeat 10 times.
    Set-TimedJob -Repeat 10 -ScriptBlock {$Host.UI.RawUI.set_WindowTitle([datetime]::Now.ToString('G'))}

.EXAMPLE
    # Test all output streams
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

.LINK
    https://blogs.technet.microsoft.com/heyscriptingguy/2011/06/17/manage-event-subscriptions-with-powershell/

#>

    [CmdletBinding()]
    [SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]

    param (
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [Alias('args')]
        [object[]]$ArgumentList,

        [Parameter()]
        [ValidateRange(10,[uint16]::MaxValue)]
        [Alias('Delay')]
        [uint16]$Interval = 10,

        [Parameter()]
        [ValidateRange(1,[uint64]::MaxValue)]
        [uint64]$Repeat = 1,

        [Parameter()]
        [switch]$ReceiveJob
    )

    process {
        $timer = New-Object -TypeName System.Timers.Timer -Property @{
            Interval = $Interval * 1000
            Enabled = $true
            AutoReset = $true
        }
        $timer.Start()
    
        $messageData = @{
            ScriptBlock = $ScriptBlock
            ArgumentList = $ArgumentList
            Repeat = $Repeat
            ReceiveJob = $ReceiveJob.IsPresent
        }

        Register-ObjectEvent -InputObject $timer -MessageData $messageData -EventName Elapsed -Action {
            $param = @{
                ScriptBlock  = $Event.MessageData.ScriptBlock
                ArgumentList = $Event.MessageData.ArgumentList
                NoNewScope   =  $true
                ErrorAction  = 'Continue'
            }
            $res = Invoke-Command @param *>&1

            if ($res -and $Event.MessageData.ReceiveJob) {
                $res | Out-Host
#                Write-Host -Object 'Press ENTER to continue' -ForegroundColor Yellow
            }

            $script:counter ++

            if ($counter -ge $Event.MessageData.Repeat) {
                Unregister-Event -SourceIdentifier $Event.SourceIdentifier
                Remove-Job -Name $Event.SourceIdentifier
            }
        } | Out-String | Write-Verbose
    }
}


function Compress-ScriptBlock {
<#
.SYNOPSIS
    Compress a scriptblock by removing comments, empty lines, trailing and leading spaces.
    Used in Invoke-Parallel to maximize script payload to PsProcess.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/31/2018
    Updated : 9/25/2018

.EXAMPLE
    Compress-ScriptBlock -ScriptBlock ${function:Compress-ScriptBlock}

.EXAMPLE
    ${function:Compress-ScriptBlock} | Compress-ScriptBlock

#>

    [CmdletBinding()]

    param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [scriptblock]$ScriptBlock
    )

    # remove comment blocks
    $text = [string]$ScriptBlock  -replace '(?=(^|\s)\<#)((.|\n)+?)(?<=#\>)'

    # split to lines
    [array]$array = $text -split "`n"

    # trim lines
    $array = $array.Trim()

    # remove comments following # in beginning of a line only
    # as # can be in strings (i.e. regex, here-string, etc.)
    $array = $array -replace '^#.*'

    # replace multiple spaces
    $array = $array -replace '\s+', ' '

    # remove spaces before and after | = + ( ) { } , 
    $array = $array -replace '\s*(\=|\+|\{|\}|\(|\)|,)\s*', '$1'

    # combine not empty lines to multiline string
    $text = $array.Where{$_} -join "`n"

    <#$null#>

    # return
    [scriptblock]::Create($text)
}


function Invoke-Parallel {
<#
.SYNOPSIS
    Invoke ScriptBlock in parallel. Available methods:
    - Runspace (default). Each instance runs in own Runspace in the same PS instance (multi threaded)
    - RunspacePool. Each instance runs in own Runspace in a dedicated Runspace Pool in the same PS instance (multi threaded)
    - RemoteRunspace. Each instance runs in own Runspace in own PS Process (multi processed)
    - Process. Each instance runs in own PS Process (multi processed)
    - Job. Each instance runs in own PS Job (multi processed)

    NOTES:
    - Synchronized variables are available in Runspace and RunspacePool modes only.
      Supported types are [hashtable], [System.Collections.ArrayList], [System.Collections.Queue]
    - VMware sdk can run in RemoteRunspace, Process, Job modes only.
    - OutputFormat and NoCleanup are for Process mode only.
    - If the scriptblock is too large, it may fail with exception:
      Invoke-Parallel : Exception calling "Start" with "0" argument(s): "The filename or extension is too long"
    - When calling from Invoke-ScheduledCommand -Method Process, use -NoCleanup, otherwise it will hang.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 4/16/2017
    Updated : 3/23/2019

.PARAMETER ScriptBlock
    Script block which will be executed in each instance.

.PARAMETER ParameterSet
    Array of hashtables with parameter names/values for the ScripBlock.
    Number of items in the array determines number of parallel instances.
    Can be an empty hashtable (that is no parameters).

.PARAMETER CommonParameterSet
    Hashtable with common parameter names/values for the ScripBlock.
    Parameters provided here are passed to each instance.
    Can be an empty hashtable (that is no common parameters).

.PARAMETER TimeOutMs
    Max time to wait for each instance to complete.
    If instance is still running, it's forcibly terminated and destroyed even when incomplete.
    Default is 4294967295 ms (~50 days).

.EXAMPLE
    # Testing.
    (Invoke-Parallel -ScriptBlock {Get-Module -ListAvailable}).Count | Should BeGreaterThan 0

.EXAMPLE
    # Single-thread, no parameters.
    Invoke-Parallel -ScriptBlock {ping google.com}

.EXAMPLE
    # Multy-thread, single parameter, single common parameter.
    Invoke-Parallel -ScriptBlock {param($name, $qty); ping $name -n $qty} -ParameterSet @{name = 'google.com'}, @{name = 'facebook.com'} -CommonParameterSet @{qty = 2}

.EXAMPLE
    # Multy-thread, multy-parameter.
    Invoke-Parallel -ScriptBlock {param($name, $qty); ping $name -n $qty} -ParameterSet @{name = 'google.com'; qty = 6}, @{name = 'facebook.com'; qty = 2}

.EXAMPLE
    # Multy-thread, with TimeOutMs (one instance will timeout).
    Invoke-Parallel -ScriptBlock {param($name, $qty); ping $name -n $qty} -ParameterSet @{name = 'google.com'; qty = 6}, @{name = 'facebook.com'; qty = 2} -TimeOutMs 2000

.EXAMPLE
    # Test all streams.
    Invoke-Parallel -ScriptBlock {
        [CmdletBinding()] param ()
        '1. Output Stream'      | Write-Output
        '2. Error Stream'       | Write-Error
        '3. Warning Stream'     | Write-Warning
        '4. Debug Stream'       | Write-Debug
        '5. Verbose Stream'     | Write-Verbose
        '6. Information Stream' | % {Write-Information -MessageData $_}
    } -Verbose -Debug -ErrorAction Continue -WarningAction Continue -InformationAction Continue

.EXAMPLE
    # Use InitializationScript.
    Invoke-Parallel -InitializationScript {ipmo VMware.VimAutomation.Core} -ScriptBlock {gmo} -Method Runspace

.EXAMPLE
    # Use syncronized [hashtable].
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

.EXAMPLE
    # Use syncronized [ArrayList].
    $var = [System.Collections.ArrayList]::new()
    Invoke-Parallel -ParameterSet @{}, @{} -ScriptBlock {
        [void]$SyncronizedObject.Add('a')
        $SyncronizedObject.Count
    } -Method RunspacePool -SyncronizedObject $var
    $var

.EXAMPLE
    # Use syncronized [Queue].
    $var = [System.Collections.Queue]::new()
    Invoke-Parallel -ParameterSet @{}, @{} -ScriptBlock {
        $SyncronizedObject.Enqueue($pid)
        $SyncronizedObject.Count
    } -Method RunspacePool -SyncronizedObject $var
    $var

.EXAMPLE
    # Test: First instance should throw, second should complete, third should timeout
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

.LINK
    https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/

.NOTES
    RemoteRunspace flow:
    1. For each parameter set
    - new PowerShellProcessInstance
    - new, open OutOfProcessRunspace
    - new Powershell
    - add script and params to Powershell
    - set PowerShell.Runspace to OutOfProcessRunspace
    - start PowerShell.BeginInvoke()
    2. Wait for completion or timeout
    3. Foreach handle
    - if IsCompeted, powershell.EndInvoke(), else powershell.Stop()
    - receive all Streams
    - dispose runspace
    - dispose instance
    - dispose powershell

    Runspace flow:
    1. For each parameter set
    - new, open Runspace
    - new Powershell
    - add script and params to Powershell
    - set PowerShell.Runspace to Runspace
    - start PowerShell.BeginInvoke()
    2. Wait for completion or timeout
    3. Foreach handle
    - if IsCompeted, powershell.EndInvoke(), else powershell.Stop()
    - receive all Streams
    - dispose runspace
    - dispose powershell

    RunspacePool flow:
    1. new and open RunspacePool
    2. For each parameter set
    - new Powershell
    - add script and params to Powershell
    - set PowerShell.RunspacePool to RunspacePool
    - start PowerShell.BeginInvoke()
    2. Wait for completion or timeout
    3. Foreach handle
    - if IsCompeted, powershell.EndInvoke(), else powershell.Stop()
    - receive all Streams
    - dispose RunspacePool
    - dispose powershell

#>

    [CmdletBinding()]
    
    param (
        [Parameter(ValueFromPipeline, Position = 0)]
        [AllowEmptyCollection()]
        [hashtable[]]$ParameterSet = @{},

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [AllowEmptyCollection()]
        [hashtable]$CommonParameterSet = @{},

        [Parameter()]
        [Alias('StartupScript')]
        [scriptblock]$InitializationScript = {},

        [Parameter()]
        [ValidateRange(10, [Int32]::MaxValue)]
        [uint32]$TimeoutMs = [Int32]::MaxValue, # ~ 25 days

        [Parameter()]
        [ValidateSet('Runspace', 'RunspacePool', 'RemoteRunspace', 'Process', 'Job')]
        [string]$Method = 'Runspace',

        [Parameter()]
        [ValidateSet('Text', 'Xml')]
        [string]$OutputFormat = 'Xml',

        [Parameter()]
        [AllowEmptyCollection()]
        [object]$SyncronizedObject,

        [Parameter()]
        [switch]$NoCleanup
    )

    begin {
        $parameterSets = @()
    }

    process {
        $ParameterSet | ForEach-Object -Process {
            $parameterSets += $_
        }
    }

    end {
        # set ErrorActionPreference Continue to avoid stop on errors
        if ($ErrorActionPreference -eq 'Stop') {
            $ErrorActionPreference = 'Continue'
        }


        #region START FUNCTIONS

        function StartJobTasks {
            $standardParameters = @{
                Verbose           = $VerbosePreference
                Debug             = $DebugPreference
                ErrorAction       = $ErrorActionPreference
                InformationAction = $InformationPreference
                WarningAction     = $WarningPreference
            }

            foreach ($paramSet in $parameterSets) {
                $parameters = $paramSet + $CommonParameterSet + $standardParameters
                $arguments  = $ScriptBlock, $parameters

                $script = {
                    $ScriptBlock = $args[0]
                    $Parameters  = $args[1]

                    $Function:ScriptBlock = $ScriptBlock

                    ScriptBlock @Parameters
                }

                $job = Start-Job -ScriptBlock $script -ArgumentList $arguments -InitializationScript $InitializationScript

                # return handle
                @{
                    job       = $job
                    stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                }
            }
        }

        function StartProcessTasks {
            function EncodeCommand ([string]$command, [switch]$compress) {
                if ($compress) {
                    # in-memory compress, then unicode into base64. in-process decode, decompress and execute
                    $bytes = [System.Text.Encoding]::ASCII.GetBytes($command)
                    $memStream = [System.IO.MemoryStream]::new()
                    $defStream = [System.IO.Compression.DeflateStream]::new($memStream, [System.IO.Compression.CompressionMode]::Compress)
                    $defStream.Write($bytes, 0, $bytes.Length)
                    $defStream.Dispose()
                    $bytes = $memStream.ToArray()
                    $memStream.Dispose()
                    $base64 = [System.Convert]::ToBase64String($bytes)

                    # Generate the code that will decompress and execute the payload.
#                    $command = 'sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$base64'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'
                    $command = @"
`$ProgressPreference='SilentlyContinue'
`$ms=[IO.MemoryStream][Convert]::FromBase64String('$base64')
`$ds=[IO.Compression.DeflateStream]::new(`$ms,[IO.Compression.CompressionMode]::Decompress)
`$cm=[IO.StreamReader]::new(`$ds,[Text.Encoding]::ASCII).ReadToEnd()
[scriptblock]::Create(`$cm).Invoke()
"@

                }

                # MUST be Unicode
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
                [System.Convert]::ToBase64String($bytes)
            }

            function ConvertToArguments ([hashtable]$parameters) {
                $params = $parameters.GetEnumerator().ForEach{
                    $name  = [string]$_.Name
                    $value = @($_.Value).ForEach{"'$_'"} -join ','

                    if ($value) {
                        "-$name $value"
                    } else {
                        "-$name"
                    }
                } -join ' '

                # build script to execute
                $script = [scriptblock]::Create(@"
`$ProgressPreference='SilentlyContinue'
.{$InitializationScript}
function Invoke{$ScriptBlock}
Invoke $params
"@) | Compress-ScriptBlock

#                $script | Write-Verbose

                # convert to Unicode base64 payload
                $encodedCommand = EncodeCommand -command $script -compress


                # return arguments array for powershell.exe
                @(
                    '-noni'                # -NonInteractive
                    '-nop'                 # -NoProfile
                    '-nol'                 # -NoLogo
                    '-w Hidden'            # -WindowStyle
                    '-exe Unrestricted'    # -ExecutionPolicy
                    '-mta'                 # -Mta/Sta
                    "-out $OutputFormat"   # -OutputFormat
                    "-enc $encodedCommand" # -EncodedCommand
                )
            }

            foreach ($paramSet in $parameterSets) {
                # create parameters string
                $parameters = $paramSet + $CommonParameterSet
                $arguments = ConvertToArguments -parameters $parameters

                # create process start info
                $startInfo = [System.Diagnostics.ProcessStartInfo]::new("$PSHOME\powershell.exe")
                $startInfo.UseShellExecute        = $false  # start the process from it's own executable file
#                $startInfo.RedirectStandardInput  = $true
                $startInfo.RedirectStandardOutput = $true
                $startInfo.RedirectStandardError  = $true
                $startInfo.CreateNoWindow         = $true
                $startInfo.WindowStyle            = 'hidden'
                $startInfo.Verb                   = 'runas'
                $startInfo.Arguments              = $arguments

                # create process
                $process = [System.Diagnostics.Process]::new()
                $process.StartInfo           = $startInfo
                $process.EnableRaisingEvents = $true

                # unique id for subscriptions
                $guid = [string][guid]::NewGuid()

                # create timer, variable name must be unique to avoid conflicts
                $timerVar = New-Variable -Name Timer_$guid -Value ([System.Timers.Timer]::new()) -PassThru
                $timerVar.Value.Interval  = $TimeoutMs
                $timerVar.Value.AutoReset = $false

                # this object can send data to and receive data from events' Action script blocks
                $messageData = @{
                    prid    = $null
                    stdout  = [System.Text.StringBuilder]::new()
                    stderr  = [System.Text.StringBuilder]::new()
                    errors  = @()
                    verbose = $VerbosePreference
                }

                # collection of subscribtion jobs
                $jobs = @()

                # subscribe to process OutputDataReceived event
                $jobs += Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -SourceIdentifier OnOutput_$guid -MessageData $messageData -Action {
                    $ErrorActionPreference = 'Stop'
                    $VerbosePreference     = $Event.Messagedata.verbose

                    $prid      = $Event.Sender.Id
                    $eventName = $EventSubscriber.EventName
                    $eventData = $EventArgs.Data

                    trap {
                        "{0} Process $prid $eventName event hadler exception: {1}" -f [datetime]::UtcNow.ToString('o'), $_.Exception.Message | Write-Warning
                    }

                    #"{0} Process $prid $eventName event handler started" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                    #"{0} Process $prid $eventName data length: {1}" -f [datetime]::UtcNow.ToString('o'), $eventData.Length | Write-Verbose

                    if (-not [string]::IsNullOrEmpty([string]$eventData)) {
                        $Event.MessageData.stdout.AppendLine([string]$eventData)
                    }

                    #"{0} Process $prid $eventName event handler ended" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                }

                # subscribe to process ErrorDataReceived event
                $jobs += Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -SourceIdentifier OnError_$guid -MessageData $messageData -Action {
                    $ErrorActionPreference = 'Stop'
                    $VerbosePreference     = $Event.Messagedata.verbose

                    $prid      = $Event.Sender.Id
                    $eventName = $EventSubscriber.EventName
                    $eventData = $EventArgs.Data

                    trap {
                        "{0} Process $prid $eventName event hadler exception: {1}" -f [datetime]::UtcNow.ToString('o'), $_.Exception.Message | Write-Warning
                    }

                    #"{0} Process $prid $eventName event handler started" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                    #"{0} Process $prid $eventName data length: {1}" -f [datetime]::UtcNow.ToString('o'), $eventData.Length | Write-Verbose

                    if (-not [string]::IsNullOrEmpty([string]$eventData)) {
                        $Event.MessageData.stderr.AppendLine([string]$eventData)
                    }

                    #"{0} Process $prid $eventName event handler ended" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                }

                <# NOT USED subscribe to process Exited event
                $jobs += Register-ObjectEvent -InputObject $process -EventName Exited -SourceIdentifier OnExit_$guid -MessageData $messageData -MaxTriggerCount 1 -Action {
                    $ErrorActionPreference = 'Stop'
                    $VerbosePreference     = $Event.Messagedata.verbose

                    $prid      = $Event.Sender.Id
                    $eventName = $EventSubscriber.EventName

                    trap {
                        "{0} Process $prid $eventName event hadler exception: {1}" -f [datetime]::UtcNow.ToString('o'), $_.Exception.Message | Write-Warning
                    }

                    "{0} Process $prid $eventName event handler started" -f [datetime]::UtcNow.ToString('o') | Write-Verbose

                    "{0} Process $prid $eventName event handler ended" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                }
                #>

                # subscribe to timer Elapsed event
                $jobs += Register-ObjectEvent -InputObject $timerVar.Value -EventName Elapsed -SourceIdentifier OnElapsed_$guid -MessageData $messageData -MaxTriggerCount 1 -Action {
                    $ErrorActionPreference = 'Stop'
                    $VerbosePreference = $Event.Messagedata.verbose

                    $prid      = $Event.MessageData.process.Id
                    $eventName = $EventSubscriber.EventName

                    trap {
                        "{0} Timer $eventName event for process $prid hadler exception: {1}" -f [datetime]::UtcNow.ToString('o'), $_.Exception.Message | Write-Warning
                    }

                    #"{0} Timer $eventName event for process $prid handler started" -f [datetime]::UtcNow.ToString('o') | Write-Verbose

                    #"{0} Timer $eventName event for process $prid killing process on timeout {1} ms" -f [datetime]::UtcNow.ToString('o'), $Event.Sender.Interval | Write-Verbose
                    $Event.MessageData.process.Kill()
                    #"{0} Timer $eventName event for process $prid killed process" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                    $Event.MessageData.errors += "Process $prid has not completed in {0} ms and was killed." -f $Event.Sender.Interval

                    #"{0} Timer $eventName event for process $prid handler ended" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                }

                # start process
                try {
                    [void]$process.Start()
                }

                catch {
                    $msg  = "Scriptblock maybe too large, try to reduce it.`n"
                    $msg += $_.Exception.Message
                    Write-Error -Message $msg -Category InvalidArgument -ErrorAction Stop
                }

                $process.BeginOutputReadLine()
                $process.BeginErrorReadLine()
                #"{0} Process {1} started" -f [datetime]::UtcNow.ToString('o'), $process.Id | Write-Verbose
                $messageData.process = $process

                # start timer
                $timerVar.Value.Start()
                #"{0} Timer for process {1} started, interval {2} ms" -f [datetime]::UtcNow.ToString('o'), $process.Id, $timerVar.Value.Interval | Write-Verbose

                # return handle
                @{
                    process = $process
                    prid    = $process.Id
                    guid    = $guid
                    data    = $messageData
                    timer   = $timerVar.Value
                    jobs    = $jobs
                }
            }
        }

        # common function for Runspace, RemoteRunspace, RunspacePool
        function NewPowershell ([hashtable]$parameters) {
            # create instance
            $powershell = [powershell]::Create()

            # add scripts and parameters
            [void]$powershell.AddScript($InitializationScript)
            [void]$powershell.AddScript($ScriptBlock)
            [void]$powershell.AddParameters([System.Collections.IDictionary]$parameters)
            [void]$powershell.AddParameters([System.Collections.IDictionary]@{
                Verbose           = $VerbosePreference
                Debug             = $DebugPreference
                ErrorAction       = $ErrorActionPreference
                InformationAction = $InformationPreference
                WarningAction     = $WarningPreference
            })

            # return
            $powershell
        }

        # common function for Runspace, RunspacePool
        function NewInitialSessionState {
            $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $sessionState.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass

            # InitializationScript added in NewPowershell
            #[void]$sessionState.StartupScripts.Add({$InitializationScript})

            # add syncronized variable
            if ($null -ne $SyncronizedObject) {
                if ($SyncronizedObject -is [hashtable]) {
                    $synced = [hashtable]::Synchronized($SyncronizedObject)
                }

                elseif ($SyncronizedObject -is [System.Collections.ArrayList]) {
                    $synced = [System.Collections.ArrayList]::Synchronized($SyncronizedObject)
                }

                elseif ($SyncronizedObject -is [System.Collections.Queue]) {
                    $synced = [System.Collections.Queue]::Synchronized($SyncronizedObject)
                }

                else {
                    $synced = $SyncronizedObject
                }

                $variable = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('SyncronizedObject', $synced, $null)
                [void]$sessionstate.Variables.Add($variable)
            }

            $sessionState
        }

        function StartRunspaceTasks {
            foreach ($paramSet in $parameterSets) {
                # create and open Runspace
                $sessionState = NewInitialSessionState
                $runspace = [runspacefactory]::CreateRunspace($sessionState)
                $runspace.ThreadOptions = 'ReuseThread'
                $runspace.Open()

                # create Powershell
                $parameters = $paramSet + $CommonParameterSet
                $powershell = NewPowershell -parameters $parameters

                # set Runspace for the Powershell
                $powershell.Runspace = $runspace

                # invoke
                $job = $powershell.BeginInvoke()

                # return handle
                @{
                    powershell = $powershell
                    job        = $job
                    stopwatch  = [System.Diagnostics.Stopwatch]::StartNew()
                }
            }
        }

        function StartRemoteRunspaceTasks {
            foreach ($paramSet in $parameterSets) {
                # create and open RemoteRunspace
                $typetable = [System.Management.Automation.Runspaces.TypeTable]::LoadDefaultTypeFiles()

                # InitializationScript added in NewPowershell
                #$instance = [System.Management.Automation.Runspaces.PowerShellProcessInstance]::new($null, $null, $InitializationScript, $true)
                $instance = [System.Management.Automation.Runspaces.PowerShellProcessInstance]::new()
                $runspace = [runspacefactory]::CreateOutOfProcessRunspace($typetable, $instance)
                $runspace.Open()

                # create Powershell
                $parameters = $paramSet + $CommonParameterSet
                $powershell = NewPowershell -parameters $parameters

                # set Runspace for the Powershell
                $powershell.Runspace = $runspace

                # invoke
                $job = $powershell.BeginInvoke()

                # return handle
                @{
                    instance   = $instance
                    powershell = $powershell
                    job        = $job
                    stopwatch  = [System.Diagnostics.Stopwatch]::StartNew()
                }
            }
        }

        function NewRunspacePool {
            # create and open RunspacePool
            $sessionState = NewInitialSessionState
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ParameterSet.Count, $sessionState, $Host)
            $runspacePool.Open()
            $runspacePool
        }

        function StartRunspacePoolTasks ([System.Management.Automation.Runspaces.RunspacePool]$runspacepool) {
            foreach ($paramSet in $parameterSets) {
                $parameters = $paramSet + $CommonParameterSet
                $powershell = NewPowershell -parameters $parameters

                # set runspace pool for the instance
                $powershell.RunspacePool = $runspacepool

                # invoke
                $job = $powershell.BeginInvoke()

                # return handle
                @{
                    powershell = $powershell
                    job        = $job
                    stopwatch  = [System.Diagnostics.Stopwatch]::StartNew()
                }
            }
        }

        #endregion


        #region END FUNCTIONS

        function StopJobTasks ([hashtable[]]$handles) {
            while ($handles) {
                foreach ($handle in $handles) {
                    if ($handle.job.State -ne 'Running') {
                        $handle.job | Receive-Job -Force -Wait -AutoRemoveJob -ErrorAction Continue
                        $handles = $handles -ne $handle
                    }

                    elseif ($handle.stopwatch.ElapsedMilliseconds -gt $TimeoutMs) {
                        $message = "Invoke-Parallel: Job has not completed in $TimeoutMs ms and was terminated."
                        $message    | Write-Error
                        $handle.job | Remove-Job -Force
                        $handles = $handles -ne $handle
                    }
                }
            }
        }

        function StopProcessTasks ([hashtable[]]$handles) {

            function ReceiveData ([hashtable]$data, [int32]$prid) {

                function ConvertFromCliXml ([string[]]$clixml, [string]$source) {
                    # convert from clixml
                    try {
                        # remove first line, which is '#< CLIXML' in clixml
                        $lines = $clixml -split "`n" | Select-Object -Skip 1

                        if ($lines) {
                            [System.Management.Automation.PSSerializer]::Deserialize($lines)
                        }
                    }

                    catch {
                        "Failed to deserialize {0} from process {1}:`n{2}." -f $source, $prid, $clixml | Write-Warning
                    }
                }

                if ($data.stdout.Length) {
                    $stdout = [string]$data.stdout

                    switch ($OutputFormat) {
                        Xml {
                            ConvertFromCliXml -clixml $stdout -source stdout | Write-Output
                        }

                        Text {
                            $stdout -join "`n" | Write-Output
                        }
                    }
                }

                if ($data.stderr.Length) {
                    $stderr = [string]$data.stderr

                    switch ($OutputFormat) {
                        Xml {
                            ConvertFromCliXml -clixml $stderr -source stdout | Write-Error
                        }

                        Text {
                            #ConvertFromCliXml -clixml (-join $stderr) -source stdout | Write-Error
                            -join $stderr | Write-Error
                        }
                    }
                }

                if ($data.errors.Count) {
                    $data.errors.ForEach{
                        "Invoke-Parallel: {0}" -f $_ | Write-Error
                    }
                }
            }

            while ($handles) {
                foreach ($handle in $handles) {
                    # process exited?
                    $process = $handle.process

                    if ($process.HasExited -or -not $process.Id) {
                        #"{0} Process Id {1} HasExited: {2}" -f [datetime]::UtcNow.ToString('o'), $process.Id, $process.HasExited | Write-Verbose

                        # stop and dispose the timer
                        $handle.timer.Stop()
                        $handle.timer.Dispose()
                        #"{0} Timer for process {1} disposed" -f [datetime]::UtcNow.ToString('o'), $process.Id | Write-Verbose

                        # receive data from the process
                        $prid = $handle.prid
                        #"{0} Receiving data from process {1}" -f [datetime]::UtcNow.ToString('o'), $prid | Write-Verbose
                        ReceiveData -data $handle.data -prid $prid

                        if ($NoCleanup) {
                            "{0} Skipped cleaning up after process $prid" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                        }

                        else {
                            #"{0} Cleaning up after process $prid" -f [datetime]::UtcNow.ToString('o') | Write-Verbose
                            $guid = $handle.guid
                            Get-EventSubscriber -SourceIdentifier *_$guid | Unregister-Event
#                            Get-Job -Name *_$guid | Remove-Job -Force
                            Remove-Job -Job $handle.jobs -Force
                        }

                        $handles = $handles.Where{$_.prid -ne $prid}
                        #"{0} Remaining Processes count: {1}" -f [datetime]::UtcNow.ToString('o'), $handles.Count | Write-Verbose
                    }

                    Start-Sleep -Milliseconds 10
                }
            }
        }

        # common Stop function for Runspace, RemoteRunspace, RunspacePool
        function StopRunspaceTasks ([hashtable[]]$handles) {

            function TestStopTask ([hashtable]$handle) {
                $handle.job.IsCompleted -or
                $handle.stopwatch.ElapsedMilliseconds -gt $TimeoutMs
            }
            
            function StopTask ([hashtable]$handle) {
                function OutStreams ([System.Management.Automation.PSDataStreams]$streams) {
                    $streams.Error       | ForEach-Object -Process {Write-Error -ErrorRecord $_}
                    $streams.Warning     | Write-Warning
                    $streams.Debug       | Write-Debug
                    $streams.Verbose     | Write-Verbose
                    $streams.Progress    | Out-Null
                    $streams.Information | ForEach-Object -Process {Write-Information -MessageData $_}
                }

                function Cleanup ([hashtable]$handle) {
                    if ($handle.powershell.Runspace) {
                        $handle.powershell.Runspace.Close()
                        $handle.powershell.Runspace.Dispose()
                    }

                    if ($handle.PsObject.Properties.Name -contains 'Instance') {
                        $handle.Instance.Dispose()
                    }

                    $handle.powershell.Dispose()
                }

                if ($handle.job.IsCompleted) {
                    $handle.powershell.EndInvoke($handle.job)
                }

                else {
                    $message = "Invoke-Parallel: $Method thread has timed out in $TimeoutMs ms and was terminated."
                    $message | Write-Error
                    $handle.powershell.Stop()
                }

                OutStreams -streams $handle.powershell.Streams
                Cleanup -handle $handle
            }

            while ($handles) {
                foreach ($handle in $handles) {
                    if (TestStopTask -handle $handle) {
                        StopTask -handle $handle
                        $handles = $handles -ne $handle
                    }
                }
            }
        }

        function RemoveRunspacePool ([System.Management.Automation.Runspaces.RunspacePool]$runspacepool) {
            $runspacePool.Close()
            $runspacePool.Dispose()
        }

        #endregion


        #region INVOKE

        switch ($Method) {
            Job {
                $handles = StartJobTasks
                StopJobTasks -handles $handles
            }

            Process {
                $globalsw = [System.Diagnostics.Stopwatch]::StartNew()
                $handles  = StartProcessTasks
                StopProcessTasks -handles $handles
            }

            Runspace {
                $handles = StartRunspaceTasks
                StopRunspaceTasks -handles $handles
            }

            RemoteRunspace {
                $handles = StartRemoteRunspaceTasks
                StopRunspaceTasks -handles $handles
            }

            RunspacePool {
                $runspacePool = NewRunspacePool
                $handles = StartRunspacePoolTasks -runspacepool $runspacePool
                StopRunspaceTasks -handles $handles
                RemoveRunspacePool -runspacepool $runspacePool
            }
        }

        #endregion


        # collect garbage
        Clear-Garbage
    }
}


function Invoke-Retry {
<#
.SYNOPSIS
    Invoke a command with retries.
    Default is 3 retries.
    Delay is exponential from 1 sec up.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 6/11/2018
    Updated : 6/13/2018

.EXAMPLE
    # Using a Command.
    Invoke-Retry -Command Get-Module

.EXAMPLE
    # Using a scriptblock.
    Invoke-Retry -scriptblock {Get-Module}

.EXAMPLE
    # Using a scriptblock with variables from the current scope.
    $name = 'Tool*'
    Invoke-Retry -ScriptBlock {Get-Module -Name $name}

.EXAMPLE
    # Using a command with parameterset.
    $params = @{
        Name = 'Tool*'
    }
    Invoke-Retry -Command Get-Module -ParameterSet $params

.EXAMPLE
    # Usage with API calls
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

#>

    [CmdletBinding(DefaultParameterSetName = 'Command')]

    param (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Command')]
        [string]$Command,

        [Parameter(Position = 0, Mandatory, ParameterSetName = 'ScriptBlock')]
        [scriptblock]$ScriptBlock,

        [Parameter(Position = 1, ParameterSetName = 'Command')]
        [hashtable]$ParameterSet,

        [Parameter()]
        [ValidateRange(1, 10)]
        [Alias('Count')]
        [byte]$MaxRetry = 3,

        [Parameter()]
        [Alias('Interval')]
        [uint16]$RetryIntervalMs = 1000
    )

    function GetErrorMessage ([System.Management.Automation.ErrorRecord]$err) {
        if ($err.Exception.Response) {
            $errResponse = $err.Exception.Response
            # [int]$errResponse.StatusCode # err Code
            # if ($errResponse.Message) {$errResponse.Message.ToString().Trim()} # err Messade
            $errResponseStream = $errResponse.GetResponseStream()
            $streamReader = [System.IO.StreamReader]::new($errResponseStream)
            $streamReader.ReadToEnd()
            $streamReader.Close()
        }

        else {
            $err.Exception.Message
        }
    }

    $ErrorActionPreference = 'Stop'
    $rateToSec = $RetryIntervalMs / 1000

    for ($i = 1; $i -le $MaxRetry; $i ++) {
        try {
            switch ($PSCmdlet.ParameterSetName) {
                Command {
                    if ($ParameterSet) {
                        . $Command @ParameterSet
                    }

                    else {
                        . $Command
                    }
                }

                ScriptBlock {
                    $script = [scriptblock]::Create($ScriptBlock)
                    . $script
                }
            }

            break
        }

        catch {
            if ($i -lt $MaxRetry) {
                GetErrorMessage -err $_ | Write-Verbose
                $milliseconds = [math]::pow($i, 2) * $RetryIntervalMs
                Start-Sleep -Milliseconds $milliseconds
            }

            else {
                GetErrorMessage -err $_ | Write-Error
            }
        }
    }
}


function Invoke-ScheduledCommand {
<#
.SYNOPSIS
    Invoke ScriptBlock at an interval.
    Used as a workaround in Containers as Scheduled Tasks are not supported.

    NOTES:
    - Output Stream redirected to Information Stream in host instance.
    - Error Stream redirected to Warning Stream in host instance.
    - All other Streams are not redirected and received by host instance.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 10/9/2017
    Updated : 12/16/2018

.PARAMETER ScriptBlock
    Mandatory. Script block which will be executed on schedule.

.PARAMETER Interval
    Mandatory. Interval.

.PARAMETER StartTime
    Optional. Default - [datetime]::Today.

.PARAMETER EndTime
    Optional. Default - [datetime]::MaxValue.

.PARAMETER RunCount
    Optional. Number of invocations.

.PARAMETER JobName
    Optional. Default - [System.Guid]::NewGuid().Guid.

.EXAMPLE
    # Simplest
    Invoke-ScheduledCommand -ScriptBlock {'test'} -Interval 0:0:10 -EndTime ([datetime]::Now.AddSeconds(30)) -verbose

.EXAMPLE
    # Testing schedule.
    Invoke-ScheduledCommand -RunNow -Interval 0:0:1 -EndTime ([datetime]::Now.AddSeconds(5)) -ScriptBlock {
        [datetime]::Now.ToString('HH:mm:ss.fff')
        $timer = $input.Sender
        $timer.Autoreset
    }

.EXAMPLE
    # Use with Invoke-Parallel -Method Process
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

.EXAMPLE
    # Test all Streams:
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

.EXAMPLE
    # Test precision, start time 100 years ago. Also randomly skips events due to intentional delay.
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

.EXAMPLE
    # Report $Event values from within the payload script.
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


.NOTES
    # TEST WITH VMWARE CONTAINER FIRST
    $ps = [powershell]::Create()
    $thread = $ps.AddScript($script, $true)
    $handle = $thread.BeginInvoke()

    if ($handle.AsyncWaitHandle.WaitOne($interval, $true)) {
        [void]$thread.EndInvoke($handle)
        $thread.EndInvoke($handle) | Write-Host -ForegroundColor Yellow
    }

    $ps.Dispose()
    $thread.Dispose()
    $handle.AsyncWaitHandle.Dispose()

#>

    [CmdletBinding(DefaultParameterSetName = 'EndTime')]
    
    param (
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [Alias('args')]
        [object[]]$ArgumentList,

        [Parameter(Mandatory)]
        [timespan]$Interval,

        [Parameter()]
        [datetime]$StartTime = [datetime]::Today,

        [Parameter(ParameterSetName = 'EndTime')]
        [datetime]$EndTime = [datetime]::MaxValue,

        [Parameter(ParameterSetName = 'RunCount')]
        [uint64]$RunCount,

        [Parameter()]
        [switch]$RunNow,

        [Parameter()]
        [switch]$RunAsync,

        [Parameter()]
        [Alias('name')]
        [string]$JobName = [guid]::NewGuid(),

        [Parameter()]
        [switch]$Passthru
    )

    function GetNextRun ([datetime]$start, [timespan]$interval) {
        while ($start -le [datetime]::UtcNow) {$start = $start.Add($interval)}
        $start
<#
        # calculates timespan from now till next run in best possible ticks precision
        while ($start -ge [datetime]::UtcNow) {$start = $start.AddYears(-1)}
        $startTicks = $start.Ticks
        $nowTicks   = [datetime]::UtcNow.Ticks
        $diffTicks  = $nowTicks - $startTicks
        $intTicks   = $interval.Ticks
        $intsCount  = [math]::DivRem($diffTicks, $intTicks, [ref]$null) + 1
        $nextTicks  = $startTicks + $intTicks * $intsCount
        [datetime]::FromBinary($nextTicks)
#>
    }

    function InvokePayload {
        [CmdletBinding()]

        param (
            # the Event itself, accessible in Payload script as $Event
            [object]$event,
            [bool]$runAsync
        )

        "{0}: {1} Payload script started" -f $event.MessageData.Counter, [datetime]::UtcNow.ToString($dtFormat) | Write-Verbose


        if ($runAsync) {
            $ps = [powershell]::Create()
            $ps.Runspace.SessionStateProxy.SetVariable('Event', $event)
            [void]$ps.AddScript($event.MessageData.ScriptBlock)
            $event.MessageData.ArgumentList.ForEach{[void]$ps.AddArgument($_)}
            [void]$ps.BeginInvoke()
        }

        else {
#            $ps.Invoke()
            Invoke-Command -ScriptBlock $event.MessageData.ScriptBlock -ArgumentList $event.MessageData.ArgumentList -Verbose:$VerbosePreference -Debug:$DebugPreference -WarningAction $WarningPreference -InformationAction $InformationPreference -ErrorAction Continue
        }

        "{0}: {1} Payload script ended."  -f $event.MessageData.Counter, [datetime]::UtcNow.ToString($dtFormat) | Write-Verbose
    }

    $dtFormat = 'yy-MM-dd HH\:mm\:ss\.fff'

    # counter variable
    $counterVar = New-Variable -Name ([string][guid]::NewGuid()) -Value 0 -PassThru

    # get first run
    $firstRun = if ($RunNow) {
        [datetime]::UtcNow.AddSeconds(1)
    }
    
    else {
        GetNextRun -start $StartTime -interval $Interval
    }

    # timer variable should have a unique name to avoid potential conflicts in the scope
    $timerVar    = New-Variable -Name ([string][guid]::NewGuid()) -Value $null -PassThru
    $timeToFirst = $firstRun - [datetime]::UtcNow
    $timerVar.Value = [System.Timers.Timer]::new($timeToFirst.TotalMilliseconds)
    $timerVar.Value.Autoreset = $false
    $timerVar.Value.Start()

    "{0} Payload first run scheduled for {1}" -f [datetime]::UtcNow.ToString('o'), $firstRun.ToString($dtFormat) | Write-Verbose

    $job = Register-ObjectEvent -InputObject $timerVar.Value -EventName Elapsed -SourceIdentifier $JobName -MessageData @{
        ScriptBlock    = $ScriptBlock
        ArgumentList   = $ArgumentList
        StartTime      = $StartTime
        EndTime        = $EndTime
        Interval       = $Interval
        RunCount       = $RunCount
        RunAsync       = $RunAsync.IsPresent
        Counter        = $counterVar.Value
        NextRun        = $nextRun
        dtFormat       = $dtFormat
        fGetNextRun    = Get-Item -Path function:GetNextRun
        fInvokePayload = Get-Item -Path function:InvokePayload
        Verbose        = $VerbosePreference
        Debug          = $DebugPreference
        Information    = $InformationPreference
    } -Action {
        # NEW SCOPE!
        $ErrorActionPreference = 'Stop'
        $dtFormat = $Event.MessageData.dtFormat

        $Event.MessageData.Counter ++
        Set-Item -Path function:GetNextRun    -Value $Event.MessageData.fGetNextRun
        Set-Item -Path function:InvokePayload -Value $Event.MessageData.fInvokePayload
        $Event.MessageData.NextRun = GetNextRun -start $Event.MessageData.StartTime -interval $Event.MessageData.Interval

        $VerbosePreference     = $Event.MessageData.Verbose
        $DebugPreference       = $Event.MessageData.Debug
        $InformationPreference = $Event.MessageData.Information

        "{0}: {1} Event script started" -f $Event.MessageData.Counter, [datetime]::UtcNow.ToString($dtFormat) | Write-Verbose

        trap {
            "{0}: {1} Event script exception: {2}" -f $Event.MessageData.Counter, [datetime]::UtcNow.ToString($dtFormat), $_.Exception.Message | Write-Warning
            continue
        }

        # invoke the payload and redirect output (if any) to Information stream
        InvokePayload -event $Event -runAsync $Event.MessageData.RunAsync -Verbose:$VerbosePreference |
        ForEach-Object -Process {
            Write-Information -InformationAction Continue -MessageData $_
        }

        # get the job running this Action
        $job = Get-Job -Name $Event.SourceIdentifier

        if ($job.Error)  {
            # redirect Error Stream to Warning Stream
            $job.Error | Write-Warning
        }

        # clear all job streams
        $job.Output.Clear()
        $job.Error.Clear()
        $job.Progress.Clear()
        $job.Verbose.Clear()
        $job.Warning.Clear()
        $job.Information.Clear()

        # recalculate next run, as it may be skipped in case of synchronious invocation
        $Event.MessageData.NextRun = GetNextRun -start $Event.MessageData.StartTime -interval $Event.MessageData.Interval

        # shall run again?
        $shallRunAgain = if ($Event.MessageData.RunCount) {
            $Event.MessageData.RunCount -gt $Event.MessageData.Counter
        }
        
        else {
            $Event.MessageData.NextRun -le $Event.MessageData.EndTime
        }

        if ($shallRunAgain) {
            # set interval to next run and start the timer
            $Event.Sender.Interval = ($Event.MessageData.NextRun - [datetime]::UtcNow).TotalMilliseconds
            $Event.Sender.Start()
            "{0}: {1} Next run: {2}" -f $Event.MessageData.Counter, [datetime]::UtcNow.ToString($dtFormat), $Event.MessageData.NextRun.ToString($dtFormat) | Write-Verbose
        }

        else {
            # clean up if next run if later than endtime
            $Event.Sender.Dispose()
            Unregister-Event -SourceIdentifier $Event.SourceIdentifier
            Remove-Job -Name $Event.SourceIdentifier
            "{0}: {1} Payload script will not run again" -f $Event.MessageData.Counter, [datetime]::UtcNow.ToString($dtFormat)  | Write-Verbose
        }

        Clear-Garbage
        "{0}: {1} Event script ended`n" -f $Event.MessageData.Counter, [datetime]::UtcNow.ToString($dtFormat) | Write-Verbose
    }

    if ($Passthru) {
        $job
    }
}


function Clear-Garbage {
<#
.SYNOPSIS
   Invoke garbage collection to release unused memory.
   This is an expensive operation, takes about a second.
   Potentially may result in deadlocks. Don't overuse.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 11/8/2018
    Updated : 11/8/2018

.EXAMPLE
    Clear-Garbage -Verbose

.LINK
    https://stackoverflow.com/questions/12265598/is-correct-to-use-gc-collect-gc-waitforpendingfinalizers
#>

    [CmdletBinding()]

    param ()

    [uint32]$memMB = [System.GC]::GetTotalMemory($false) / 1MB
    "Garbage collection: Memory before $memMB MB" | Write-Verbose

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
    [System.GC]::Collect([System.GC]::MaxGeneration, [System.GCCollectionMode]::Forced)
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()

    [uint32]$memMB = [System.GC]::GetTotalMemory($true) / 1MB
    "Garbage collection: Memory after  $memMB MB" | Write-Verbose
    "Garbage collection: Cleanup took  {0} ms" -f $sw.ElapsedMilliseconds | Write-Verbose
}

#endregion



#region OBJECT PROCESSING

function Join-Object {
<#
.SYNOPSIS
    Join data from two sets of objects based on a common value

.DESCRIPTION
    Join data from two sets of objects based on a common value

    For more details, see the accompanying blog post:
        http://ramblingcookiemonster.github.io/Join-Object/

    For even more details, see the original code and discussions that this borrows from:
        Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections
        Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

.PARAMETER Left
    'Left' collection of objects to join.  You can use the pipeline for Left.

    The objects in this collection should be consistent.
    We look at the properties on the first object for a baseline.
    
.PARAMETER Right
    'Right' collection of objects to join.

    The objects in this collection should be consistent.
    We look at the properties on the first object for a baseline.

.PARAMETER LeftJoinProperty
    Property on Left collection objects that we match up with RightJoinProperty on the Right collection

.PARAMETER RightJoinProperty
    Property on Right collection objects that we match up with LeftJoinProperty on the Left collection

.PARAMETER LeftProperties
    One or more properties to keep from Left.  Default is to keep all Left properties (*).

    Each property can:
        - Be a plain property name like "Name"
        - Contain wildcards like "*"
        - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                Name is the output property name
                Expression is the property value ($_ as the current object)
                
                Alternatively, use the Suffix or Prefix parameter to avoid collisions
                Each property using this hashtable syntax will be excluded from suffixes and prefixes

.PARAMETER RightProperties
    One or more properties to keep from Right.  Default is to keep all Right properties (*).

    Each property can:
        - Be a plain property name like "Name"
        - Contain wildcards like "*"
        - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                Name is the output property name
                Expression is the property value ($_ as the current object)
                
                Alternatively, use the Suffix or Prefix parameter to avoid collisions
                Each property using this hashtable syntax will be excluded from suffixes and prefixes

.PARAMETER Prefix
    If specified, prepend Right object property names with this prefix to avoid collisions

    Example:
        Property Name                   = 'Name'
        Suffix                          = 'j_'
        Resulting Joined Property Name  = 'j_Name'

.PARAMETER Suffix
    If specified, append Right object property names with this suffix to avoid collisions

    Example:
        Property Name                   = 'Name'
        Suffix                          = '_j'
        Resulting Joined Property Name  = 'Name_j'

.PARAMETER Type
    Type of join.  Default is AllInLeft.

    AllInLeft will have all elements from Left at least once in the output, and might appear more than once
        if the where clause is true for more than one element in right, Left elements with matches in Right are
        preceded by elements with no matches.
        SQL equivalent: outer left join (or simply left join)

    AllInRight is similar to AllInLeft.
        
    OnlyIfInBoth will cause all elements from Left to be placed in the output, only if there is at least one
        match in Right.
        SQL equivalent: inner join (or simply join)
         
    AllInBoth will have all entries in right and left in the output. Specifically, it will have all entries
        in right with at least one match in left, followed by all entries in Right with no matches in left, 
        followed by all entries in Left with no matches in Right.
        SQL equivalent: full join

.EXAMPLE
    #
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

.EXAMPLE  
    #
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

.EXAMPLE
    #
    #Hey!  You know how to script right?  Can you merge these two CSVs, where Path1's IP is equal to Path2's IP_ADDRESS?
        
    #Get CSV data
    $s1 = Import-CSV $Path1
    $s2 = Import-CSV $Path2

    #Merge the data, using a full outer join to avoid omitting anything, and export it
    Join-Object -Left $s1 -Right $s2 -LeftJoinProperty IP_ADDRESS -RightJoinProperty IP -Prefix 'j_' -Type AllInBoth |
        Export-CSV $MergePath -NoTypeInformation

.EXAMPLE
    #
    # "Hey Warren, we need to match up SSNs to Active Directory users, and check if they are enabled or not.
    #  I'll e-mail you an unencrypted CSV with all the SSNs from gmail, what could go wrong?"
        
    # Import some SSNs. 
    $SSNs = Import-CSV -Path D:\SSNs.csv

    #Get AD users, and match up by a common value, samaccountname in this case:
    Get-ADUser -Filter "samaccountname -like 'wframe*'" |
        Join-Object -LeftJoinProperty samaccountname -Right $SSNs `
                    -RightJoinProperty samaccountname -RightProperties ssn `
                    -LeftProperties samaccountname, enabled, objectclass

.NOTES
    This borrows from:
        Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections/
        Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

    Changes:
        Always display full set of properties
        Display properties in order (left first, right second)
        If specified, add suffix or prefix to right object property names to avoid collisions
        Use a hashtable rather than ordereddictionary (avoid case sensitivity)

.LINK
    http://ramblingcookiemonster.github.io/Join-Object/

.FUNCTIONALITY
    PowerShell Language

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeLine)]
        [object[]] $Left,

        # List to join with $Left
        [Parameter(Mandatory)]
        [object[]] $Right,

        [Parameter(Mandatory)]
        [string] $LeftJoinProperty,

        [Parameter(Mandatory)]
        [string] $RightJoinProperty,

        [Parameter()]
        [object[]]$LeftProperties = '*',

        # Properties from $Right we want in the output.
        # Like LeftProperties, each can be a plain name, wildcard or hashtable. See the LeftProperties comments.
        [object[]]$RightProperties = '*',

        [Parameter()]
        [ValidateSet('AllInLeft', 'OnlyIfInBoth', 'AllInBoth', 'AllInRight')]
        [string]$Type = 'AllInLeft',

        [Parameter()]
        [string]$Prefix,

        [Parameter()]
        [string]$Suffix
    )

    Begin {
        if ($env:ToolboxUsageLog) {
            Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
        }

        function AddItemProperties ($item, $properties, $hash) {
            if ($null -eq $item) {
                return
            }

            foreach ($property in $properties) {
                $propertyHash = $property -as [hashtable]
                if ($null -ne $propertyHash) {
                    $hashName = $propertyHash["name"] -as [string]         
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $expressionValue = $expression.Invoke($item)
            
                    $hash[$hashName] = if ($expressionValue.Count -eq 1) {
                        $expressionValue.Item(0)
                    } else {
                        $expressionValue
                    }
                } else {
                    foreach ($itemProperty in $item.psobject.Properties) {
                        if ($itemProperty.Name -like $property) {
                            $hash[$itemProperty.Name] = $itemProperty.Value
                        }
                    }
                }
            }
        }

        function TranslateProperties {
            [cmdletbinding()]
            param(
                [object[]]$Properties,
                [psobject]$RealObject,
                [string]$Side
            )

            foreach ($Prop in $Properties) {
                $propertyHash = $Prop -as [hashtable]
                if ($null -ne $propertyHash) {
                    $hashName = $propertyHash["name"] -as [string]         
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $ScriptString = $expression.tostring()
                    if ($ScriptString -notmatch 'param\(') {
                        Write-Verbose "Property '$HashName'`: Adding param(`$_) to scriptblock '$ScriptString'"
                        $Expression = [ScriptBlock]::Create("param(`$_)`n $ScriptString")
                    }
                
                    $Output = @{Name =$HashName; Expression = $Expression }
                    Write-Verbose "Found $Side property hash with name $($Output.Name), expression:`n$($Output.Expression | out-string)"
                    $Output
                } else {
                    foreach ($ThisProp in $RealObject.psobject.Properties) {
                        if ($ThisProp.Name -like $Prop) {
                            Write-Verbose "Found $Side property '$($ThisProp.Name)'"
                            $ThisProp.Name
                        }
                    }
                }
            }
        }

        function WriteJoinObjectOutput($leftItem, $rightItem, $leftProperties, $rightProperties) {
            $properties = @{}

            AddItemProperties $leftItem $leftProperties $properties
            AddItemProperties $rightItem $rightProperties $properties

            New-Object psobject -Property $properties
        }

        #Translate variations on calculated properties.  Doing this once shouldn't affect perf too much.
        foreach ($Prop in @($LeftProperties + $RightProperties)) {
            if ($Prop -as [hashtable]) {
                foreach($variation in ('n','label','l')) {
                    if (-not $Prop.ContainsKey('Name')) {
                        if ($Prop.ContainsKey($variation)) {
                            $Prop.Add('Name',$Prop[$Variation])
                        }
                    }
                }
                if (-not $Prop.ContainsKey('Name') -or $Prop['Name'] -like $null) {
                    Throw "Property is missing a name`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }


                if (-not $Prop.ContainsKey('Expression')) {
                    if ($Prop.ContainsKey('E')) {
                        $Prop.Add('Expression',$Prop['E'])
                    }
                }
            
                if (-not $Prop.ContainsKey('Expression') -or $Prop['Expression'] -like $null) {
                    Throw "Property is missing an expression`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }
            }        
        }

        $leftHash = @{}
        $rightHash = @{}

        # Hashtable keys can't be null; we'll use any old object reference as a placeholder if needed.
        $nullKey = New-Object psobject
        
        $bound = $PSBoundParameters.keys -contains "InputObject"
        if (-not $bound) {
            [System.Collections.ArrayList]$LeftData = @()
        }
    }

    Process {
        #We pull all the data for comparison later, no streaming
        if ($bound) {
            $LeftData = $Left
        } else {
            foreach ($Object in $Left) {
                [void]$LeftData.add($Object)
            }
        }
    }

    End {
        foreach ($item in $Right) {
            $key = $item.$RightJoinProperty

            if ($null -eq $key) {
                $key = $nullKey
            }

            $bucket = $rightHash[$key]

            if ($null -eq $bucket) {
                $bucket = New-Object System.Collections.ArrayList
                $rightHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        foreach ($item in $LeftData) {
            $key = $item.$LeftJoinProperty

            if ($null -eq $key) {
                $key = $nullKey
            }

            $bucket = $leftHash[$key]

            if ($null -eq $bucket) {
                $bucket = New-Object System.Collections.ArrayList
                $leftHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        $LeftProperties = TranslateProperties -Properties $LeftProperties -Side 'Left' -RealObject $LeftData[0]
        $RightProperties = TranslateProperties -Properties $RightProperties -Side 'Right' -RealObject $Right[0]

        #I prefer ordered output. Left properties first.
        [string[]]$AllProps = $LeftProperties

        #Handle prefixes, suffixes, and building AllProps with Name only
        $RightProperties = foreach($RightProp in $RightProperties) {
            if (-not ($RightProp -as [Hashtable])) {
                Write-Verbose "Transforming property $RightProp to $Prefix$RightProp$Suffix"
                @{
                    Name="$Prefix$RightProp$Suffix"
                    Expression=[scriptblock]::create("param(`$_) `$_.'$RightProp'")
                }
                $AllProps += "$Prefix$RightProp$Suffix"
            } else {
                Write-Verbose "Skipping transformation of calculated property with name $($RightProp.Name), expression:`n$($RightProp.Expression | out-string)"
                $AllProps += [string]$RightProp["Name"]
                $RightProp
            }
        }

        $AllProps = $AllProps | Select-Object -Unique

        Write-Verbose "Combined set of properties: $($AllProps -join ', ')"

        foreach ($entry in $leftHash.GetEnumerator()) {
            $key = $entry.Key
            $leftBucket = $entry.Value

            $rightBucket = $rightHash[$key]

            if ($null -eq $rightBucket) {
                if ($Type -eq 'AllInLeft' -or $Type -eq 'AllInBoth') {
                    foreach ($leftItem in $leftBucket) {
                        WriteJoinObjectOutput $leftItem $null $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            } else {
                foreach ($leftItem in $leftBucket) {
                    foreach ($rightItem in $rightBucket) {
                        WriteJoinObjectOutput $leftItem $rightItem $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
        }

        if ($Type -eq 'AllInRight' -or $Type -eq 'AllInBoth') {
            foreach ($entry in $rightHash.GetEnumerator()) {
                $key = $entry.Key
                $rightBucket = $entry.Value

                $leftBucket = $leftHash[$key]

                if ($null -eq $leftBucket) {
                    foreach ($rightItem in $rightBucket) {
                        WriteJoinObjectOutput $null $rightItem $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
        }
    }
}


function Get-ObjectDefaultDisplayProperty {
<#
.SYNOPSIS
    Get list of object DefaultDisplayPropery names.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/5/2016

.PARAMETER Object
    [object]

.EXAMPLE
    $branches = Invoke-GitHubApi -_branches list-branches -owner tier3 -repo toolbox
    $branches | Get-ObjectDefaultDisplayProperty

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#> 

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Object
    )

    process {
        if ($obj | Get-Member -MemberType MemberSet -Name PSStandardMembers -Force) {
            $obj.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames
        }
    }
}


function Set-ObjectDefaultDisplayProperty {
<#
.SYNOPSIS
    Set DefaultDisplayPropery for an object.
    If Object.PsStandardMembers.DefaultDisplayPropertySet already exists, it's not modified.
    May be exisiting property or calculated property, see examples.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/5/2016

.PARAMETER Object
    [object[]]

.PARAMETER ProperyName
    [string[]]

.EXAMPLE
    # Display Name and Sha of the latest commit of GitHub repo branches.
    $branches = Invoke-GitHubApi -_branches list-branches -owner tier3 -repo toolbox
    $branches | Select-Object -Property *, @{Name = 'Sha'; Expression = {$_.commit.sha}} | Set-ObjectDefaultDisplayProperty Name, Sha -PassThru

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#> 

    [CmdletBinding()]
    [SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Object,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('name')]
        [string[]]$PropertyName = '*',

        [Parameter()]
        [switch]$PassThru
    )

    process {
        foreach ($obj in $Object) {
            if ($obj | Get-Member -MemberType MemberSet -Name PSStandardMembers -Force) {
                # if '*' in -PropertyName, get existing property names
                [array]$names = if ($PropertyName -contains '*') {
                    $obj | Get-ObjectDefaultDisplayProperty
                }

                # add new names, no wildchars
                $names += $PropertyName.Where{$_ -ne '*'}

                # remove duplicates
                $names = $names | Select-Object -Unique

                # create value collection
                $value = [System.Collections.ObjectModel.Collection`1[System.String]]::new([string[]]@($names))

                # get field and set new value
                $field = $obj.PSStandardMembers.DefaultDisplayPropertySet.GetType().GetField('referencedPropertyNames','static,nonpublic,instance')
                $field.SetValue($obj.PSStandardMembers.DefaultDisplayPropertySet, $value)

            } else {
                $propertySet = New-Object -TypeName System.Management.Automation.PSPropertySet -ArgumentList DefaultDisplayPropertySet, $PropertyName
                $memberInfo = [System.Management.Automation.PSMemberInfo[]]@($propertySet)

                # add new with unique typename
                $obj.PsObject.TypeNames.Insert(0,'Object.DefaultDisplayPropertySet')
                $obj | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $memberInfo -Force
            }

            if ($PassThru) {
                $obj
            }
        }
    }
}


function Split-Collection {
<#  
.SYNOPSIS   
    Split a collection into chunks.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 12/18/2017
    Updated : 5/10/2018

.EXAMPLE
    $r = 1 .. 2 | Split-Collection -Count 1
    $r.Count

.EXAMPLE
    $r = 1 .. 10 | Split-Collection -Size 3
    $r.Count

.EXAMPLE
    $r = 1 .. 10 | Split-Collection -Count 3
    $r.Count

#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [array]$Collection,

        [Parameter(ParameterSetName = 'Count')]
        [uint16]$Count,

        [Parameter(ParameterSetName = 'Size')]
        [uint16]$Size
    )

    begin {
        $array = @()
    }

    process {
        $Collection | ForEach-Object -Process {
            $array += $_
        }
    }

    end {
        switch ($PSCmdlet.ParameterSetName) {
            Count {$Size = [Math]::Ceiling($array.Count / $Count)}

            Size  {$Count = [Math]::Ceiling($array.Count / $Size)}
        }

        $outArray = [System.Collections.Generic.List[psobject]]::new()
        $i = 0

        while ($i -lt $array.Count) {
            $last = [System.Linq.Enumerable]::Min([int[]]($array.Count, ($i + $Size))) - 1
            [array]$subArray = $array[$i .. $last]
            $outArray.Add($subArray)
            $i += $Size
        }

        , $outArray
    }
}


New-Alias @script:NewAliasCommonParams -Name expand -Value Expand-Object
New-Alias @script:NewAliasCommonParams -Name exp    -Value Expand-Object

function Expand-Object {
<#  
.SYNOPSIS   
    Deep list PS object properties.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 10/7/2018
    Updated : 1/8/2018

.EXAMPLE
    Get-Process powershell_ise | Expand-Object | ft -a

#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Alias('object')]
        [PSObject[]]$InputObject
    )

    begin {
        function ReportProperty ([string]$path, [object]$value) {
            [pscustomobject]@{
                Property = $path
                Value    = $value
            }
        }

        function GetObjectProperty ([PSObject]$object, [string]$prop) {
            ReportProperty | Out-String | Write-Verbose

            # objects is null - continue if no prop, otherwise report
            if ($null -eq $object) {
                if ($prop) {
                    ReportProperty -path $prop -value $object
                }

                else {}
            }

            # object is array - loop thru items
            elseif (
                $object -is [System.Array] -or
                $object -is [System.Collections.ArrayList]
            ) {
                if ($object.Count -gt 0) {
                    for ($i = 0; $i -lt $object.Count; $i ++) {
                        GetObjectProperty -object $object[$i] -prop "$prop[$i]"
                    }
                }

                else {
                    ReportProperty -path $prop -value $object
                }
            }

            # object is hashtable - enumerate items
            elseif (
                $object -is [System.Collections.Hashtable]
            ) {
                if ($object.Count -gt 0) {
                    $object.GetEnumerator().ForEach{
                        $key   = $_.Key
                        $value = $_.Value
                        $path  = @($prop, $key).Where{$_} -join '.'
                        ReportProperty -path $path -value $value
                    }
                }

                else {
                    ReportProperty -path $prop -value $object
                }
            }

            # object is dictionary - enumerate items
            elseif (
                $object -is [System.Collections.Specialized.StringDictionary]
            ) {
                if ($object.Count -gt 0) {
                    $object.GetEnumerator().ForEach{
                        $key   = $_.Key
                        $value = $_.Value
                        $path  = "$prop['$key']"
                        ReportProperty -path $path -value $value
                    }
                }

                else {
                    ReportProperty -path $prop -value $object
                }
            }

            # object is basic type
            elseif ($object.GetType().IsSerializable) {
                ReportProperty -path $prop -value $object
            }

            # other types - loop thru properties
            else {
                $propNames = $object.PsObject.Properties.Name

                foreach ($propName in $propNames) {
                    $value = $object.$propName
                    $path  = @($prop, $propName).Where{$_} -join '.'
                    GetObjectProperty -object $value -prop $path
                }
            }
        }
    }

    process {
        $InputObject | ForEach-Object -Process {
            GetObjectProperty -object $_
        }
    }
}


function Compare-ObjectProperty {
<#  
.SYNOPSIS   
    Deep compare PS objects.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 8/29/2018
    Updated : 10/7/2018

.EXAMPLE
    $ReferenceObject  = Get-Process powershell_ise
    $DifferenceObject = Get-Process notepad
    Compare-ObjectProperty -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject | ft -a

#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, Position = 0)]
        [PSObject]$ReferenceObject,

        [Parameter(Mandatory, Position = 1)]
        [PSObject]$DifferenceObject,

        [Parameter()]
        [string[]]$IncludeProperty,

        [Parameter()]
        [string[]]$ExcludeProperty,

        [Parameter()]
        [switch]$IncludeEqual
    )

    function ReportProperty {
        [pscustomobject]@{
            Property = $property
            RefValue = $refValue
            DifValue = $difValue
        }
    }

    # convert to flat objects
    $refObject = $ReferenceObject  | Expand-Object
    $difObject = $DifferenceObject | Expand-Object

    # select properties
    [array]$properties = @($refObject.Property) + @($difObject.Property) | Select-Object -Unique

    # filter by IncludeProperty list
    if ($IncludeProperty) {
        @($IncludeProperty).ForEach{
            $regex = [regex]::Escape($_)
            [array]$properties = $properties -match "^$regex"
        }
    }

    # filter by ExcludeProperty list
    if ($ExcludeProperty) {
        @($ExcludeProperty).ForEach{
            $regex = [regex]::Escape($_)
            [array]$properties = $properties -notmatch "^$regex"
        }
    }

    # compare and report
    foreach ($property in $properties) {
        $refValue = $refObject | Where-Object -Property Property -eq $property | Select-Object -ExpandProperty Value
        $difValue = $difObject | Where-Object -Property Property -eq $property | Select-Object -ExpandProperty Value

        if ($difValue -ne $refValue) {
            ReportProperty
        }

        elseif ($IncludeEqual) {
            ReportProperty
        }
    }
}

#endregion



#region DATA CONVERSION

New-Alias @NewAliasCommonParams -Name ctcr -Value ConvertTo-PSCredential

function ConvertTo-PSCredential {
<#
.SYNOPSIS
    Convert plain-text UserName and Password to [PSCredential] object.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 11/29/2016
    Updated : 10/29/2017

.EXAMPLE
    ConvertTo-PSCredential -UserName UserName -Password Password

.EXAMPLE
    [pscustomobject]@{
        UserName = 'UserName'
        Password = 'Password'
    } | ConvertTo-PSCredential

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#> 

    [CmdletBinding()]
    [SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]

    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$UserName,

        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)]
        [string]$Password
    )

    New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, (
        ConvertTo-SecureString -String $Password -AsPlainText -Force
    )
}


function ConvertFrom-PSCredential {
<#
.SYNOPSIS
    Convert from [PSCredential] to plain text [pscustomobject].

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 10/29/2017
    Updated : 10/29/2017

.EXAMPLE
    Import-Credential -FriendlyName T3N | ConvertFrom-PSCredential

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#> 

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [pscredential]$Credential
    )

    [pscustomobject]@{
        UserName = $Credential.UserName
        Password = $Credential.GetNetworkCredential().Password
    }
}

# TODO: replace by [regex]::Escape([string]$s) and decomm
function ConvertTo-Regex {
<#
.SYNOPSIS
    Convert string to regex-compatible by prefixing special regex charachters with escape charachter '\'.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 3/14/2015

.EXAMPLE
    ConvertTo-Regex -String 192.168.1.1
    192\.168\.1\.1

.EXAMPLE
    '10.88.10.220','10.88.10.221' | ConvertTo-Regex
    192\.168\.1\.1

.PARAMETER String
    Required.
    String to convert

.INPUTS
    [string]

.OUTPUTS
    [string]

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string[]]$String
    )

    begin {
        $chars = '^','$','[',']','{','}','(',')','<','>','\','|','/','.','*','+','?'
        $res = @()
    }

    process {
        $res += foreach ($s in $string) {
             -join ($s.GetEnumerator() | ForEach-Object -Process {
                if ($_ -in $chars) {
                    "\$_"
                } else {
                    $_
                }
            })
        }
    }

    end {
        $res -join '|'
    }
}


function ConvertTo-Utf8 {
<#
.SYNOPSIS
    Converts an existing file to UTF-8 encoding.
    Converted file overwrites existing file.

.DESCRIPTION
    Author   : Dmitry Gancho
    Last edit: 12/8/2015

.PARAMETER Path
    Required.
    Full path to the file.

.PARAMETER IncludeBOM
    Switch.
    If specified, BOM (Byte Order Mark) is added (not recommended for UTF-8 encoding). 

.EXAMPLE
    ConvertTo-Utf8 -Path Z:\CTL\Utility\Utility.psd1

.INPUTS
    [string]
    [switch]
    [switch]

.OUTPUTS
    [IO.FileInfo]

.LINK
    http://www.fileformat.info/info/unicode/utf8.htm

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$Path,

        [Parameter()]
        [switch]$IncludeBOM,

        [Parameter()]
        [switch]$PassThru
    )

    if ([System.IO.File]::Exists($Path)) {
        $content = [System.IO.File]::ReadAllLines($Path)
        [System.IO.File]::Delete($Path)

        $utf8Encoding = New-Object System.Text.UTF8Encoding($IncludeBOM.IsPresent)
        [System.IO.File]::WriteAllLines($Path,$content,$utf8Encoding)

        if ($PassThru) {
            Get-Item -Path $Path
        }
    }
}


function Expand-Gzip {
<#
.SYNOPSIS
    Expand gzip file content.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 5/21/2016

.PARAMETER Path
    Required.
    Full path to the file.

.EXAMPLE
    # Expand Gzip to output stream
    Expand-Gzip -Path Z:\config.gzip

.EXAMPLE
    # Expand Gzip and save to a file
    Expand-Gzip -Path Z:\config.gzip > config.txt

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Path
    )
    
    process {
        if ([System.IO.File]::Exists($Path)) {
            # unzip gz
            $fileStream = New-Object -TypeName System.IO.FileStream -ArgumentList $Path, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
            $memoryStream = New-Object -TypeName System.IO.MemoryStream
            $gZipStream = New-object -TypeName System.IO.Compression.GZipStream -ArgumentList $fileStream, ([System.IO.Compression.CompressionMode]::Decompress)
            $buffer = New-Object -TypeName byte[](1024)
            $count = 0

            do {
                $count = $gZipStream.Read($buffer, 0, 1024)
                if ($count -gt 0) {
                    $memoryStream.Write($buffer, 0, $count)
                }
            } while ($count -gt 0)

            $array = $memoryStream.ToArray()

            # close streams
            $gZipStream.Close()
            $memoryStream.Close()
            $fileStream.Close()

            # output
            $ascii = [System.Text.Encoding]::ASCII
            $ascii.GetString($array) #.Split("`n")
        }

        else {
            throw "Path '$Path' not found."
        }
    }
}


function ConvertTo-Ascii {
<#
.SYNOPSIS
    Convert string encoding

.DESCRIPTION
    Author  : Dmitrty Gancho
    Created : 4/6/2015

.PARAMETER String
    Required.
    A string or strings to convert.

.PARAMETER InputEncoding
    Optional, default Unicode
    Encoding of input string.

.EXAMPLE
@'
“”‘’ äâûêéèàùçä
'@ | ConvertTo-Ascii    

.OUTPUTS
    [string] ASCII string

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#> 

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$String
    )

    process {
        foreach ($str in $String) {
            $normalized = $str.Normalize('FormD')
            $res = [string]::empty
            foreach ($char in [char[]]$normalized) {
                $uCategory = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($char)
                Write-Verbose -Message "char : '$char' category : $uCategory"
                $asciiChar = switch -Regex ([string]$uCategory) {
                    'NonSpacingMark' {}

                    'InitialQuotePunctuation|FinalQuotePunctuation' {
                        switch -Regex ([string][int][char]$char) {
                            '8216|8217' {"'"}

                            '8220|8221' {'"'}

                            default {'"'}
                        }
                    }

                    default {$char}
                }
                $res += $asciiChar
            }
            return $res
        }
    }
}


function ConvertTo-Base64 {
<#
.SYNOPSIS
    Convert string to base64. Used in Http request headers.

.DESCRIPTION
    Author  : Dmitrty Gancho
    Created : 8/29/2018
    Updated : 8/29/2018

.PARAMETER String
    Required.
    A string or strings to convert.

.EXAMPLE
    $string = "{0}:{1}" -f $Credential.UserName, $Credential.GetNetworkCredential().Password
    $string | ConvertTo-Base64

#> 
    [CmdletBinding()]

    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$String
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($String)
    [System.Convert]::ToBase64String($bytes)
}


Function ConvertTo-HashTable {
<#
.SYNOPSIS
    Convert an object to a HashTable

.DESCRIPTION
    Convert an object to a HashTable excluding certain types.
    For example, ListDictionaryInternal doesn't support serialization therefore can't be converted to JSON.

.PARAMETER InputObject
    Object to convert

.PARAMETER ExcludeTypeName
    Array of types to skip adding to resulting HashTable.  Default is to skip ListDictionaryInternal and Object arrays.

.PARAMETER MaxDepth
    Maximum depth of embedded objects to convert. Default is 4.

.Example
    $bios = Get-CimInstance -ClassName Win32_Bios
    $bios | ConvertTo-HashTable

#>
    
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Object]$InputObject,

        [Parameter()]
        [string[]]$ExcludeTypeName = @("ListDictionaryInternal","Object[]"),

        [Parameter()]
        [ValidateRange(1, 10)]
        [byte]$MaxDepth = 4
    )

    process {
        #$propNames = Get-Member -MemberType Properties -InputObject $InputObject | Select-Object -ExpandProperty Name
        $propNames = $InputObject.psobject.Properties | Select-Object -ExpandProperty Name

        $hash = @{}

        $propNames | ForEach-Object -Process {
            if ($null -ne $InputObject.$_) {
                if (
                    $InputObject.$_ -is [string] -or
                    (Get-Member -MemberType Properties -InputObject ($InputObject.$_) ).Count -eq 0
                ) {
                    $hash.Add($_,$InputObject.$_)
                }

                else {
                    if ($InputObject.$_.GetType().Name -in $ExcludeTypeName) {
                        Write-Verbose "Skipped $_"
                    }

                    elseif ($MaxDepth -gt 1) {
                        $hash.Add($_, (ConvertTo-HashTable -InputObject $InputObject.$_ -MaxDepth ($MaxDepth - 1)))
                    }
                }
            }
        }

        $hash
    }
}

#endregion



#region DATA REDIRECTION

function Out-Clip {
<#
.SYNOPSIS
    Takes object from pipeline, converts to string and copies to clipboard.
    The object is passed further down the pipeline intact.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 17/1/2015
    Updated : 3/29/2019

.EXAMPLE
    Get-Process notepad | Out-Clip -Passthru

.INPUTS
    [object] from pipeline.

.OUTPUTS
    [object]

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>

    [CmdletBinding()]

    param (
        [Parameter(ValueFromPipeline, Position = 0)]
        [Object]$InputObject,

        [Parameter()]
        [switch]$PassThru
    )

    if ($PassThru) {
        $InputObject
    }

    $string = $InputObject | Out-String

    if ($string -ne [string]::Empty) {
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.Clipboard]::Clear()
        [Windows.Forms.Clipboard]::SetText($string)
    }
}


function Out-Voice {
<#
.SYNOPSIS
    Outputs string to voice using self-removed background job.

.DESCRIPTION
    Author  : Dmitry Gancho, dmitry@ganco.com
    Created : 9/16/2016

.PARAMETER Text
    Text to speak

.PARAMETER Passthru

.EXAMPLE
    Out-Voice -Text 'Hello world'

.EXAMPLE
    'Hello world' | Out-Voice -Passthru

.INPUTS
    [string]

.OUTPUTS
    [string]

.LINK

#>
    [Cmdletbinding()]

    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Text,

        [Parameter()]
        [switch]$PassThru
    )
    
    if ($PassThru) {$Text}

    $params = @{
        Name = $MyInvocation.MyCommand.Name
        ArgumentList = $Text
        ScriptBlock = {
            Add-Type -AssemblyName System.Speech
            $speak = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
            $zira = $speak.GetInstalledVoices().VoiceInfo |
            Where-Object -Property Name -Like '*Zira*' |
            Select-Object -ExpandProperty Name
            if ($zira) {
                $speak.SelectVoice($zira)
            }
            $speak.Speak($args[0])
            #[void](New-Object -ComObject SAPI.SpVoice).Speak($args[0])
        }
    }

    Start-Job @params | Register-JobRemove
}

#endregion



#region STRING MANIPULATION

# TODO: decomm (used in Juniper module)
function Test-Numeric 
{
<#
    .SYNOPSIS
        Returns false if value is null, empty or not a number, otherwise it returns true
    .DESCRIPTION
        Author    : Chris Blydenstein
        Last edit : 01/28/2016
        Version   : 1.0
    .PARAMETER Value
        Required.
        Any type you want to check
    .EXAMPLE
        Test-Numeric "ABC"
    .EXAMPLE
        Test-Numeric "123"
    .OUTPUTS
        [bool] true if a number
    .LINK
        https://support.ctl.io/hc/en-us/articles/207170083
#> 
    [CmdletBinding()]
    param (
        [Parameter()][string]$Value
    )

    if([string]::IsNullOrEmpty($Value)) { return $false }
    if([string]::IsNullOrWhiteSpace($Value)) { return $false }
    try 
    {
        0 + $Value | Out-Null
        return $true
    } 
    catch 
    {
        return $false
    }
}

# TODO: decomm (used in Juniper module)
function Find-MatchingLine 
{
<#
    .SYNOPSIS
        Returns matching strings from a string array
    .DESCRIPTION
        Author    : Chris Blydenstein
        Last edit : 01/28/2016
        Version   : 1.0
    .PARAMETER StringArray
        Required.
        An array containing data you're searching
    .PARAMETER SearchString
        Required.
        A string you want to find in the array
    .PARAMETER SkipUntilMatches
        Required.
        A string you want to find in the array
    .EXAMPLE
        $myArray = "Erik", "Chris", "Fred", "Christopher"
        Find-MatchingLine $myArray "Chris"
    .EXAMPLE
        $myArray = "Erik", "Chris", "Fred", "Christopher"
        Find-MatchingLine $myArray "Chris" -BeginSearchAtString "Fred"
    .OUTPUTS
        [array] All matching lines
    .LINK
        https://support.ctl.io/hc/en-us/articles/207170083
#> 

    [CmdletBinding()]
    [OutputType([string])]

    param (
        [Parameter(Mandatory)][array]$StringArray,
        [Parameter(Mandatory)][string]$SearchForString,
        [Parameter()][string]$BeginSearchAtString
    )

    if($BeginSearchAtString)
    {
        $startSearch = $false
        foreach ($line in $StringArray)
        {
            if($line -match $BeginSearchAtString)
            {
                $startSearch = $true
            }
            if($startSearch)
            {
                if($line -match $SearchForString) { return [string]$line }
            }
        }
    }
    else
    {
        foreach ($line in $StringArray)
        {
            if($line -match $SearchForString) { return [string]$line }
        }
    }
}

# TODO: decomm (used in Juniper module)
function Find-LinesBetween 
{
<#
    .SYNOPSIS
        Returns strings from a string array that are between two matching strings
    .DESCRIPTION
        Author    : Chris Blydenstein
        Last edit : 01/28/2016
        Version   : 1.0
    .PARAMETER StringArray
        Required.
        An array containing data you're searching
    .PARAMETER SearchString
        Required.
        A string you want to find in the array
    .EXAMPLE
        $myArray = "Erik", "Chris", "Fred", "Jim", "Christopher"
        $result = Find-LinesBetween $myArray "Chris" "Christopher"
        $result
    .EXAMPLE
        $myArray = "Erik", "Chris", "Fred", "Jim", "Christopher"
        $result = Find-LinesBetween $myArray "Chris" "Christopher" -CombineLines
        $result
    .OUTPUTS
        [array] All matching lines
    .LINK
        https://support.ctl.io/hc/en-us/articles/207170083
#> 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][array]$StringArray,
        [Parameter(Mandatory)][string]$FirstLine,
        [Parameter(Mandatory)][string]$LastLine,
        [Parameter()][switch]$CombineLines
    )

    $firstLineFound = $false
    $matchedLines = @()
    foreach ($line in $StringArray)
    {
        if($line -match $lastLine) { break }
        if($firstLineFound){ $matchedLines += [string]$line.Trim() }
        if($line -match $firstLine) { $firstLineFound = $true }
    }
    if($CombineLines) { return ($matchedLines -join "; ") }
    else { return $matchedLines }
}

#endregion



#region LOGGING

function Test-EventLog {
<#
.SYNOPSIS
    Test whether EventLog (and EventSouce) exist.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 5/24/2017

.PARAMETER LogName

.PARAMETER Source

.PARAMETER ComputerName

.EXAMPLE
    Test-EventLog -EventLog Toolbox

.EXAMPLE
    Test-EventLog -EventLog Toolbox -EventSource test_source

.LINK
#>

    [CmdletBinding()]

    param (
        [Parameter()]
        [string]$LogName,

        [Parameter()]
        [string]$Source,

        [Parameter()]
        [Alias('cn')]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    end {
        trap {
            Write-Warning -Message $_.Exception.Message
            continue
        }

        if ($LogName -and $Source) {
            [System.Diagnostics.EventLog]::Exists($LogName, $ComputerName) -and
            [System.Diagnostics.EventLog]::SourceExists($Source, $ComputerName)

        } elseif ($LogName) {
            [System.Diagnostics.EventLog]::Exists($LogName, $ComputerName)

        } elseif ($Source) {
            [System.Diagnostics.EventLog]::SourceExists($Source, $ComputerName)
        }
    }
}


function Write-UsageLog {
<#
.SYNOPSIS
    Logs the current invocation of a function to Elasticsearch

.DESCRIPTION
    Author  : James Rodgers
    Created : 12/3/2016

.PARAMETER Invocation
    Required.
    An object with information about the current command. 

.EXAMPLE
    Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference

.LINK
    https://support.ctl.io/hc/en-us/articles/207170083
#>

    [Cmdletbinding()]

    param (
        [Parameter(Mandatory)]
        [psobject]$Invocation,

        [Parameter()]
        [string]$address = 'https://ccapi.ctl.io/api/logging'
    )

    return

    Get-InvocationLine -Invocation $Invocation | Write-Verbose
    $command = $Invocation.MyCommand

    if ($command.Source -in @(
        'Cloud-LSE'
        'Control API v1'
        'Control API v2'
    )) {
        $moduleName = $command.Source
        $functionName = $command.Name
        $message = "Module '$moduleName' \ function '$functionName' are deprecated and not supported.`n"
        Write-Warning -Message $message
    }

    if ($env:ToolboxUsageLog -ne 'True') {return}

#    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $callStack = Get-PSCallStack
        $firstCall = $callstack[$callstack.Length - 1].Command
        $functionName = $Invocation.MyCommand.Name

        if (
            $firstCall -ne 'TabExpansion2' -and 
            $firstCall -ne 'profile.ps1' -and 
            $functionName -ne 'New-DynamicParameter' -and
            $functionName -ne 'Write-UsageLog'
        ) {
            $now = [DateTime]::UtcNow
            $timeZone = $(([TimeZoneInfo]::Local).DisplayName)
            $timestamp = $now.ToString("yyyyMMdd'T'HHmmssZ")
            $user = $([Environment]::UserName)
            $machine = $([Environment]::MachineName)
            $os = $([Environment]::OSVersion.VersionString)
            $cmd = $([Environment]::CommandLine).Replace('"','').Trim()
            $version = $([Environment]::Version.ToString())
            $moduleName = $Invocation.MyCommand.Source

            $callsArray = New-Object System.Collections.ArrayList
            
            if ($firstCall -eq '<ScriptBlock>') {
                $firstCall = $callstack[$callstack.Length - 2].Command
            }

            foreach($call in $callStack) {
                if (
                    -not [bool]($call.Command.Trim()) -and
                    $call.Command -ne '<ScriptBlock>' -and 
                    $call.Command -ne $MyInvocation.MyCommand
                ) {
                    [void]$callsArray.Add($call.Command)
                }
            }
            
            $logObject = New-Object psobject
            $logObject | Add-Member -Type NoteProperty -Name time_zone -Value $timeZone
            $logObject | Add-Member -Type NoteProperty -Name timestamp -Value $timestamp
            $logObject | Add-Member -Type NoteProperty -Name user -Value $user
            $logObject | Add-Member -Type NoteProperty -Name machine $machine
            $logObject | Add-Member -Type NoteProperty -Name os $os
            $logObject | Add-Member -Type NoteProperty -Name cmd $cmd
            $logObject | Add-Member -Type NoteProperty -Name first_call $firstCall
            $logObject | Add-Member -Type NoteProperty -Name version $version
            $logObject | Add-Member -Type NoteProperty -Name function -Value $functionName
            $logObject | Add-Member -Type NoteProperty -Name module_name -Value $moduleName
            $logObject | Add-Member -Type NoteProperty -Name call_stack -Value $callsArray    
            $logObject | Add-Member -Type NoteProperty -Name pid -Value $pid    
            $logObject | Add-Member -Type NoteProperty -Name stack_size -Value $callsArray.Count
        
            $json = $logObject | ConvertTo-Json -Compress

            if ($json) {
                Invoke-RestMethod ($address + '/docindex') -Method Post -Body $json -ContentType 'application/json' -Headers @{Authorization=("Basic Y2NhcGk6JEpEcmZ6NCZwcTZz")} -Verbose:$false | Out-Null
            }
        }
    }

    catch {
        $env:ToolboxUsageLog = $null
        "Write-UsageLog : {0}" -f $_.Exception.Message | Write-Verbose
    }

#    "Write-UsageLog : $([math]::Round($sw.Elapsed.TotalMilliseconds)) ms." | Write-Verbose
}

#endregion



#region COMPUTER TOOLS

function Test-Computer {
<#
.SYNOPSIS
    Test basic health of a computer.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 4/17/2017
    Updated : 3/30/2018

.PARAMETER ComputerName

.EXAMPLE
    # Test localhost.
    Test-Computer

.EXAMPLE
    # Test remote computers.
    Test-Computer -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01

.INPUTS
    [string]

.OUTPUTS
    [PSCustomObject]

.LINK
#>

    [CmdletBinding()]

    param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('cn')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, [byte]::MaxValue)]
        [Byte]$TimeOutSec = 60
    )

    begin {
        $targets = @()
    }

    process {
        $targets += $ComputerName | ForEach-Object -Process {
            $_
        }
    }

    end {
        # test script
        $script = {
            [CmdletBinding()]

            param (
                [string]$Target,
                [PSCredential]$Credential,
                [UInt32]$TimeOutSec
            )

            $ErrorActionPreference = 'Stop'

            #region GET DATA
            # create CIM session
            $cimSession = New-CimSession -ComputerName $Target -Credential:$Credential -OperationTimeoutSec $TimeOutSec

            # win32_OperatingSystem instance
            $query = "SELECT * FROM win32_OperatingSystem"
            $win32_OperatingSystem = Get-CimInstance -CimSession $cimSession -Query $query -OperationTimeoutSec $timeOutSec

            # win32_Processor instances
            $query = "SELECT * FROM win32_Processor"
            $win32_Processor = Get-CimInstance -CimSession $cimSession -Query $query -OperationTimeoutSec $timeOutSec

            # win32_LogicalDisk instances
            $query = "SELECT * FROM win32_LogicalDisk"
            $win32_LogicalDisk = Get-CimInstance -CimSession $cimSession -Query $query -OperationTimeoutSec $timeOutSec

            # win32_Service instances
            $query = "SELECT * FROM win32_Service"
            $win32_Service = Get-CimInstance -CimSession $cimSession -Query $query -OperationTimeoutSec $timeOutSec

            # win32_Process instances and porcess owners
            $query = "SELECT * FROM win32_Process"
            $win32_Process = Get-CimInstance -CimSession $cimSession -Query $query -OperationTimeoutSec $timeOutSec |
            ForEach-Object -Process {
                $owner = try {
                    Invoke-CimMethod -InputObject $_ -MethodName GetOwner -CimSession $cimSession -OperationTimeoutSec $TimeOutSec
                }

                catch {
                    $_.Exception.Message | Write-Verbose
                }

                $_ | Add-Member -NotePropertyName Owner -NotePropertyValue $owner -PassThru
            }

            # Win32_PerfFormattedData_PerfProc_Process instances
            $query = "SELECT * FROM win32_PerfFormattedData_PerfProc_Process"
            $win32_PerfFormattedData_PerfProc_Process = Get-CimInstance -CimSession $cimSession -Query $query -OperationTimeoutSec $timeOutSec

            # remove CIM session
            Remove-CimSession -CimSession $cimSession

            #endregion

            #region CONSOLIDATE DATA

            $cName  = $win32_OperatingSystem.CSName
            $osName = $win32_OperatingSystem.Caption
            $uptime = $win32_OperatingSystem.LocalDateTime - $win32_OperatingSystem.LastBootUpTime

            $memory = [pscustomobject]@{
                TotalGB     = [math]::Round($win32_OperatingSystem.TotalVisibleMemorySize / 1MB, 2)
                FreeGB      = [math]::Round($win32_OperatingSystem.FreePhysicalMemory / 1MB, 2)
                FreePercent = [math]::Round($win32_OperatingSystem.FreePhysicalMemory / $win32_OperatingSystem.TotalVisibleMemorySize * 100)
            }

            $cpuCount = @($win32_Processor).Count
            $cpu = [pscustomobject]@{
                Count = $cpuCount
                Utilization = [math]::Round([System.Linq.Enumerable]::Sum([int[]]$win32_Processor.LoadPercentage) / $cpuCount)
                Speed = $win32_Processor.CurrentClockSpeed | Select-Object -Unique
                Name = $win32_Processor.Name | Select-Object -Unique
            }

            $logicalDisks = @($win32_LogicalDisk).Where{$_.MediaType -eq 12}.ForEach{
                [pscustomobject]@{
                    Name = $_.Name
                    SizeGB = [math]::Round($_.Size / 1GB, 2)
                    FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
                    FreePercent = [math]::Round($_.FreeSpace / $_.Size * 100)
                }
            }

            $services = @($win32_Service).ForEach{
                $processId = $_.ProcessId
                $memoryMB = if ($processId) {
                    $process = $win32_Process.Where{$_.ProcessId -eq $processId}
                    [math]::Round($process.WorkingSetSize / 1MB, 1)
                }

                [pscustomobject]@{
                    ProcessId = [uint64]$processId
                    Name      = $_.Name
                    Status    = $_.Status
                    State     = $_.State
                    MemoryMB  = $memoryMB
                    ExitCode  = $_.ExitCode
                }
            } | Sort-Object -Property MemoryMB -Descending

            $processes = @($win32_Process).ForEach{
                $processId = $_.ProcessId

                if ($processId -and $processId -ne 0) {
                    $perfData = @($Win32_PerfFormattedData_PerfProc_Process).Where{$_.IDProcess -eq $processId}
                    $cpuPercent = [uint64]$perfData.PercentProcessorTime
                    $memoryB = $perfData.WorkingSet
                } else {
                    $cpuPercent = $null
                    $memoryB = $_.WorkingSetSize
                }

                [pscustomobject]@{
                    ProcessId     = [uint64]$processId
                    Name          = $_.Name
                    Owner         = "{0}\{1}" -f $_.Owner.Domain, $_.Owner.User
                    MemoryMB      = [math]::Round($memoryB / 1MB, 1)
                    MemoryPercent = [math]::Round($memoryB / 1KB / $win32_OperatingSystem.TotalVisibleMemorySize * 100)
                    CpuPercent    = $cpuPercent
                }
            } | Sort-Object -Property MemoryMB, CpuPercent -Descending

            #endregion

            # return results
            [pscustomobject]@{
                ComputerName    = $cName
                OperatingSystem = $osName
                Uptime          = $uptime
                Memory          = $memory
                Cpu             = $cpu
                LogicalDisk     = $logicalDisks
                Service         = $services
                Process         = $processes
                RawData         = [pscustomobject]@{
                    win32_OperatingSystem                    = $win32_OperatingSystem
                    win32_Processor                          = $win32_Processor
                    win32_LogicalDisk                        = $win32_LogicalDisk
                    win32_Service                            = $win32_Service
                    win32_Process                            = $win32_Process
                    win32_PerfFormattedData_PerfProc_Process = $win32_PerfFormattedData_PerfProc_Process
                }
            }
        }

        # parameter sets
        $parameterSets = @($targets).ForEach{
            @{
                Target = $_
            }
        }

        # common parameters set
        $commonParameterSet = @{
            Credential = $Credential
            TimeOutSec = $TimeOutSec
        }

        # invoke
        Invoke-Parallel -ScriptBlock $script -ParameterSet $parameterSets -CommonParameterSet $commonParameterSet -TimeOutMs ($TimeOutSec * 1000) -ErrorAction Continue
    }
}


function Get-PerformanceCounter {
<#
.SYNOPSIS
    Get performance counter data for computer(s).

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 5/14/2017

.PARAMETER ComputerName

.EXAMPLE
    # Get performance data from localhost.
    Get-PerformanceCounter

.EXAMPLE
    # Get performance data from remote computers.
    Get-PerformanceCounter -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01

.EXAMPLE
    # Save performance data from remote computers to a PerformanceMonitor-compatible .BLG file.
    Get-PerformanceCounter -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01 -OutFile E:\PerfCounter.blg

.OUTPUTS
    [PSCustomObject]

.LINK
#>

    [CmdletBinding()]

    param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('cn')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [string[]]$Counter = @(
            '\Memory\Available Bytes'
            '\Memory\Committed Bytes'
            '\Processor(*)\% Processor Time'
            '\LogicalDisk(*:)\% Free Space'
            '\Process(*)\ID Process'
            '\Process(*)\% Processor Time'
            '\Process(*)\Working Set - Private'
        ),

        [Parameter()]
        [uint16]$SampleInterval = 1,

        [Parameter()]
        [uint32]$MaxSamples = 10,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$OutFile,

        [Parameter()]
        [switch]$AsJob
    )

    begin {
        $targets = @()
    }

    process {
        $targets += $ComputerName
    }

    end {
        # argiment list for script block
        $argumentList = @(
            @($targets), # 0
            @($Counter),      # 1
            $MaxSamples,      # 2
            $SampleInterval,  # 3
            $Credential,      # 4
            $OutFile          # 5
        )

        # script block
        $script = {
            [CmdletBinding()]

            $_targets        = $args[0]
            $_Counter        = $args[1]
            $_MaxSamples     = $args[2]
            $_SampleInterval = $args[3]
            $_Credential     = $args[4]
            $_OutFile        = $args[5]

            $results = if ($_Credential) {
                Invoke-Command -ComputerName $_targets -Credential $_Credential -ArgumentList @(
                    @($_Counter),     # 0
                    $_MaxSamples,     # 1
                    $_SampleInterval, # 2
                    $_OutFile         # 3

                ) -ScriptBlock {
                    $_Counter        = $args[0]
                    $_MaxSamples     = $args[1]
                    $_SampleInterval = $args[2]
                    $_OutFile        = $args[3]

                    Get-Counter -Counter $_Counter -MaxSamples $_MaxSamples -SampleInterval $_SampleInterval -ErrorAction Continue
                } -ErrorAction Continue

            } else {
                Get-Counter -ComputerName $_targets -Counter $_Counter -MaxSamples $_MaxSamples -SampleInterval $_SampleInterval -ErrorAction Continue
            }

            # save to file and report
            if ($_OutFile) {
                $results | Export-Counter -Path $_OutFile -FileFormat BLG -Force

                # report file
                Get-Item -Path $_OutFile
            } else {
                # report results
                $results
            }
        }

        # invoke
        if ($AsJob) {
            $job = Start-Job -Name PerfCollector -ScriptBlock $script -ArgumentList $argumentList
            $job | Register-JobRemove
            $job
        } else {
            Invoke-Command -ScriptBlock $script -ArgumentList $argumentList -NoNewScope
        }
    }
}


function Group-Counter {
<#
.SYNOPSIS
    Group CounterSets by ComputerName.

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 5/15/2017
    Updated : 9/12/2018

.PARAMETER CounterSampleSet

.EXAMPLE
    # Split Counter Sets from 2 computers.
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

#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Microsoft.PowerShell.Commands.GetCounter.PerformanceCounterSampleSet[]]$CounterSampleSet
    )

    process {
        foreach ($sampleSet in $CounterSampleSet) {
            $sampleSet | Out-String | Write-Verbose

            # path example: \\wa1t3nccnoc01\\memory\available bytes
            $computerNames = $sampleSet.CounterSamples.Path -replace '^\\{2}|\\.*$' | Select-Object -Unique

            foreach ($computerName in $computerNames) {
                $pattern = "^\\{2}$computerName\\"
                $computerName = $computerName.ToUpper()
                "ComputerName: {0}" -f $computerName | Write-Verbose

                # select Samples for this computer
                $counterSamples = $sampleSet.CounterSamples |
                Where-Object -FilterScript {
                    $_.Path -match $pattern
                } |
                ForEach-Object -Process {
                    $counterPath = $_.Path -replace '^\\{2}[^\\]*\\+'
                    $objectName, $counterName = $counterPath -split '\\+'
                    $counterSetName = $objectName -replace '\(.*\)$'

                    $_ |
                    Add-Member -NotePropertyName ComputerName   -NotePropertyValue $computerName   -PassThru -Force |
                    Add-Member -NotePropertyName CounterSetName -NotePropertyValue $counterSetName -PassThru -Force |
                    Add-Member -NotePropertyName ObjectName     -NotePropertyValue $objectName     -PassThru -Force |
                    Add-Member -NotePropertyName CounterName    -NotePropertyValue $counterName    -PassThru -Force
                }

                # convert $sampleSet to serialized PsObject to avoid change the original
                $object = [ordered]@{
                    TimeStamp    = $sampleSet.Timestamp
                    ComputerName = $computerName
                    SampleCount  = @($counterSamples).Count
                    Samples      = $counterSamples
                }
<#
                # group samples by ObjectName
                $objectGroups = $counterSamples | Group-Object -Property ObjectName

                foreach ($objectGroup in $objectGroups) {
                    $objectName  = $objectGroup.Name
                    $objectValue = [ordered]@{}

                    foreach ($counterSample in $objectGroup.Group) {
                        $sampleName  = $counterSample.CounterName
                        $objectValue.$sampleName = $counterSample
                    }
                    $object.$objectName = [pscustomobject]$objectValue
                }
#>
                $object | Out-String | Write-Verbose
                [pscustomobject]$object
            }
        }
    }
}


function Get-ComputerPerformance {
<#
.SYNOPSIS
    Get average performance data for computer(s).

.DESCRIPTION
    Author  : Dmitry Gancho
    Created : 5/14/2017

.PARAMETER ComputerName

.EXAMPLE
    # Get performance data from localhost.
    Get-ComputerPerformance

.EXAMPLE
    # Get performance data from remote computers.
    Get-ComputerPerformance -ComputerName WA1T3NCCNOC03, AU1T3NCCNOC01

.OUTPUTS
    [PSCustomObject[]]

.LINK
#>

    [CmdletBinding(DefaultParameterSetname = 'ComputerName')]

    param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ComputerName')]
        [Alias('cn')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateSet(
            'Memory',
            'Processor',
            'LogicalDisk',
            'Process'
        )]
        [string[]]$Object = @(
            'Memory'
            'Processor'
            'LogicalDisk'
        ),

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePath')]
        [uint32]$IntervalSec = 10,

        [Parameter(ParameterSetName = 'ComputerName')]
        [uint16]$SampleIntervalSec = 1,

        [Parameter(ParameterSetName = 'ComputerName')]
        [PSCredential]$Credential,

        [Parameter(Position = 0, ValueFromPipeline, ParameterSetName = 'SampleSet')]
        [Microsoft.PowerShell.Commands.GetCounter.PerformanceCounterSampleSet[]]$SampleSet,

        [Parameter(Position = 0, ValueFromPipeline, ParameterSetName = 'FilePath')]
        [System.IO.FileInfo]$FilePath,

        [Parameter()]
        [switch]$Summary
    )

    process {
        switch ($PSCmdlet.ParameterSetName) {
            ComputerName {
                $targets += $ComputerName
            }

            SampleSet {
                $sampleSets += $SampleSet
            }
        }
    }

    end {
        # if Process if specified, we must also get Memory and Processors
        if ($Object -contains 'Process') {
            if ($Object -notcontains 'Memory') {
                $Object += 'Memory'
            }

            if ($Object -notcontains 'Processor') {
                $Object += 'Processor'
            }
        }

        #region GET CounterSamples
        $sampleSets = switch ($PSCmdlet.ParameterSetName) {
            ComputerName {
                $counters = foreach ($item in $Object) {
                    switch ($item) {
                        Memory {
                            '\Memory\Available Bytes'
                            '\Memory\Committed Bytes'
                        }

                        Processor {
                            '\Processor(*)\% Processor Time'
#                            '\Processor(*)\% Idle Time'
                        }

                        LogicalDisk {
                            "\LogicalDisk(*:)\% Free Space"
                        }

                        Process {
                            '\Process(*)\ID Process'
#                            '\Process(*)\Creating Process ID'
                            '\Process(*)\% Processor Time'
                            '\Process(*)\Working Set - Private'
#                            '\Process(*)\Working Set'
#                            '\Process(*)\Private Bytes'

                        }
                    }
                }
        
                $param = @{
                    ComputerName   = $targets
                    Counter        = $counters
                    SampleInterval = $SampleIntervalSec
                    MaxSamples     = [math]::Truncate($IntervalSec / $SampleIntervalSec)
                    Credential     = $Credential
                }

                Get-PerformanceCounter @param
            }

            FilePath {
                $startTime = [datetime]::Now.AddSeconds(- $IntervalSec)
                Import-Counter -Path $FilePath -StartTime $startTime -ErrorAction Ignore 
            }
        }
        #endregion


        #region COMPILE RESULTS

        # start and end times
        $startTime = $sampleSets | Select-Object -ExpandProperty Timestamp -First 1
        $endTime   = $sampleSets | Select-Object -ExpandProperty Timestamp -Last 1
        $sampleCount = @($sampleSets).Count

        # extract samples
        $samples = $sampleSets | Select-Object -ExpandProperty CounterSamples

        # add properties
        foreach ($sample in $samples) {
            # split path '\\au1t3nccnoc01\\processor(_total)\% processor time'
            $null, $comp, $counter = $sample.Path -split '\\{2}'

            # add properties
            $sample |
            Add-Member -NotePropertyName ComputerName -NotePropertyValue $comp.ToUpper() -Force -PassThru |
            Add-Member -NotePropertyName Counter -NotePropertyValue $counter -Force
        }

        # group by ComputerName
        $computerGroups = $samples | Group-Object -Property ComputerName | Sort-Object -Property Name

        foreach ($computerGroup in $computerGroups) {
            # create output object
            $result = [ordered]@{
                ComputerName = $computerGroup.Name
                StartTime    = $startTime
                EndTime      = $endTime
                SampleCount  = $sampleCount
            }

            # group by Counter
            $counterGroups = $computerGroup.Group | Group-Object -Property Counter

            foreach ($counterGroup in $counterGroups) {
                # Instance name
                $counterName = $counterGroup.Name

                # Instance average value
                $cookedValues = $counterGroup.Group.CookedValue
                $counterValue = [math]::Round([system.linq.enumerable]::Average([decimal[]]$cookedValues), 2)

                # add values to output object
                $result.$counterName = $counterValue
            }

            # return
            if ($Summary) {
                $output = [ordered]@{
                    ComputerName = $result.ComputerName
                    Samples = [pscustomobject]@{
                        Start = $result.StartTime
                        End   = $result.EndTime
                        Count = $result.SampleCount
                    }
                }

                # Memory
                if (
                    $result.Keys -contains 'memory\available bytes' -and
                    $result.Keys -contains 'memory\committed bytes'
                ) {
                    $memoryFree  = $result.'memory\available bytes'
                    $memoryUsed  = $result.'memory\committed bytes'
                    $memoryTotal = $memoryFree + $memoryUsed

                    $output.Memory = [pscustomobject]@{
                        'TotalGB' = [math]::Round($memoryTotal / 1GB)
                        'UsedGB'  = [math]::Round($memoryUsed / 1GB, 2)
                        'FreeGB'  = [math]::Round($memoryFree / 1GB, 2)
                        'Used%'   = if ($memoryTotal -gt 0) {[math]::Round(100 * $memoryUsed / $memoryTotal, 1)} else {}
                        'Free%'   = if ($memoryTotal -gt 0) {[math]::Round(100 * $memoryFree / $memoryTotal, 1)} else {}
                    }
                }

                # Processors
                $output.Processor = foreach ($key in ($result.Keys -match '^processor\W')) {
                    $name  = [regex]::Match($key,'\(.*\)').Value -replace '\(|\)|_'
                    $value = [math]::Round($result.$key, 1)

                    [pscustomobject]@{
                        'Name'         = $name
                        'Utilization%' = $value
                    }
                }

                # LogicalDisks
                $output.LogicalDisk = foreach ($key in ($result.Keys -match '^logicaldisk\W')) {
                    $name  = [regex]::Match($key,'\(.*\)').Value -replace '\(|\)'
                    $value = [math]::Round($result.$key, 1)

                    [pscustomobject]@{
                        'Name'       = $name.ToUpper()
                        'FreeSpace%' = $value
                    }
                }

                # Processes
                $output.Process = if ($result.Keys -match '^process\W') {
                    $processorCount = $output.Processor.Where{$_.Name -notmatch 'Total'}.Count

                    # get list of process names
                    $processNames = $result.Keys.Where{
                        $_ -match '^process\W'
                    }.ForEach{
                        [regex]::Match($_,'\(.*\)').Value -replace '\(|\)|_'
                    } | Select-Object -Unique | Sort-Object
                    
                    # find processor and memory use for each process
                    foreach ($processName in $processNames) {
                        $key = [string]$result.Keys.Where{$_ -match "\($processName\)\\ID Process$"}
                        $processId = $result.$key

                        $key = [string]$result.Keys.Where{$_ -match "\($processName\)\\Creating Process ID$"}
                        $creatingProcessId = $result.$key

                        $key = [string]$result.Keys.Where{$_ -match "\($processName\)\\% Processor Time$"}
                        $processorTime = $result.$key

                        $key = [string]$result.Keys.Where{$_ -match "\($processName\)\\Working Set$"}
                        $workingSet = $result.$key

                        $key = [string]$result.Keys.Where{$_ -match "\($processName\)\\Working Set - Private$"}
                        $workingSetPrivate = $result.$key

                        $key = [string]$result.Keys.Where{$_ -match "\($processName\)\\Private Bytes$"}
                        $privateBytes = $result.$key

                        [pscustomobject]@{
                            'PID'  = $processId
                            'Name' = $processName
                            'MemoryKB'   = [math]::Round($workingSetPrivate / 1KB)
                            'Memory%'    = if ($memoryTotal -gt 0) {[math]::Round(100 * $workingSetPrivate / $memoryTotal, 1)} else {}
                            'Processor%' = if ($processorCount -gt 0) {[math]::Round($processorTime / $processorCount, 1)} else {}

#                            'WorkingSetKB'   = [math]::Round($workingSet / 1KB)
#                            'PrivateBytesKB' = [math]::Round($privateBytes / 1KB)
#                            'WorkingSet%'    = [math]::Round(100 * $workingSet / $memoryTotal, 2)
#                            'WorkingSetPrivate%' = [math]::Round(100 * $workingSetPrivate / $memoryTotal, 2)
#                            'PrivateBytes%' = [math]::Round(100 * $privateBytes / $memoryTotal, 2)
                        }
                    }
                }

                [pscustomobject]$output

            } else {
                [pscustomobject]$result
            }
        }
        #endregion
    }
}

#endregion
