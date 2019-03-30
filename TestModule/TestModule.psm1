<#
.Author
    Dmitry Gancho

.Description
    Testing.

.FormatsToProcess
    TestModule.Format.ps1xml

.FunctionsToExport
    Test-Target
    Invoke-Parallel
#>


#Requires -Version 5.0


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

