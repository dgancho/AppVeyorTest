
<#
$path = "$HOME\Documents\AppVeyorTest\Utility"
Invoke-Pester -Script $path\Utility.Tests.ps1
#>


Describe 'Utility Module Test' {

    InModuleScope Utility {

        Remove-Module Utility -Force -ErrorAction Ignore
        Import-Module $PSScriptRoot\Utility -Force

        Context 'Strict Mode' {

            Set-StrictMode -Version Latest

            It 'Invoke-Parallel Test 1' {
                $var = [System.Collections.Queue]::new()
                Invoke-Parallel -ParameterSet ([hashtable[]]::new(100)) -ScriptBlock {
                    $SyncronizedObject.Enqueue($pid)
                    $SyncronizedObject.Count
                } -Method RunspacePool -SyncronizedObject $var
                $var.Count | Should Be 100
            }

            It 'Invoke-Parallel Test 2' {
                Invoke-Parallel -ParameterSet @(
                    @{target = 'google.com'}
                ) -ScriptBlock {
                    param ($target)
                    [net.dns]::GetHostByName($target).AddressList[0]
                } | Should BeOfType IpAddress
            }
        }
    }
}

Reset-PsPrompt

