
<#
$path = "$HOME\Documents\AppVeyorTest\TestModule"
Invoke-Pester -Script $path\TestModule.Tests.ps1
#>


Describe 'TestModule Test' {

    InModuleScope TestModule {

        Import-Module $PSScriptRoot\TestModule -Force

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
