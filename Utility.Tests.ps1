InModuleScope Utility {
    Describe 'Utility Module Test' {
        It 'Invoke-Parallel Test 1' {
            $var = [System.Collections.Queue]::new()
            Invoke-Parallel -ParameterSet @{}, @{} -ScriptBlock {
                $SyncronizedObject.Enqueue($pid)
                $SyncronizedObject.Count
            } -Method RunspacePool -SyncronizedObject $var
            $var.Count | Should Be 2
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

<#
Invoke-Pester -Script $HOME\Documents\AppVeyorTest\Utility.Tests.ps1
#>
