
# Use this variable for any path-sepecific actions (like loading dlls and such) to ensure it will work in testing and after being built
$MyModulePath = $(
    Function Get-ScriptPath {
        $Invocation = (Get-Variable MyInvocation -Scope 1).Value
        if($Invocation.PSScriptRoot) {
            $Invocation.PSScriptRoot
        }
        Elseif($Invocation.MyCommand.Path) {
            Split-Path $Invocation.MyCommand.Path
        }
        elseif ($Invocation.InvocationName.Length -eq 0) {
            (Get-Location).Path
        }
        else {
            $Invocation.InvocationName.Substring(0,$Invocation.InvocationName.LastIndexOf("\"));
        }
    }

    Get-ScriptPath
)

#region Module Cleanup
$ExecutionContext.SessionState.Module.OnRemove = {
    # Action to take if the module is removed
}

$null = Register-EngineEvent -SourceIdentifier ( [System.Management.Automation.PsEngineEvent]::Exiting ) -Action {
    # Action to take if the whole pssession is killed
}

# Use this in your scripts to check if the function is being called from your module or independantly.
$ThisModuleLoaded = $true

# Several lookup variables

$jsonStatusCodes = @{
    '2000' = 'Success!'
    '4001' = 'Device busy.'
    '4002' = 'Line not registered.'
    '4003' = 'Operation not allowed.'
    '4004' = 'Operation Not Supported'
    '4005' = 'Line does not exist.'
    '4006' = 'URLs not configured.'
    '4007' = 'Call Does Not Exist'
    '4008' = 'Configuration Export Failed'
    '4009' = 'Input Size Limit Exceeded'
    '4010' = 'Default Password Not Allowed'
    '5000' = 'Failed to process request.'
}

$LastRESTCall = @{}