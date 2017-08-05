## Pre-Loaded Module code ##

<#
 Put all code that must be run prior to function dot sourcing here.

 This is a good place for module variables as well. The only rule is that no 
 variable should rely upon any of the functions in your module as they 
 will not have been loaded yet. Also, this file cannot be completely
 empty. Even leaving this comment is good enough.
#>

## PRIVATE MODULE FUNCTIONS AND DATA ##

function Get-CallerPreference {
    <#
    .Synopsis
       Fetches "Preference" variable values from the caller's scope.
    .DESCRIPTION
       Script module functions do not automatically inherit their caller's variables, but they can be
       obtained through the $PSCmdlet variable in Advanced Functions.  This function is a helper function
       for any script module Advanced Function; by passing in the values of $ExecutionContext.SessionState
       and $PSCmdlet, Get-CallerPreference will set the caller's preference variables locally.
    .PARAMETER Cmdlet
       The $PSCmdlet object from a script module Advanced Function.
    .PARAMETER SessionState
       The $ExecutionContext.SessionState object from a script module Advanced Function.  This is how the
       Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
       script module.
    .PARAMETER Name
       Optional array of parameter names to retrieve from the caller's scope.  Default is to retrieve all
       Preference variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0)
       This parameter may also specify names of variables that are not in the about_Preference_Variables
       help file, and the function will retrieve and set those as well.
    .EXAMPLE
       Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

       Imports the default PowerShell preference variables from the caller into the local scope.
    .EXAMPLE
       Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference','SomeOtherVariable'

       Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
    .EXAMPLE
       'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

       Same as Example 2, but sends variable names to the Name parameter via pipeline input.
    .INPUTS
       String
    .OUTPUTS
       None.  This function does not produce pipeline output.
    .LINK
       about_Preference_Variables
    #>

    [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.SessionState]$SessionState,

        [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline = $true)]
        [string[]]$Name
    )

    begin {
        $filterHash = @{}
    }
    
    process {
        if ($null -ne $Name)
        {
            foreach ($string in $Name)
            {
                $filterHash[$string] = $true
            }
        }
    }

    end {
        # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0

        $vars = @{
            'ErrorView' = $null
            'FormatEnumerationLimit' = $null
            'LogCommandHealthEvent' = $null
            'LogCommandLifecycleEvent' = $null
            'LogEngineHealthEvent' = $null
            'LogEngineLifecycleEvent' = $null
            'LogProviderHealthEvent' = $null
            'LogProviderLifecycleEvent' = $null
            'MaximumAliasCount' = $null
            'MaximumDriveCount' = $null
            'MaximumErrorCount' = $null
            'MaximumFunctionCount' = $null
            'MaximumHistoryCount' = $null
            'MaximumVariableCount' = $null
            'OFS' = $null
            'OutputEncoding' = $null
            'ProgressPreference' = $null
            'PSDefaultParameterValues' = $null
            'PSEmailServer' = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName' = $null
            'PSSessionConfigurationName' = $null
            'PSSessionOption' = $null

            'ErrorActionPreference' = 'ErrorAction'
            'DebugPreference' = 'Debug'
            'ConfirmPreference' = 'Confirm'
            'WhatIfPreference' = 'WhatIf'
            'VerbosePreference' = 'Verbose'
            'WarningPreference' = 'WarningAction'
        }

        foreach ($entry in $vars.GetEnumerator()) {
            if (([string]::IsNullOrEmpty($entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($entry.Value)) -and
                ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $filterHash.ContainsKey($entry.Name))) {
                
                $variable = $Cmdlet.SessionState.PSVariable.Get($entry.Key)
                
                if ($null -ne $variable) {
                    if ($SessionState -eq $ExecutionContext.SessionState) {
                        Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
                    }
                    else {
                        $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                    }
                }
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'Filtered') {
            foreach ($varName in $filterHash.Keys) {
                if (-not $vars.ContainsKey($varName)) {
                    $variable = $Cmdlet.SessionState.PSVariable.Get($varName)
                
                    if ($null -ne $variable)
                    {
                        if ($SessionState -eq $ExecutionContext.SessionState)
                        {
                            Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
                        }
                        else
                        {
                            $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                        }
                    }
                }
            }
        }
    }
}

## PUBLIC MODULE FUNCTIONS AND DATA ##

function Get-VVXCallStatus {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.1/docs/Functions/Get-VVXCallStatus.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Phone','DeviceName')]
        [string]$Device,

        [Parameter()]
        [ValidateSet('HTTP','HTTPS')]
        [string]$Protocol = 'HTTP',

        [Parameter()]
        [int]$Port = 80,

        [Parameter()]
        [int]$RetryCount = 3,

        [Parameter()]
        [switch]$IgnoreSSLCertificate,

        [Parameter()]
        [alias('Creds')]
        [Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )

    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
        }
        if ($IgnoreSSLCertificate) {
            $RestSplat.IgnoreSSLCertificate = $true
        }
    }
    process {
        $Devices += $Device
    }
    end {
        foreach ($Dev in $Devices) {
            try {
                Send-VVXRestCommand  -Device $Dev -Command 'webCallControl/callStatus' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Device either invalid or is not on a call."
            }

        }
    }
}


function Get-VVXLastRESTCall {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.1/docs/Functions/Get-VVXLastRestCall.md
    #>
    [CmdletBinding()]
    param()

    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
        }
        if ($IgnoreSSLCertificate) {
            $RestSplat.IgnoreSSLCertificate = $true
        }
    }
    process {
        $Devices += $Device
    }
    end {
        foreach ($Dev in $Devices) {
            try {
                Send-VVXRestCommand  -Device $Dev -Command 'webCallControl/callStatus' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Device either invalid or is not on a call."
            }

        }
    }
}


function Send-VVXRestCommand {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.1/docs/Functions/Send-VVXRestCommand.md
    #>
    [CmdletBinding(DefaultParameterSetName='URINotPassed')]
    param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'URINotPassed', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Phone','DeviceName')]
        [string]$Device,

        [Parameter(Position = 1, ParameterSetName = 'URINotPassed')]
        [ValidateSet('HTTP','HTTPS')]
        [string]$Protocol = 'HTTP',

        [Parameter(ParameterSetName = 'URINotPassed')]
        [int]$Port = 80,

        [Parameter(Position = 3, Mandatory = $true, ParameterSetName = 'URINotPassed')]
        [string]$Command,

        [Parameter(ParameterSetName = 'URINotPassed')]
        [string]$Base = 'api/v1',

        [Parameter(Position = 0, ParameterSetName = 'URIPassed', Mandatory = $true)]
        [string]$FullURI,

        [Parameter(ParameterSetName = 'URINotPassed')]
        [Parameter(ParameterSetName = 'URIPassed')]
        [ValidateSet('Head', 'Get', 'Put', 'Patch', 'Post', 'Delete')]
        [string]$Method = 'Get',

        [Parameter(ParameterSetName = 'URINotPassed')]
        [Parameter(ParameterSetName = 'URIPassed')]
        [Hashtable]$Body,

        [Parameter(ParameterSetName = 'URINotPassed')]
        [Parameter(ParameterSetName = 'URIPassed')]
        [int]$RetryCount = 3,

        [Parameter(ParameterSetName = 'URINotPassed')]
        [Parameter(ParameterSetName = 'URIPassed')]
        [switch]$IgnoreSSLCertificate,

        [Parameter(ParameterSetName = 'URINotPassed')]
        [Parameter(ParameterSetName = 'URIPassed')]
        [alias('Creds')]
        [Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )
    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $URIs = @()
        $BodyData = if ($Body -eq $null) { $null } else { if ($Method -ne 'Get') { @{data = $Body} | ConvertTo-Json } else { $Body } }

        if ($IgnoreSSLCertificate) {
            Write-Verbose "$($FunctionName): Ignoring any SSL certificate errors"
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        }
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'URIPassed' {
                $URIs += $FullURI
                Write-Verbose "$($FunctionName): URI added = $FullURI"
            }
            default {
                $ThisURI = "$($Protocol)://$($Device):$Port/$Base/$Command"
                Write-Verbose "$($FunctionName): URI Constructed = $ThisURI"
                $URIs += $ThisURI
            }
        }
    }
    end {
        foreach ($URI in $URIs) {
            try {
                # Create a request object using the URI
                $request = [System.Net.HttpWebRequest]::Create($URI)

                $request.Credentials = $Credential
                $request.KeepAlive = $true
                $request.Pipelined = $true
                $request.AllowAutoRedirect = $false
                $request.Method = $Method
                $request.ContentType = "application/json"

                if ($null -ne $Bodydata) {
                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($BodyData)
                    $request.ContentLength = $utf8Bytes.Length
                    $postStream = $request.GetRequestStream()
                    $postStream.Write($utf8Bytes, 0, $utf8Bytes.Length)
                    $postStream.Dispose()
                }

                $Script:LastRESTCall = @{
                    URI = $URI
                    Method = $Method
                    Credential = $Credential
                    Body = $BodyData
                }

                $response = $request.GetResponse()

                $reader = [IO.StreamReader] $response.GetResponseStream()
                $output = $reader.ReadToEnd()
                $json = $output | ConvertFrom-Json

                $reader.Close()
                $response.Close()
            }
            catch {
                $RESTError = $_
                if ($RetryCount -gt 0) {
                    Write-Verbose "$($FunctionName): Issue connecting to URI, Retries Left = $RetryCount"
                    $RetryCount--
                    Send-VVXRestCommand -FullURI $URI -RetryCount $RetryCount -Credential $Credential
                }
                else {
                    throw $RestError #"$($FunctionName): Exception occurred - `n$response"
                }
            }

            if ($null -ne $json) {
                Write-Verbose "$($FunctionName): API result = $($json.Status)"
                switch ($json.Status) {
                    2000 {
                        Write-Verbose "$($FunctionName): API call succeeded"
                        Write-Output $json.data
                    }
                    Default {
                        if ( ($Script:JsonStatusCodes).Keys -contains $_ ) {
                            Write-Verbose "$($FunctionName): API call failed - $(($Script:jsonStatusCodes)[$json.Status])"
                            throw "$($FunctionName): API call failed - $(($Script:jsonStatusCodes)[$json.Status])"
                        }
                        else {
                            Write-Verbose "$($FunctionName): API call failed - Unknown status code $($json.Status)"
                            throw "$($FunctionName): API call failed - Unknown status code $($json.Status)"
                        }
                    }
                }
            }
        }
    }
}


## Post-Load Module code ##


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


