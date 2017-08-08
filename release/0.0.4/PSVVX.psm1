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

function Get-LocalIP
{
    # Get Networking Adapter Configuration
    $Computer = "."
    $IPconfigset = Get-WmiObject Win32_NetworkAdapterConfiguration
    $LocalIP = ""

    # Iterate and get IP address
    $count = 0
    foreach ($IPConfig in $IPConfigSet) {
       if ($Ipconfig.IPaddress) {
          foreach ($addr in $Ipconfig.Ipaddress) {
            #write-host "IP Address   : $addr"
            $count++
            if($addr -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
            {
                $LocalIP = $addr
                break;
            }
          }
       }
    }
    if ($count -eq 0) {write-host "ERROR: No IP addresses found on system." -foreground "red"}
    else {
    #write-host "Discovered local IP address $LocalIP." -foreground "green"
    }

    return [string]$LocalIP
}

## PUBLIC MODULE FUNCTIONS AND DATA ##

function Find-VVXDevice {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Find-VVXDevice.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Phone','DeviceName','IP')]
        [string]$Device,

        [Parameter()]
        [int]$Port = 5060,

        [Parameter()]
        [int]$DiscoveryWaitTime = 350,

        [Parameter()]
        [string]$LocalIP = (Get-LocalIP),

        [Parameter()]
        [string]$LocalPort = '51234'
    )

    begin {

        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        [string]$returndata = ""
        $receivebytes = $null

        $serverip = "${LocalIP}:${LocalPort}"
        $phoneid = "discover"
        [string]$time = [DateTime]::Now
        $time = $time.Replace(" ","").Replace("/","").Replace(":","")
        $call_id = "${time}msgto${phoneid}"

        $message = @"
NOTIFY sip:${phoneid}:5060 SIP/2.0
Via: SIP/2.0/UDP ${serverip}
From: <sip:discover>;tag=1530231855-106746376154
To: <sip:${Device}:5060>
Call-ID: ${call_id}
CSeq: 1500 NOTIFY
Contact: <sip:${phoneid}>
Content-Length: 0


"@

    }
    end {
        $Result = @{
            Device = "$($Device):$Port"
            Response = $null
            Status = $null
            LyncServer = $null
            ClientApp = $null
            SipUser = $null
        }
        $a = new-object system.text.asciiencoding
        $byte = $a.GetBytes($message)

        #Use base level UDP socket implementation for faster for discovery!
        $Socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,
                        [Net.Sockets.SocketType]::Dgram,
                        [Net.Sockets.ProtocolType]::Udp)

        $LocalEndpoint = New-Object system.net.ipendpoint([System.Net.IPAddress]::Parse($LocalIP),$LocalPort)
        $Socket.Bind($LocalEndpoint)
        $Socket.Connect($Device,$Port)
        try {
            [Void]$Socket.Send($byte)
        }
        catch {
            $Result.Status = 'Unable to Connect'
        }

        # Buffer to hold the returned Bytes.
        [Byte[]]$buffer = New-Object -TypeName Byte[]($Socket.ReceiveBufferSize)
        $BytesReceivedError = $false

        try {
            #Note: This socket timeout has been tuned to allow phones to respond within 350ms. This timer should work well in most cases, however, if you have a device that is on a slow link you may need to make this value higher.
            $theDiscoveryWaitTime = $DiscoveryWaitTime * 1000
            #Write-Host "DISCOVERY WAIT TIME: $discoveryWaitTime" #DEBUGGING
            if($Socket.Poll($theDiscoveryWaitTime,[System.Net.Sockets.SelectMode]::SelectRead)) {
                $receivebytes = $Socket.Receive($buffer)
            }
            else {
                #Timed out
                $Result.Status = 'No Response'
                $BytesReceivedError = $true
            }
        }
        catch {
            $Result.Status = 'No Response'
            $BytesReceivedError = $true
        }
        if(-not $BytesReceivedError) {
            if ($receivebytes) {
                [string]$returndata = $a.GetString($buffer, 0, $receivebytes)
                $Result.Status = 'Online'
                $Result.Response = $returndata

                if($returndata -imatch "SIP/2.0 200 OK") {
                    if($returndata -imatch "Contact: <sip:" -and $returndata -imatch "PolycomVVX") {
                        [string]$returndataSplit = ($returndata -split 'Contact: <sip:')[1]
                        [string]$returndataSplit = ($returndataSplit -split "`r`n")[0]

                        if($returndataSplit -imatch "VVX500@" -or $returndataSplit -imatch "VVX501@" -or $returndataSplit -imatch "VVX600@" -or $returndataSplit -imatch "VVX601@" -or $returndataSplit -imatch "VVX300@" -or $returndataSplit -imatch "VVX301@" -or $returndataSplit -imatch "VVX310@" -or $returndataSplit -imatch "VVX311@" -or $returndataSplit -imatch "VVX400@" -or $returndataSplit -imatch "VVX401@" -or $returndataSplit -imatch "VVX410@" -or $returndataSplit -imatch "VVX411@" -or $returndataSplit -imatch "VVX200@" -or $returndataSplit -imatch "VVX201@") {
                            Write-Output "$($FunctionName): Discovered device with no user logged in."

                            if($returndata -imatch "User-Agent: ") {
                                [string]$ClientAppTemp = ($returndata -split 'User-Agent: ')[1]
                                [string]$ClientApp = ($ClientAppTemp -split "`r`n")[0]
                            }
                        }
                        elseif ($returndataSplit.Contains(";opaque")) {
                            $Result.SipUser = ($returndataSplit -split ';')[0]

                            if($returndata -imatch "targetname=") {
                                [string]$LyncServerStringTemp = ($returndata -split "targetname=`"")[1]
                                $Result.LyncServer = ($LyncServerStringTemp -split "`",")[0]
                            }
                            if($returndata -imatch "User-Agent: ") {
                                [string]$ClientAppTemp = ($returndata -split 'User-Agent: ')[1]
                                $Result.ClientApp = ($ClientAppTemp -split "`r`n")[0]
                            }
                        }
                    }
                    else {
                        $Result.Response = $returndata
                        $Result.Status = 'Non-VVX Device'
                    }
                }
                else {
                    $Result.Status = 'Error'
                    $Result.Response = $returndata
                }


            }
            else {
                $Result.Status = 'No Data Received'
            }
        }
        $Socket.Close()
        $Socket.Dispose()
        $Socket = $null

        New-Object -TypeName psobject -Property $Result
    }
}



function Get-VVXCallStatus {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXCallStatus.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
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



function Get-VVXDeviceInfo {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXDeviceInfo.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
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
                Send-VVXRestCommand  -Device $Dev -Command 'mgmt/device/info' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
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
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXLastRestCall.md
    #>
    [CmdletBinding()]
    param()

    $Script:LastRESTCall
}


function Get-VVXLineInfo {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXLineInfo.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
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
                Send-VVXRestCommand  -Device $Dev -Command 'mgmt/lineInfo' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Device either invalid or is not on a call."
            }
        }
    }
}



function Get-VVXNetworkInfo {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXNetworkInfo.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
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
                Send-VVXRestCommand  -Device $Dev -Command 'mgmt/network/info' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Device either invalid or is not on a call."
            }
        }
    }
}



function Get-VVXNetworkStat {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXNetworkStat.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
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
                Send-VVXRestCommand  -Device $Dev -Command 'mgmt/network/stats' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Device either invalid or is not on a call."
            }
        }
    }
}



function Get-VVXSetting {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXSetting.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Phone','DeviceName')]
        [string]$Device,

        [Parameter(Mandatory = $true)]
        [string]$Setting,

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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
            'Body' = $Setting
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
                Send-VVXRestCommand -Device $Dev -Command 'mgmt/config/get' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Unable to retreive the setting - $Setting"
            }
        }
    }
}


function Get-VVXSIPStatus {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Get-VVXSIPStatus.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
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
                Send-VVXRestCommand  -Device $Dev -Command 'webCallControl/sipStatus' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Device either invalid or is not on a call."
            }
        }
    }
}



function Reset-VVXConfigToFactory {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Reset-VVXConfigToFactory.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
            'Body' = @{}
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
                Send-VVXRestCommand -Device $Dev -Command 'mgmt/factoryReset' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Unable to process request to this device."
            }
        }
    }
}



function Reset-VVXConfiguration {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Reset-VVXConfiguration.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
            'Body' = @{}
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
                Send-VVXRestCommand -Device $Dev -Command 'mgmt/configReset' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Unable to process request to this device."
            }
        }
    }
}



function Restart-VVXDevice {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Restart-VVXDevice.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
            'Body' = @{}
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
                Send-VVXRestCommand -Device $Dev -Command 'mgmt/safeRestart' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Unable to process request to this device."
            }
        }
    }
}



function Restart-VVXDeviceAndReboot {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Restart-VVXDeviceAndReboot.md
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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
            'Body' = @{}
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
                Send-VVXRestCommand -Device $Dev -Command 'mgmt/safeReboot' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Unable to process request to this device."
            }
        }
    }
}



function Send-VVXPushCommand {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Send-VVXPushCommand.md
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

        [Parameter(ParameterSetName = 'URINotPassed')]
        [string]$Base = 'push',

        [Parameter(Position = 0, ParameterSetName = 'URIPassed', Mandatory = $true)]
        [string]$FullURI,

        [Parameter(ParameterSetName = 'URINotPassed', Mandatory = $true)]
        [Parameter(ParameterSetName = 'URIPassed', Mandatory = $true)]
        $Body,

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
                $ThisURI = "$($Protocol)://$($Device):$Port/$Base"
                Write-Verbose "$($FunctionName): URI Constructed = $ThisURI"
                $URIs += $ThisURI
            }
        }
    }
    end {
        foreach ($URI in $URIs) {
            try {
                Write-Verbose "$($FunctionName): Creating POST request to $URI"
                # Create a request object using the URI
                $request = [System.Net.HttpWebRequest]::Create($URI)

                $request.Credentials = $Credential
                $request.KeepAlive = $true
                $request.Pipelined = $true
                $request.AllowAutoRedirect = $false
                $request.Method = "POST"
                $request.ContentType = "text/xml"

                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
                $request.ContentLength = $utf8Bytes.Length
                $postStream = $request.GetRequestStream()
                $postStream.Write($utf8Bytes, 0, $utf8Bytes.Length)
                $postStream.Dispose()

                $Script:LastRESTCall = @{
                    URI = $URI
                    Method = 'POST'
                    Credential = $Credential
                    Body = $Body
                }

                $response = $request.GetResponse()

                $reader = [IO.StreamReader] $response.GetResponseStream()
                $output = $reader.ReadToEnd()

                $reader.Close()
                $response.Close()
            }
            catch {
                $RESTError = $_
                if ($RetryCount -gt 0) {
                    Write-Verbose "$($FunctionName): Issue connecting to URI, Retries Left = $RetryCount"
                    $RetryCount--
                    $ResendSplat = @{
                        FullURI = $URI
                        RetryCount = $RetryCount
                        Body = $Body
                        Credential = $Credential
                    }
                    if ($IgnoreSSLCertificate) {
                        $ResendSplat.IgnoreSSLCertificate = $true
                    }
                    Send-VVXPushCommand @ResendSplat
                }
                else {
                    throw $RestError
                }
            }

            if ($null -ne $response) {
                $response
            }
        }
    }
}


function Send-VVXRestCommand {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Send-VVXRestCommand.md
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
        $Body,

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
        $BodyData = if ($Body -eq $null) { $null } else { if ($Body -is [hashtable]) { @{data = $Body} | ConvertTo-Json } else { @{data = @($Body)} | ConvertTo-Json } }

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
                Write-Verbose "$($FunctionName): Creating $Method request to $URI"
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
                    Send-VVXRestCommand -FullURI $URI -RetryCount $RetryCount -Method $Method -Body $Body -Credential $Credential
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


function Send-VVXTextMessage {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Send-VVXTextMessage.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Phone','DeviceName')]
        [string]$Device,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string]$Priority,

        [Parameter()]
        [ValidateSet('S4B','Error','Standard')]
        [string]$Theme = 'S4B',

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter()]
        [ValidateSet('HTTP','HTTPS')]
        [string]$Protocol = 'HTTP',

        [Parameter()]
        [int]$Port = 80,

        [Parameter()]
        [string]$Base = 'push',

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

    $vvxphone = Find-VVXDevice -Device $Device
    if ($vvxphone.status -eq 'online') {
        #VVX Display Resolutions - Use the same for 400/500/600, and special formatting for 300 and 201.
        #VVX 600     480x252
        #VVX 500     320x220
        #VVX 400     320x240
        #VVX 300     208x104
        #VVX 201    132x64

        $AllowedMessageChars = 0
        $AllowedHeadingChars = 0

        $Date = Get-Date -format g

        if($vvxphone.ClientApp -imatch 'PolycomVVX-VVX_[4-6]') {
            $AllowedMessageChars = 200  #Limited to 200 chars to fit on the screen.
            $AllowedHeadingChars = 18    #Limited to 18 chars to not overlap the date.

            switch ($Theme) {
                's4b' {
                    #MODERN LOOK
                    $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: #015077;border-radius: 0px 0px 0px 0px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 1px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                }
                'Error' {
                    #RED ALERT
                    $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: #ff0909;border-radius: 0px 0px 0px 0px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 1px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                }
                'Standard' {
                    #OLD LOOK
                    $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: -webkit-linear-gradient(top, #58615e , #00174d);border-radius: 5px 5px 5px 5px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 2px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                }
            }
        }
        else {
            $AllowedMessageChars = 69    #Limited to 69 chars to fit on the screen.
            $AllowedHeadingChars = 18
            $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{text-align: center; max-width: 180px; word-wrap: break-word;}</style></head><body><h1>$Title</h1>$Message</body></Data></PolycomIPPhone>"
        }

        if(-not ($Message.length -gt $AllowedMessageChars)) {
            if(-not ($Title.length -gt $AllowedHeadingChars)) {
                $PushSplat = @{
                    Device = $Device
                    RetryCount = $RetryCount
                    Protocol = $Protocol
                    Port = $Port
                    Base = $Base
                    Credential = $Credential
                    Body = $Body
                }
                if ($IgnoreSSLCertificate) {
                    $PushSplat.IgnoreSSLCertificate = $true
                }
                Send-VVXPushCommand @PushSplat
            }
            else {
                Write-Error "$($FunctionName): Not Sent to $Device. Message title is " $title.length " characters long. Messages are limited to $AllowedHeadingChars characters for this model of VVX device"
            }
        }
        else {
            Write-Error "$($FunctionName): Not Sent to $Device. Message is " $message.length " characters long. Messages are limited to $AllowedMessageChars characters."
        }
    }
    else {
        Write-Warning "$($FunctionName): $Device is not able to be connected to or is not a VVX device."
    }
}


function Set-VVXScreenCapture {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Set-VVXScreenCapture.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Phone','DeviceName')]
        [string]$Device,

        [Parameter(Mandatory = $true)]
        [string]$Value,

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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
            'Body' = @{'up.screenCapture.enabled' = $Value}
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
                Send-VVXRestCommand -Device $Dev -Command 'mgmt/config/set' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Unable to set the setting."
            }
        }
    }
}



function Set-VVXSetting {
    <#
    .EXTERNALHELP PSVVX-help.xml
    .LINK
        https://github.com/zloeber/psvvx/tree/master/release/0.0.4/docs/Functions/Set-VVXSetting.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Phone','DeviceName')]
        [string]$Device,

        [Parameter(Mandatory = $true)]
        [string]$Setting,

        [Parameter(Mandatory = $true)]
        [string]$Value,

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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $RestSplat = @{
            'RetryCount' = $RetryCount
            'Body' = @{$Setting = $Value}
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
                Send-VVXRestCommand -Device $Dev -Command 'mgmt/config/set' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Error "$($FunctionName): $Dev - Unable to set $Setting to $Value."
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


