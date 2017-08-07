function Get-VVXSetting {
    <#
    .SYNOPSIS
    Retreive a configuration setting from a device.
    .DESCRIPTION
    Retreive a configuration setting from a device.
    .PARAMETER Device
    Device to send command for processing.
    .PARAMETER Setting
    Setting to look up.
    .PARAMETER Protocol
    Protocol to use. Must be HTTP or HTTPS. Default is HTTP.
    .PARAMETER Port
    Port to use. Default is 80.
    .PARAMETER RetryCount
    Number of times to retry if unsuccessful. Default is 3 times.
    .PARAMETER Credential
    User ID and password for the device
    .PARAMETER IgnoreSSLCertificate
    Ignore any certificate warnings
    .EXAMPLE
    $cred = Get-Credential -UserName 'Polycom' -Message 'Please supply the admin password for the device'
    Get-VVXSetting -Credential $cred -Device '10.0.29.20' -ErrorAction:Ignore -Setting 'up.screenCapture.enabled'

    .NOTES
    Author: Zachary Loeber
    .LINK
    https://github.com/zloeber/PSVVX
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