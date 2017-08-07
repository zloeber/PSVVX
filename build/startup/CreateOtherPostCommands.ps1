$Template = @'
function {{Name}} {
    <#
    .SYNOPSIS
    {{Description}}
    .DESCRIPTION
    {{Description}}
    .PARAMETER Device
    Device to send command for processing.
    .PARAMETER Value
    Value to set for this setting.
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
    {{Name}} -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -ErrorAction:Ignore

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
                Send-VVXRestCommand -Device $Dev -Command '{{Command}}' -Method 'Post' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Unable to process request to this device."
            }
        }
    }
}
'@

$Definitions = @'
Name,Description,Command
Restart-VVXDevice,Restart a VVX device,mgmt/safeRestart
Restart-VVXDeviceAndReboot,Reboot a VVX device,mgmt/safeReboot
Reset-VVXConfiguration,Reset a VVX device configuration,mgmt/configReset
Reset-VVXConfigToFactory,Factory reset a VVX device,mgmt/factoryReset
'@ | ConvertFrom-CSV

Foreach ($Definition in $Definitions) {
    $Template -replace '{{Name}}',$Definition.Name `
              -replace '{{Description}}',$Definition.Description `
              -replace '{{Command}}',$Definition.Command | Out-File -FilePath ('.\src\public\' + $Definition.Name + '.ps1') -Force
}