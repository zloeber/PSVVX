$Template = @'
function Get-VVX{{Name}} {
    <#
    .SYNOPSIS
    {{Description}}
    .DESCRIPTION
    {{Description}}
    .PARAMETER Device
    Device to send command for processing.
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
    Get-{{Name}} -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -ErrorAction:Ignore

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
                Send-VVXRestCommand  -Device $Dev -Command '{{Command}}' -Method 'Get' -Credential $Credential -Protocol $Protocol -Port $Port @RestSplat
            }
            catch {
                Write-Warning "$($FunctionName): $Dev - Device either invalid or is not on a call."
            }
        }
    }
}
'@

$Definitions = @'
Name,Description,Command
CallStatus,Returns the current call status of a device,webCallControl/callStatus
DeviceInfo,Returns device related information,mgmt/device/info
NetworkInfo,Returns device related network information,mgmt/network/info
LineInfo,Returns device related line information,mgmt/lineInfo
SIPStatus,Returns device related SIP status information,webCallControl/sipStatus
NetworkStat,Returns device related network statistics,mgmt/network/stats
'@ | ConvertFrom-CSV

Foreach ($Definition in $Definitions) {
    $Template -replace '{{Name}}',$Definition.Name `
              -replace '{{Description}}',$Definition.Description `
              -replace '{{Command}}',$Definition.Command | Out-File -FilePath ('.\src\public\Get-VVX' + $Definition.Name + '.ps1') -Force
}