function Get-VVXScreenShot {
    <#
    .SYNOPSIS
    Returns a screenshot of the vvx device screen.
    .DESCRIPTION
    Returns a screenshot of the vvx device screen.
    .PARAMETER Device
    Device to send command for processing.
    .PARAMETER Screen
    Which screen to capture. Can be 'mainScreen','em/1','em/2', or 'em/3'. Defaults to mainScreen.
    .PARAMETER File
    File name to save screenshot to.
    .PARAMETER AsStream
    Return results as a stream instead of saving to a file.
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
    .PARAMETER Silent
    Do not display progress indicators
    .EXAMPLE
    $cred = Get-Credential -UserName 'Polycom' -Message 'Please supply the admin password for the device'
    Get-VVXScreenShot -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -File c:\temp\vvxscreenshot.bmp

    .NOTES
    For this function to work the user must manually configure Settings -> Basic -> Preferences -> Screen Capture -> Enabled

    You can view all screens in your browser by directly going to http<s>:\\<device>:<port>\captureScreen as well.

    Author: Zachary Loeber
    .LINK
    https://github.com/zloeber/PSVVX
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'AsFile')]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'AsStream')]
        [Alias('Phone','DeviceName')]
        [string]$Device,

        [Parameter(ParameterSetName = 'AsFile')]
        [Parameter(ParameterSetName = 'AsStream')]
        [ValidateSet('mainScreen','em/1','em/2','em/3')]
        [string]$Screen = 'mainScreen',

        [Parameter(Mandatory=$true, ParameterSetName = 'AsFile')]
        [string]$File,

        [Parameter(Mandatory=$true, ParameterSetName = 'AsStream')]
        [switch]$AsStream,

        [Parameter(ParameterSetName = 'AsFile')]
        [Parameter(ParameterSetName = 'AsStream')]
        [ValidateSet('HTTP','HTTPS')]
        [string]$Protocol = 'HTTP',

        [Parameter(ParameterSetName = 'AsFile')]
        [Parameter(ParameterSetName = 'AsStream')]
        [int]$Port = 80,

        [Parameter(ParameterSetName = 'AsFile')]
        [Parameter(ParameterSetName = 'AsStream')]
        [int]$RetryCount = 3,

        [Parameter(ParameterSetName = 'AsFile')]
        [Parameter(ParameterSetName = 'AsStream')]
        [switch]$IgnoreSSLCertificate,

        [Parameter(ParameterSetName = 'AsFile')]
        [Parameter(ParameterSetName = 'AsStream')]
        [alias('Creds')]
        [Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(ParameterSetName = 'AsFile')]
        [switch]$Silent
    )

    begin {
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        $Devices = @()
        $URIPath = 'captureScreen'
        if (-not [string]::IsNullOrEmpty($Screen) ){
            $URIPath = "$URIPath/$Screen"
        }
        $RestSplat = @{
            RetryCount = $RetryCount
            RequestTimeOut = 1000
            Protocol = $Protocol
            Port = $Port
            Credential = $Credential
            Path = $URIPath
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
                $response = Get-VVXURI -Device $Dev @RestSplat

                $responseLength = $response.get_ContentLength()
                if ($responseLength -ge 1024) {
                   $totalLength = [System.Math]::Floor($responseLength/1024)
                }
                else {
                   $totalLength = [System.Math]::Floor(1024/1024)
                }

                $responseStream = $response.GetResponseStream()

                if ($AsStream) {
                    $sr = new-object IO.StreamReader($responseStream)
                    [string]$result = $sr.ReadToEnd()

                    $result
                }
                else {
                    $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $File, Create
                    $buffer = new-object byte[] 10KB
                    $count = $responseStream.Read($buffer,0,$buffer.length)
                    Write-Verbose "$($FunctionName): Screenshot size (in bytes) = $count"
                    $downloadedBytes = $count

                    while ($count -gt 0) {
                        $targetStream.Write($buffer, 0, $count)
                        $count = $responseStream.Read($buffer,0,$buffer.length)
                        $downloadedBytes = $downloadedBytes + $count
                        if (-not $Silent) {
                            Write-Progress -activity "Downloading file.." -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $totalLength)  * 100)
                        }
                    }
                    if (-not $Silent) {
                        Write-Progress -activity "Finished downloading file"
                    }

                    $targetStream.Flush()
                    $targetStream.Close()
                    $targetStream.Dispose()
                }
                $responseStream.Dispose()
            }
            catch {
                $ErrMessage = $_

                if ($ErrMessage.Exception.Message -imatch '(404)') {
                    throw "$($FunctionName): 404 response received. Note that for this function to work the user must MANUALLY configure Settings -> Basic -> Preferences -> Screen Capture -> Enabled."
                }
                else {
                    throw $ErrMessage
                }
            }
        }
    }
}