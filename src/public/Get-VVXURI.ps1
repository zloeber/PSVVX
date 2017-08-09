function Get-VVXURI {
    <#
    .SYNOPSIS
    Attempts to retrieve a VVX URI.
    .DESCRIPTION
    Attempts to retrieve a VVX URI.
    .PARAMETER Device
    Device to send HTTP get request
    .PARAMETER Protocol
    Protocol to use. Must be HTTP or HTTPS. Default is HTTP.
    .PARAMETER Port
    Port to use. Default is 80.
    .PARAMETER Path
    Base REST uri path.
    .PARAMETER FullURI
    A full web url to parse
    .PARAMETER RetryCount
    Number of times to retry if unsuccessful. Default is 3 times.
    .PARAMETER RequestTimeout
    Amount of time to allow for the request to process (in ms). Defaults to 800 ms.
    .PARAMETER Credential
    User ID and password for the device
    .PARAMETER IgnoreSSLCertificate
    Ignore any certificate warnings
    .EXAMPLE
    TBD
    .NOTES
    Author: Zachary Loeber
    .LINK
    https://github.com/zloeber/PSVVX
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
        [string]$Path,

        [Parameter(Position = 0, ParameterSetName = 'URIPassed', Mandatory = $true)]
        [string]$FullURI,

        [Parameter(ParameterSetName = 'URINotPassed')]
        [Parameter(ParameterSetName = 'URIPassed')]
        [int]$RetryCount = 3,

        [Parameter(ParameterSetName = 'URINotPassed')]
        [Parameter(ParameterSetName = 'URIPassed')]
        [int]$RequestTimeOut = 800,

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
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
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
                $ThisURI = "$($Protocol)://$($Device):$Port/$Path"
                Write-Verbose "$($FunctionName): URI Constructed = $ThisURI"
                $URIs += $ThisURI
            }
        }
    }
    end {
        foreach ($URI in $URIs) {
            try {
                Write-Verbose "$($FunctionName): Creating HTTP request to $URI"
                $request = [System.Net.HttpWebRequest]::Create($URI)
                $request.KeepAlive = $true
                $request.Pipelined = $true
                $request.AllowAutoRedirect = $false
                $request.Method = 'Get'
                $request.Timeout = $RequestTimeOut

                if ($null -ne $Credential) {
                    $request.Credentials = $Credential
                }
                $Script:LastRESTCall = @{
                    URI = $URI
                    Method = 'Get'
                    Credential = $Credential
                    Body = $null
                }

                $request.GetResponse()
            }
            catch {
                $RequestError = $_
                if ($RetryCount -gt 0) {
                    Write-Verbose "$($FunctionName): Issue connecting to URI, Retries Left = $RetryCount"
                    $RetryCount--
                    $ResendSplat = @{
                        FullURI = $URI
                        RetryCount = $RetryCount
                        RequestTimeout = $RequestTimeOut
                    }
                    if ($IgnoreSSLCertificate) {
                        $ResendSplat.IgnoreSSLCertificate = $true
                    }
                    if ($null -ne $Credential) {
                        $ResendSplat.Credential = $Credential
                    }
                    Get-VVXURI @ResendSplat
                }
                else {
                    throw $_.Exception.Message
                }
            }
        }
    }
}

<#
function downloadFile($url, $targetFile) {
    $uri = New-Object "System.Uri" "$url"
    $request = [System.Net.HttpWebRequest]::Create($uri)
    $request.set_Timeout(15000) #15 second timeout
    $response = $request.GetResponse()
    $totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
    $responseStream = $response.GetResponseStream()
    $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
    $buffer = new-object byte[] 10KB
    $count = $responseStream.Read($buffer,0,$buffer.length)
    $downloadedBytes = $count
    while ($count -gt 0)
    {
        [System.Console]::CursorLeft = 0
        [System.Console]::Write("Downloaded {0}K of {1}K", [System.Math]::Floor($downloadedBytes/1024), $totalLength)
        $targetStream.Write($buffer, 0, $count)
        $count = $responseStream.Read($buffer,0,$buffer.length)
        $downloadedBytes = $downloadedBytes + $count
    }
    "`nFinished Download"
    $targetStream.Flush()
    $targetStream.Close()
    $targetStream.Dispose()
    $responseStream.Dispose()
}
#>