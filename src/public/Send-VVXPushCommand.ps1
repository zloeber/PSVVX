function Send-VVXPushCommand {
    <#
    .SYNOPSIS
    Sends a push command to a VVX device.
    .DESCRIPTION
    Sends a push command to a VVX device.
    .PARAMETER Device
    Device to send push command for processing.
    .PARAMETER Protocol
    Protocol to use. Must be HTTP or HTTPS. Default is HTTP.
    .PARAMETER Port
    Port to use. Default is 80.
    .PARAMETER Base
    Base push URI path. Defaults to push
    .PARAMETER FullURI
    A full web url to parse
    .PARAMETER Body
    The body of the push command
    .PARAMETER RetryCount
    Number of times to retry if unsuccessful. Default is 3 times.
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
        [alias('Creds','Cred')]
        [Management.Automation.PSCredential]$Credential
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