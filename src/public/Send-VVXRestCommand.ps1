function Send-VVXRestCommand {
    <#
    .SYNOPSIS
    Sends a REST command to a VVX device.
    .DESCRIPTION
    Sends a REST command to a VVX device.
    .PARAMETER Device
    Device to send command for processing.
    .PARAMETER Protocol
    Protocol to use. Must be HTTP or HTTPS. Default is HTTP.
    .PARAMETER Port
    Port to use. Default is 80.
    .PARAMETER Method
    REST method to send. Can be Head, Get, Put, Patch, Post, or Delete. Default is Get.
    .PARAMETER Command
    RESTful command to send.
    .PARAMETER Base
    Base REST uri path. Defaults to api/v1
    .PARAMETER FullURI
    A full web url to parse
    .PARAMETER Body
    The body of the REST request
    .PARAMETER RetryCount
    Number of times to retry if unsuccessful. Default is 3 times.
    .PARAMETER RequestTimeout
    Amount of time to allow for the request to process (in ms). Defaults to 300 ms.
    .PARAMETER Credential
    User ID and password for the device
    .PARAMETER IgnoreSSLCertificate
    Ignore any certificate warnings

    .EXAMPLE
    $cred = Get-Credential -UserName 'Polycom' -Message 'Please supply the admin password for the device'
    Send-VVXRestCommand -Command 'mgmt/device/info' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
    Send-VVXRestCommand -Command 'webCallControl/callStatus' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
    Send-VVXRestCommand -Command 'mgmt/network/info' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
    Send-VVXRestCommand -Command 'mgmt/lineInfo' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
    Send-VVXRestCommand -Command 'webCallControl/sipStatus' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
    Send-VVXRestCommand -Command 'mgmt/network/stats' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate

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
        [int]$RequestTimeOut = 300,

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
                $request.Timeout = $RequestTimeOut

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