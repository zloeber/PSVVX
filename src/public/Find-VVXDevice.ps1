function Find-VVXDevice {
    <#
    .SYNOPSIS
    Discovers a VVX device.
    .DESCRIPTION
    Discovers a VVX device.
    .PARAMETER Device
    Device to discover.
    .PARAMETER DiscoveryWaitTime
    Time in ms to wait for responses. Defaults to 350ms
    .PARAMETER Port
    Port to use for remote device connection. Default is 5060.
    .PARAMETER LocalIP
    Local IP address to use for connection to device. Defaults to an autodiscovered IP of the local system.
    .PARAMETER LocalPort
    Local port to use for connection to device. Defaults to 51234.
    .EXAMPLE
    TBD
    .NOTES
    Author: Zachary Loeber
    .LINK
    https://github.com/zloeber/PSVVX
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
            SIPUserName = $null
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
                            $Result.SIPUserName = ($returndataSplit -split ';')[0]

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
