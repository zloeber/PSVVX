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
    Local port to use for connection to device. Defaults to a random unused high port.
    .EXAMPLE
    Find-VVXDevice -Device '192.168.1.100'

    Checks to see if the device at 192.168.1.100 is a VVX device.
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
        [string]$LocalIP = (Get-PIIPAddress | Select -First 1).IP.ToString(),

        [Parameter()]
        [int]$LocalPort = (Get-UnusedHighPort)
    )

    begin {
        if ($Script:ThisModuleLoaded) {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose "$($FunctionName): Begin."

        #Note: This socket timeout has been tuned to allow phones to respond within 350ms. This timer should work well in most cases, however, if you have a device that is on a slow link you may need to make this value higher.
        $theDiscoveryWaitTime = $DiscoveryWaitTime * 1000
        $serverip = "$($LocalIP):$LocalPort"
        $phoneid = "discover"
        $message = @"
NOTIFY sip:$($phoneid):$($Port) SIP/2.0
Via: SIP/2.0/UDP ${serverip}
From: <sip:$($phoneid)>;tag=1530231855-106746376154
To: <sip:%%DEVICE%%:$($Port)>
Call-ID: %%CALLID%%
CSeq: 1500 NOTIFY
Contact: <sip:$($phoneid)>
Content-Length: 0


"@
        # Lookup table for matching responses to device type.
        $DeviceTypes = @{
            "VVX500@" = 'VVX 500'
            "VVX501@" = 'VVX 501'
            "VVX600@" = 'VVX 600'
            "VVX601@" = 'VVX 601'
            "VVX300@" = 'VVX 300'
            "VVX301@" = 'VVX 301'
            "VVX310@" = 'VVX 310'
            "VVX311@" = 'VVX 311'
            "VVX400@" = 'VVX 400'
            "VVX401@" = 'VVX 401'
            "VVX410@" = 'VVX 410'
            'PolycomVVX-VVX_410' = 'VVX 410'
            "VVX411@" = 'VVX 411'
            "VVX200@" = 'VVX 200'
            "VVX201@" = 'VVX 201'
            'PolycomRealPresenceTrio-Trio_8800' = 'Trio 8800'
            'PolycomRealPresenceTrio-Trio_8500' = 'Trio 8500'
        }
        $Devices = @()
    }

    process {
        $Devices += $Device
    }
    end {
        ForEach ($Device in $Devices) {
            [string]$returndata = ""
            $receivebytes = $null

            [string]$time = [DateTime]::Now
            $time = $time.Replace(" ","").Replace("/","").Replace(":","")
            $call_id = "${time}msgto${phoneid}"
            $Result = @{
                Device = $Device
                DeviceType = $null
                Port = $Port
                LocalIP = $LocalIP
                Response = $null
                Status = 'Unknown'
                LyncServer = $null
                SipUser = $null
                UserAgent = $null
            }

            $sipmessage = $message -replace '%%DEVICE%%',$Device -replace '%%CALLID%%',$call_id
            Write-Verbose "$($FunctionName): Discovering $($Device):$($Port) using source of $serverip"

            $a = new-object system.text.asciiencoding
            $byte = $a.GetBytes($sipmessage)

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
                Write-Verbose "$($FunctionName): Polling device for $theDiscoveryWaitTime ms..."
                if($Socket.Poll($theDiscoveryWaitTime,[System.Net.Sockets.SelectMode]::SelectRead)) {
                    $receivebytes = $Socket.Receive($buffer)
                }
                else {
                    Write-Verbose "$($FunctionName): No SIP response received"
                    #Timed out
                    $Result.Status = 'No Response'
                    $BytesReceivedError = $true
                }
            }
            catch {
                $Result.Response = $_
                Write-Verbose "$($FunctionName): Socket failure occurred"
                $Result.Status = 'Socket Failure'
                $BytesReceivedError = $true
            }
            if(-not $BytesReceivedError) {
                if ($receivebytes) {
                    [string]$returndata = $a.GetString($buffer, 0, $receivebytes)

                    $Result.Response = $returndata
                    $Result.Status = 'Online'
                    if ($returndata -imatch "SIP/2.0 200 OK") {
                        Write-Verbose "$($FunctionName): Received SIP/2.0 200 OK reponse"
                        $Result.DeviceType = 'SIP Device'
                        if ($returndata -imatch [string]($DeviceTypes.Keys -join '|')) {
                            $Result.DeviceType = $DeviceTypes[$Matches[0]]
                        }

                        if ($returndata -imatch "Contact: <sip:") {
                            [string]$returndataSplit = ($returndata -split 'Contact: <sip:')[1]
                            [string]$returndataSplit = ($returndataSplit -split "`r`n")[0]

                            if ($returndataSplit.Contains(";opaque")) {
                                $Result.SipUser = ($returndataSplit -split ';')[0]

                                if($returndata -imatch "targetname=") {
                                    [string]$LyncServerStringTemp = ($returndata -split "targetname=`"")[1]
                                    $Result.LyncServer = ($LyncServerStringTemp -split "`",")[0]
                                }
                            }
                        }
                        if($returndata -imatch "User-Agent: ") {
                            [string]$UserAgentTemp = ($returndata -split 'User-Agent: ')[1]
                            $Result.UserAgent = ($UserAgentTemp -split "`r`n")[0]
                        }
                    }
                }
                else {
                    $Result.Status = 'No Data Received'
                }
            }
            $Socket.Close()
            $Socket.Dispose()
            $Socket = $null

            New-Object -TypeName psobject -Property $Result | Select-Object Device,DeviceType,Port,LocalIP,Response,Status,LyncServer,SipUser,UserAgent
        }
    }
}
