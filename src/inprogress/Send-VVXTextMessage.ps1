function Send-VVXTextMessage {
    <#
    .SYNOPSIS
    Set the screen capture setting of a device
    .DESCRIPTION
    Set the screen capture setting of a device
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
    Set-VVXScreenCapture -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -ErrorAction:Ignore -Value 1

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
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string]$Priority,

        [Parameter(Mandatory = $true)]
        [string]$Title,

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

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {

            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP
            $ClientApp = $vvxphone.ClientApp
            #$ClientApp = "PolycomVVX-VVX_300"
            #Local port number used on server running script. Make sure this isn't being used by another application.
            $Port = "51234"

            if($user -eq $SipUser)
            {
                #VVX Display Resolutions - Use the same for 400/500/600, and special formatting for 300 and 201.
                #VVX 600     480x252
                #VVX 500     320x220
                #VVX 400     320x240
                #VVX 300     208x104
                #VVX 201    132x64

                $AllowedMessageChars = 0
                $AllowedHeadingChars = 0

                $Date = Get-Date -format g

                if($ClientApp -imatch "PolycomVVX-VVX_6" -or $ClientApp -imatch "PolycomVVX-VVX_5" -or $ClientApp -imatch "PolycomVVX-VVX_4")
                {
                    $AllowedMessageChars = 200  #Limited to 200 chars to fit on the screen.
                    $AllowedHeadingChars = 18    #Limited to 18 chars to not overlap the date.

                    [string]$themeSetting = $ThemeDropDownBox.SelectedItem
                    if($themeSetting -eq "SfB Theme")
                    {
                        #MODERN LOOK
                        $putParams = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: #015077;border-radius: 0px 0px 0px 0px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 1px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                    }
                    elseif($themeSetting -eq "Error Theme")
                    {
                        #RED ALERT
                        $putParams = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: #ff0909;border-radius: 0px 0px 0px 0px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 1px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                    }
                    else #Polycom Theme default fallback
                    {
                        #OLD LOOK
                        $putParams = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: -webkit-linear-gradient(top, #58615e , #00174d);border-radius: 5px 5px 5px 5px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 2px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                    }
                }
                else
                {
                    $AllowedMessageChars = 69    #Limited to 69 chars to fit on the screen.
                    $AllowedHeadingChars = 18
                    $putParams = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{text-align: center; max-width: 180px; word-wrap: break-word;}</style></head><body><h1>$Title</h1>$Message</body></Data></PolycomIPPhone>"
                }

                if(!($message.length -gt $AllowedMessageChars))
                {
                    if(!($Title.length -gt $AllowedHeadingChars))
                    {
                    if($ClientIP -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
                    {

                        if($UseHTTPS)
                        {
                            Write-Host "INFO: Sending message to: $(Script:Proto)://${ClientIP}:${WebServicePort}/push" -foreground "Yellow"
                            $uri = New-Object System.Uri ("$(Script:Proto)://${ClientIP}:${WebServicePort}/push")
                        }
                        else
                        {
                            Write-Host "Sending message to: http://${ClientIP}:${WebServicePort}/push"
                            $uri = New-Object System.Uri ("http://${ClientIP}:${WebServicePort}/push")
                        }


                        #$secpasswd = ConvertTo-SecureString $script:PushPassword -AsPlainText -Force
                        #$mycreds = New-Object System.Management.Automation.PSCredential ($script:PushUsername, $secpasswd)

                        $r = $null
                        try {
                            #REMOVED Invoke-WebRequest because of random failures that would occur and sockets not clearing down correctly... I believe this had something to do with sending Body in web request.
                            #$r = Invoke-WebRequest -Uri $uri -Method POST -Body $putParams -ContentType "text/xml" -Credential $mycreds -TimeoutSec 2

                            #REPLACED WITH .NET CODE
                            $secpasswd = ConvertTo-SecureString $script:PushPassword -AsPlainText -Force
                            $cred = New-Object System.Management.Automation.PSCredential ($script:PushUsername, $secpasswd)

                            # Create a request object using the URI
                            $request = [System.Net.HttpWebRequest]::Create($uri)

                            $request.Credentials = $cred
                            $request.KeepAlive = $true
                            $request.Pipelined = $true
                            $request.AllowAutoRedirect = $false
                            $request.Method = "POST"
                            $request.ContentType = "text/xml"
                            #$request.Accept = "text/xml"

                            $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($putParams)
                            $request.ContentLength = $utf8Bytes.Length
                            $postStream = $request.GetRequestStream()
                            $postStream.Write($utf8Bytes, 0, $utf8Bytes.Length)
                            $postStream.Dispose()

                            try
                            {
                              $response = $request.GetResponse()
                            }
                            catch
                            {
                              $response = $Error[0].Exception.InnerException.Response;
                              Throw "Exception occurred in $($MyInvocation.MyCommand): `n$($_.Exception.Message)"
                            }

                            $reader = [IO.StreamReader] $response.GetResponseStream()
                            $output = $reader.ReadToEnd()
                            $r = $output

                            $reader.Close()
                            $response.Close()
                            Write-Output $output


                        } catch {
                            Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                            Write-Host "Exception:" $_.Exception.Message -foreground "red"
                            if($_.Exception.Response.StatusCode.value__ -eq "")
                            {
                                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                            }
                        }
                        if($r -imatch "Push Message will be displayed successfully" -and $r -ne $null)
                        {
                            $objInformationTextBox.Text += "${SipUser}: Send SUCCESS!`n"
                            Write-Host "${SipUser}: Message Send SUCCESS!" -foreground "green"
                            Write-Host "RESPONSE: $r"
                        }
                        else
                        {
                            $objInformationTextBox.Text += "${SipUser}: Send FAILURE.`n"
                            Write-Host "${SipUser}: Send Message FAILURE." -foreground "red"
                            Write-Host "RESPONSE: $r"
                        }
                    }
                    else
                    {
                        $objInformationTextBox.Text += "${SipUser}: FAILURE No IP.`n"
                        Write-Host "ERROR: No IP Address was avaialable for user ${SipUser}..." -foreground "red"
                    }
                    }
                    else
                    {
                        Write-Host "ERROR: Not Sent to ${SipUser}. Message title is " $title.length " character long. Messages are limited to $AllowedHeadingChars characters." -foreground "red"
                        $objInformationTextBox.Text += "Message to ${SipUser}: FAILURE (Message title contains too many chars)`n"
                    }
                }
                else
                {
                    Write-Host "ERROR: Not Sent to ${SipUser}. Message is " $message.length " character long. Messages are limited to $AllowedMessageChars characters." -foreground "red"
                    $objInformationTextBox.Text += "Message to ${SipUser}: FAILURE (Message contains too many chars)`n"
                }
            }
        }
    }
}