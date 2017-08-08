function Send-VVXTextMessage {
    <#
    .SYNOPSIS
    Set the screen capture setting of a device
    .DESCRIPTION
    Set the screen capture setting of a device
    .PARAMETER Device
    Device to send command for processing.
    .PARAMETER Title
    Message title
    .PARAMETER Message
    Body of the message
    .PARAMETER Priority
    Message priority
    .PARAMETER Theme
    Messagebox theme
    .PARAMETER Base
    Base URL for push messages (defaults to 'push')
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
    $cred = Get-Credential -UserName 'vvxmanager' -Message 'Please supply the push account password for the device'
    Send-VVXTextMessage -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -ErrorAction:Ignore -Title 'test' -Message 'Test message' -Priority 1

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

        [Parameter()]
        [ValidateSet('S4B','Error','Standard')]
        [string]$Theme = 'S4B',

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter()]
        [ValidateSet('HTTP','HTTPS')]
        [string]$Protocol = 'HTTP',

        [Parameter()]
        [int]$Port = 80,

        [Parameter()]
        [string]$Base = 'push',

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

    $vvxphone = Find-VVXDevice -Device $Device
    if ($vvxphone.status -eq 'online') {
        #VVX Display Resolutions - Use the same for 400/500/600, and special formatting for 300 and 201.
        #VVX 600     480x252
        #VVX 500     320x220
        #VVX 400     320x240
        #VVX 300     208x104
        #VVX 201    132x64

        $AllowedMessageChars = 0
        $AllowedHeadingChars = 0

        $Date = Get-Date -format g

        if($vvxphone.ClientApp -imatch 'PolycomVVX-VVX_[4-6]') {
            $AllowedMessageChars = 200  #Limited to 200 chars to fit on the screen.
            $AllowedHeadingChars = 18    #Limited to 18 chars to not overlap the date.

            switch ($Theme) {
                's4b' {
                    #MODERN LOOK
                    $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: #015077;border-radius: 0px 0px 0px 0px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 1px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                }
                'Error' {
                    #RED ALERT
                    $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: #ff0909;border-radius: 0px 0px 0px 0px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 1px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                }
                'Standard' {
                    #OLD LOOK
                    $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{background-color:black}.container{position:absolute;left:50%;top:50%;margin:-80px 0 0 -140px;}.box{background: -webkit-linear-gradient(top, #58615e , #00174d);border-radius: 5px 5px 5px 5px;width: 280px;max-height: 150px;word-wrap: break-word;overflow: hidden;border: 2px solid #808080;margin: 0px auto;}.box bold{font-weight:bold;font-family : geneva, helvetica;color : #FFFFFF; font-size : medium;}.box p{ font-family : geneva, helvetica;color : #FFFFFF; font-size : small;margin:10px 10px 25px 10px;}.box date{font-family:geneva,helvetica;color:#FFFFFF; font-size:x-small; position:absolute; left:170px; top:10px;}.box exit{font-family : geneva, helvetica;position:absolute; left:230px; bottom:8%;}a:link {color:#FFFFFF;}a:visited {color:#FFFFFF;}a:hover {color:#FFFFFF;}a:active {color:#FFFFFF;}</style></head><body><div class=`"container`"><div class=`"box`"><p><bold>$Title</bold><date>$Date</date><br>$Message<br><bold><exit><a href=`"Key:Home`">Exit</a></exit></bold></p></div></div></body></Data></PolycomIPPhone>"
                }
            }
        }
        else {
            $AllowedMessageChars = 69    #Limited to 69 chars to fit on the screen.
            $AllowedHeadingChars = 18
            $Body = "<PolycomIPPhone><Data priority=`"$Priority`"><head><style>body{text-align: center; max-width: 180px; word-wrap: break-word;}</style></head><body><h1>$Title</h1>$Message</body></Data></PolycomIPPhone>"
        }

        if(-not ($Message.length -gt $AllowedMessageChars)) {
            if(-not ($Title.length -gt $AllowedHeadingChars)) {
                $PushSplat = @{
                    Device = $Device
                    RetryCount = $RetryCount
                    Protocol = $Protocol
                    Port = $Port
                    Base = $Base
                    Credential = $Credential
                    Body = $Body
                }
                if ($IgnoreSSLCertificate) {
                    $PushSplat.IgnoreSSLCertificate = $true
                }
                Send-VVXPushCommand @PushSplat
            }
            else {
                Write-Error "$($FunctionName): Not Sent to $Device. Message title is " $title.length " characters long. Messages are limited to $AllowedHeadingChars characters for this model of VVX device"
            }
        }
        else {
            Write-Error "$($FunctionName): Not Sent to $Device. Message is " $message.length " characters long. Messages are limited to $AllowedMessageChars characters."
        }
    }
    else {
        Write-Warning "$($FunctionName): $Device is not able to be connected to or is not a VVX device."
    }
}