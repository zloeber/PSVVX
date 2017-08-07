########################################################################
# Name: Skype4B / Lync Polycom VVX Phone Manager v2
# Version: v2.1.0 (28/7/2017)
# Original Release Date: 1/10/2015
# Created By: James Cussen
# Web Site: http://www.myskypelab.com
# Notes: This is a Powershell tool. To run the tool, open it from the Powershell command line on a Lync server.
#         For more information on the requirements for setting up and using this tool please visit http://www.myskypelab.com.
#
# Copyright: Copyright (c) 2017, James Cussen (www.myskypelab.com) All rights reserved.
# Licence:     Redistribution and use of script, source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#                1) Redistributions of script code must retain the above copyright notice, this list of conditions and the following disclaimer.
#                2) Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#                3) Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#                4) This license does not include any resale or commercial use of this software.
#                5) Any portion of this software may not be reproduced, duplicated, copied, sold, resold, or otherwise exploited for any commercial purpose without express written consent of James Cussen.
#            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; LOSS OF GOODWILL OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Pre-requisistes:
#        - To use this tool the VVX needs to have at lease 5.4 version of software.
#        - The VVX must have the following setting enabled in it's configuration "<apps apps.restapi.enabled="1" />"
#        - For more detail on pre-requisistes please visit http://www.myskyplab.com.
#        - Command line: .\Skype4B-Lync-PolycomVVXManager2.00.ps1 -WebPortInput "40" -UseHTTPSInput "false" -AdminUsernameInput "AdminUsername" -AdminPasswordInput "AdminPassword" -PushUsernameInput "PushUsername" -PushPasswordInput "PushPassword" -IPRangeInput "192.168.0.1-192.168.0.200"
#
# Known Issues:
#        - If Get-CsClientPinInfo throws the error "no available servers to connect to", check your Proxy Settings in IE and make sure you can get to the Lync Control Panel. This cmdlet appears to use IE proxy settings.
#        - The VVX Phone Manager Tool uses the registration database within the Lync/Skype for Business monitoring database to determine the IP addresses of phones. However, registrations are logged only at the time when a user manually signs in with a PIN or with Domain authentication details. If a user moves to a new subnet/IP Address without signing it out/back in then it�s new IP Address may not show up in the Monitoring database. So in some cases the Monitoring database may not produce a complete list of registered devices..
#
# Release Notes:
# 2.00 Initial Release - Support for VVX REST interface
#    - Massive update in version 2 to leveage all the features of the REST interface included in VVX version 5.40
#    - Discovery method has been changed to use monitoring database. Old method was inconsistent with discovering IP addresses of devices and required lots of firewall changes.
#
# 2.01 Enhancements
#    - Fixed issue with the Get Config function
#    - Increased the timeout for discovery ping from 200ms to 350ms to handle sites that might be over a higher latency connection. Also added a setting called "Discovery Wait Time" which allows you to tune the time that the tool will wait for responses from discovery messages sent to phones (setting between 200ms-1000ms).
#
# 2.02 Bug Fixes and Enhancements
#    - Fixed issue with rescan on import.
#    - Included new Polycom MAC Address range 64:16:7F
#    - Added a discovery summary at the end of IP Based discovery. This gives a useful summary when scanning multiple IP ranges.
#    - The command line input for IPRangeInput now accepts muiltple ranges eg. Skype4B-Lync-PolycomVVXManager2.02.ps1 -IPRangeInput "192.168.0.1-192.168.0.200,192.168.0.10/24"
#
# 2.03 Bug fix
#    - There was an issue with detecting users when capital "SIP:" was used as part of their SIP URI.
#
# 2.04 Bug Fix
#    - Fixed a couple of typos that affected operation on Powershell 5
#    - Added more VVX types when discovering logged out phones
#
# 2.05 Bug Fix
#    - Added port number to Screen viewing URL. Required when non-standard HTTP/HTTPS port is used.
#
# 2.10 Fixes and Enhancement! (why 10? "Because we are not building an incremental product, the new Windows is Windows 10... I�m serious this time." ...Or in this case, so you are encouraged to update because there are very some important fixes in this version)
#    - Replaced Invoke-RestMethods with shiny new .net web requests to fix annoying connection issues found in previous versions.
#    - Added option in Send Message dialog to change the theme of the dialog displayed on the VVX. Default is to send the new SfB dialog look, the original Polycom theme and red/alarm themes are also available.
#    - Updated Icon to MySkypeLab icon.
#
#########################################################################



param (
[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $WebPortInput,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $UseHTTPSInput,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $AdminUsernameInput,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $AdminPasswordInput,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $PushUsernameInput,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $PushPasswordInput,

[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[ValidateNotNullOrEmpty()]
[string] $IPRangeInput
)


# HTTP default is "80", and HTTPS default is "443"
$script:WebPort = "443"
if($WebPortInput -ne $null -and $WebPortInput -ne "")
{
    Write-Host "INFO: Using command line WebPortInput setting = $WebPortInput" -foreground "Yellow"
    $script:WebPort = $WebPortInput
}

$script:WebServicePort = "443"
if($WebPortInput -ne $null -and $WebPortInput -ne "")
{
    $script:WebServicePort = $WebPortInput
}


#setting $true will make web interface connections use $(Script:Proto)://
$script:UseHTTPS = $true
if($UseHTTPSInput.ToLower() -eq "true")
{
    Write-Host "INFO: Using command line UseHTTPSInput setting = $UseHTTPSInput" -foreground "Yellow"
    $script:UseHTTPS = $true
    $Script:Proto = 'https'
}
elseif($UseHTTPSInput.ToLower() -eq "false")
{
    Write-Host "INFO: Using command line UseHTTPSInput setting = $UseHTTPSInput" -foreground "Yellow"
    $script:UseHTTPS = $false
    $Script:Proto = 'http'
}



# Examples:
# $script:IPRanges = @("192.168.0.200-192.168.0.220", "192.168.1.10-192.168.1.20")
# $script:IPRanges = @("192.168.0.200/24", "192.168.1.10/24")
$script:IPRanges = @()
if($IPRangeInput -ne $null -and $IPRangeInput -ne "")
{
    if($IPRangeInput.Contains(",")) #CHECK THERE ARE MULTIPLE
    {
        $Ranges = $IPRangeInput -split ","

        foreach($Range in $Ranges)
        {
            if($Range.Contains("/")) #CHECK SUBNET FORMAT
            {
                $IPRangeSplit = $Range -split "/"
                [string]$Network = $IPRangeSplit[0]
                if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
                {
                    [string]$Mask = $IPRangeSplit[1]

                    if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
                    {
                        Write-Host "Range format accepted."
                        $script:IPRanges += @($Range)
                    }
                    else
                    {
                        Write-Host "ERROR: IP Range not in correct format. Bad subnet mask." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "ERROR: IP Range not in correct format. Bad network address." -foreground
                }

            }
            else #CHECK FOR ALTERNATE FORMAT
            {
                if($Range.Contains("-"))
                {
                    $IPRangeSplit = $Range -split "-"
                    if($IPRangeSplit[0] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b" -and $IPRangeSplit[1] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
                    {
                        Write-Host "Range format accepted."
                        $script:IPRanges += @($Range)
                    }
                    else
                    {
                        Write-Host "ERROR: IP Range not in correct format." -foreground "red"
                    }

                }
                else
                {
                    Write-Host "ERROR: IP Range not in correct format." -foreground "red"
                }
            }
        }
    }
    else
    {
        if($IPRangeInput.Contains("/")) #CHECK SUBNET FORMAT
        {
            $IPRangeSplit = $IPRangeInput -split "/"
            [string]$Network = $IPRangeSplit[0]
            if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
            {
                [string]$Mask = $IPRangeSplit[1]

                if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
                {
                    $script:IPRanges = @($IPRangeInput)
                }
                else
                {
                    Write-Host "ERROR: IP Range not in correct format. Bad subnet mask." -foreground "red"
                }
            }
            else
            {
                Write-Host "ERROR: IP Range not in correct format. Bad network address." -foreground
            }

        }
        else #CHECK FOR ALTERNATE FORMAT
        {
            if($IPRangeInput.Contains("-"))
            {
                $IPRangeSplit = $IPRangeInput -split "-"
                if($IPRangeSplit[0] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b" -and $IPRangeSplit[1] -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
                {
                    Write-Host "Range format accepted."
                    $script:IPRanges = @($IPRangeInput)
                }
                else
                {
                    Write-Host "ERROR: IP Range not in correct format." -foreground "red"
                }

            }
            else
            {
                Write-Host "ERROR: IP Range not in correct format." -foreground "red"
            }
        }
    }
}

#Custom username and password for messaging.
$script:PushUsername = "vvxmanager"
if($PushUsernameInput -ne $null -and $PushPasswordInput -ne "")
{
    Write-Host "INFO: Using command line PushUsernameInput setting = $PushUsernameInput" -foreground "Yellow"
    $script:PushUsername = $PushUsernameInput
}

$script:PushPassword = "vvxmanager"
if($PushPasswordInput -ne $null -and $PushPasswordInput -ne "")
{
    Write-Host "INFO: Using command line PushPasswordInput setting = $PushPasswordInput" -foreground "Yellow"
    $script:PushPassword = $PushPasswordInput
}
#Custom administrator and REST web service username and password
$script:AdminUsername = "Polycom"
if($AdminUsernameInput -ne $null -and $AdminUsernameInput -ne "")
{
    Write-Host "INFO: Using command line AdminUsernameInput setting = $AdminUsernameInput" -foreground "Yellow"
    $script:AdminUsername = $AdminUsernameInput
}

$script:AdminPassword = "12345"
if($AdminPasswordInput -ne $null -and $AdminPasswordInput -ne "")
{
    Write-Host "INFO: Using command line AdminPasswordInput setting = $AdminPasswordInput" -foreground "Yellow"
    $script:AdminPassword = $AdminPasswordInput
}

#This is the default SQL query length in months
$Script:MonitoringDatabaseQueryMonths = 6

#This is the default amount of time that the tool will wait for responses from VVXs during the discovery process
$Script:DiscoveryWaitTime = 350


#This setting controls the level at which PUSH messages are sent to the VVX. This is a configuration item in the phones. By default the tool is set to "Critical"
$script:MessagePriority = "Critical"

$script:computers = @()
$script:tempFTPTestFilePath = "c:\temp\"
$script:CancelScan = $false

$script:NumberOfUsersImported = 0


$theVersion = $PSVersionTable.PSVersion
$MajorVersion = $theVersion.Major

Write-Host ""
Write-Host "--------------------------------------------------------------"
Write-Host "Powershell Version Check..." -foreground "yellow"
if($MajorVersion -eq  "1")
{
    Write-Host "This machine only has Version 1 Powershell installed.  This version of Powershell is not supported." -foreground "red"
    exit
}
elseif($MajorVersion -eq  "2")
{
    Write-Host "This machine has Version 2 Powershell installed. This version of Powershell is not supported." -foreground "red"
    exit
}
elseif($MajorVersion -eq  "3")
{
    Write-Host "This machine has version 3 Powershell installed. CHECK PASSED!" -foreground "green"
}
elseif($MajorVersion -eq  "4")
{
    Write-Host "This machine has version 4 Powershell installed. CHECK PASSED!" -foreground "green"
}
elseif($MajorVersion -eq  "5")
{
    Write-Host "This machine has version 5 Powershell installed. CHECK PASSED!" -foreground "green"
}
else
{
    Write-Host "This machine has version $MajorVersion Powershell installed. Unknown level of support for this version." -foreground "yellow"
}
Write-Host "--------------------------------------------------------------"
Write-Host ""

Function Get-MyModule
{
Param([string]$name)

    if(-not(Get-Module -name $name))
    {
        if(Get-Module -ListAvailable | Where-Object { $_.name -eq $name })
        {
            Import-Module -Name $name
            return $true
        } #end if module available then import
        else
        {
            return $false
        } #module not available
    } # end if not module
    else
    {
        return $true
    } #module already loaded
} #end function get-MyModule


$Script:LyncModuleAvailable = $false
$Script:SkypeModuleAvailable = $false


Write-Host "--------------------------------------------------------------"
#Import Lync Module
if(Get-MyModule "Lync")
{
    Invoke-Expression "Import-Module Lync"
    Write-Host "Imported Lync Module..." -foreground "green"
    $Script:LyncModuleAvailable = $true
}
else
{
    Write-Host "Unable to import Lync Module..." -foreground "yellow"
}
#Import SkypeforBusiness Module
if(Get-MyModule "SkypeforBusiness")
{
    Invoke-Expression "Import-Module SkypeforBusiness"
    Write-Host "Imported SkypeforBusiness Module..." -foreground "green"
    $Script:SkypeModuleAvailable = $true
}
else
{
    $Script:RESTOnlyMode = $true
    Write-Host "Unable to import SkypeforBusiness Module... Running in REST only mode." -foreground "yellow"
}


add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy
#[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11

#Multi-thread variables
$DiscoverSyncHash = [hashtable]::Synchronized(@{})
$DiscoverSyncHash.VVXphones = @()
$DiscoverSyncHash.NumberOfUsersDiscovered = 0
$DiscoverSyncHash.CancelScan = $false

$Script:CurrentCallID = ""

#Multi-threading, bro!
$objRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 50, $Host)
$objRunspacePool.Open()


$Script:ConnectState = $false
$Script:MonitoringDatabaseAvailable = $true


#Select only single computer from a pool or single computer from the pool. (Paired Pools are still added as separtate machines)
if (-not $Script:RESTOnlyMode) {
    Get-CsPool | where-object {$_.Services -like "Registrar*"} | select-object Computers | ForEach-Object {$computers +=  $_.Computers}
    Write-Host ""
    Get-CsCommonAreaPhone | select-object SipAddress, DisplayName | ForEach-Object {[string]$CommonSipAddress = $_.SipAddress; [string]$CommonDisplayName = $_.DisplayName; write-host "Found Common Area Device: $CommonSipAddress ($CommonDisplayName)" -foreground yellow}
}

# Set up the form  ============================================================

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

$objForm = New-Object System.Windows.Forms.Form
$objForm.Text = "Skype4B / Lync Polycom VVX Manager v2.10"
$objForm.Size = New-Object System.Drawing.Size(710,610)
$objForm.MinimumSize = New-Object System.Drawing.Size(710,370)
$objForm.StartPosition = "CenterScreen"
#Myskypelab Icon
[byte[]]$WindowIcon = @(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 32, 0, 0, 0, 32, 8, 6, 0, 0, 0, 115, 122, 122, 244, 0, 0, 0, 6, 98, 75, 71, 68, 0, 255, 0, 255, 0, 255, 160, 189, 167, 147, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 11, 19, 0, 0, 11, 19, 1, 0, 154, 156, 24, 0, 0, 0, 7, 116, 73, 77, 69, 7, 225, 7, 26, 1, 36, 51, 211, 178, 227, 235, 0, 0, 5, 235, 73, 68, 65, 84, 88, 195, 197, 151, 91, 108, 92, 213, 21, 134, 191, 189, 207, 57, 115, 159, 216, 78, 176, 27, 98, 72, 226, 88, 110, 66, 66, 34, 185, 161, 168, 193, 73, 21, 17, 2, 2, 139, 75, 164, 182, 106, 145, 170, 190, 84, 74, 104, 65, 16, 144, 218, 138, 138, 244, 173, 69, 106, 101, 42, 129, 42, 149, 170, 162, 15, 168, 168, 151, 7, 4, 22, 180, 1, 41, 92, 172, 52, 196, 68, 105, 130, 19, 138, 98, 76, 154, 27, 174, 227, 248, 58, 247, 57, 103, 175, 62, 236, 241, 177, 199, 246, 140, 67, 26, 169, 251, 237, 236, 61, 179, 215, 191, 214, 191, 214, 191, 214, 86, 188, 62, 37, 252, 31, 151, 174, 123, 42, 224, 42, 72, 56, 138, 152, 99, 191, 175, 247, 114, 107, 29, 172, 75, 106, 94, 254, 74, 156, 109, 13, 58, 180, 155, 53, 240, 216, 64, 129, 63, 156, 43, 95, 55, 0, 106, 62, 5, 158, 134, 83, 59, 147, 116, 36, 106, 7, 103, 188, 44, 228, 13, 120, 202, 126, 151, 12, 100, 3, 225, 183, 231, 203, 60, 55, 88, 66, 4, 80, 215, 0, 96, 89, 68, 113, 97, 87, 138, 180, 3, 163, 101, 120, 116, 160, 192, 161, 81, 159, 203, 69, 33, 230, 40, 58, 27, 52, 251, 215, 69, 248, 198, 74, 183, 238, 165, 175, 141, 248, 60, 114, 178, 192, 165, 188, 44, 9, 100, 22, 128, 192, 127, 238, 73, 209, 18, 81, 252, 109, 52, 224, 222, 247, 179, 179, 46, 206, 93, 102, 142, 119, 193, 76, 216, 96, 247, 13, 46, 223, 189, 201, 101, 207, 74, 143, 148, 99, 183, 159, 250, 184, 72, 207, 96, 169, 46, 136, 16, 192, 183, 91, 61, 94, 233, 140, 241, 81, 198, 176, 229, 173, 204, 226, 198, 175, 102, 5, 194, 243, 157, 113, 246, 221, 236, 225, 42, 232, 29, 9, 184, 255, 104, 174, 62, 0, 165, 192, 239, 78, 163, 129, 174, 195, 57, 14, 143, 5, 255, 115, 114, 197, 29, 197, 200, 221, 41, 82, 14, 188, 63, 30, 240, 245, 190, 220, 162, 145, 208, 0, 141, 174, 66, 1, 37, 129, 195, 163, 254, 34, 40, 1, 191, 70, 25, 250, 50, 75, 197, 156, 149, 15, 132, 27, 254, 62, 205, 229, 178, 176, 163, 201, 161, 103, 115, 172, 182, 14, 196, 181, 53, 114, 38, 107, 64, 22, 194, 92, 147, 80, 200, 67, 105, 50, 247, 165, 171, 156, 104, 141, 105, 70, 186, 211, 200, 131, 105, 214, 46, 82, 53, 69, 3, 119, 244, 217, 240, 63, 177, 214, 35, 233, 170, 250, 66, 164, 20, 11, 221, 52, 240, 171, 77, 49, 114, 6, 198, 74, 18, 158, 106, 5, 239, 110, 79, 208, 236, 41, 254, 93, 16, 206, 102, 204, 162, 30, 14, 78, 27, 158, 60, 93, 68, 1, 7, 191, 150, 176, 73, 60, 31, 64, 182, 178, 185, 49, 169, 103, 80, 132, 235, 166, 164, 38, 238, 64, 66, 67, 104, 94, 224, 229, 206, 56, 111, 93, 182, 116, 61, 246, 81, 177, 118, 166, 107, 248, 253, 121, 43, 92, 119, 52, 106, 86, 39, 245, 66, 0, 147, 101, 9, 105, 188, 171, 165, 186, 198, 127, 179, 57, 202, 233, 233, 106, 216, 9, 79, 113, 169, 96, 216, 119, 179, 135, 47, 112, 240, 114, 185, 110, 169, 77, 149, 132, 95, 159, 181, 32, 182, 54, 58, 139, 83, 112, 231, 7, 121, 0, 126, 210, 17, 129, 96, 150, 134, 213, 9, 205, 84, 185, 42, 29, 121, 103, 91, 130, 15, 38, 45, 228, 105, 95, 40, 207, 97, 173, 209, 83, 124, 179, 213, 227, 153, 13, 81, 16, 91, 205, 247, 174, 116, 113, 42, 118, 31, 89, 227, 86, 37, 109, 8, 224, 189, 97, 159, 178, 64, 71, 82, 207, 166, 129, 192, 75, 231, 203, 180, 68, 170, 235, 252, 95, 57, 195, 150, 138, 218, 156, 43, 8, 70, 102, 43, 98, 96, 103, 146, 63, 119, 198, 120, 115, 216, 210, 243, 179, 245, 81, 222, 248, 106, 156, 141, 73, 77, 201, 192, 109, 141, 14, 86, 171, 231, 39, 161, 99, 209, 158, 43, 152, 48, 156, 237, 41, 205, 123, 163, 1, 174, 99, 55, 38, 3, 225, 209, 142, 40, 7, 78, 23, 217, 182, 220, 2, 120, 247, 202, 172, 59, 27, 155, 28, 90, 163, 138, 76, 32, 28, 159, 12, 192, 23, 30, 110, 181, 148, 238, 63, 85, 64, 128, 166, 121, 149, 160, 23, 118, 96, 21, 122, 255, 226, 150, 40, 103, 178, 134, 132, 182, 123, 167, 50, 134, 95, 222, 18, 229, 108, 198, 112, 99, 212, 238, 29, 155, 156, 5, 240, 253, 53, 54, 84, 127, 25, 246, 9, 4, 214, 175, 112, 104, 139, 107, 46, 20, 132, 129, 41, 179, 196, 60, 96, 108, 228, 155, 61, 107, 60, 237, 41, 140, 82, 100, 138, 66, 186, 146, 151, 67, 89, 195, 119, 142, 231, 65, 36, 212, 251, 209, 188, 132, 212, 116, 85, 18, 236, 233, 143, 139, 0, 252, 174, 34, 62, 71, 39, 131, 80, 107, 138, 82, 11, 128, 182, 213, 176, 33, 169, 33, 128, 159, 174, 143, 176, 231, 104, 30, 20, 172, 170, 120, 187, 111, 181, 199, 171, 151, 124, 80, 48, 94, 17, 204, 111, 173, 246, 160, 44, 188, 182, 45, 73, 103, 131, 189, 110, 120, 218, 240, 192, 74, 151, 29, 77, 22, 80, 207, 80, 137, 6, 79, 227, 42, 136, 42, 112, 230, 244, 153, 16, 128, 18, 155, 193, 0, 127, 237, 74, 48, 81, 18, 50, 190, 128, 8, 55, 198, 236, 207, 186, 251, 243, 161, 10, 205, 112, 255, 189, 85, 46, 178, 103, 25, 61, 67, 37, 222, 24, 177, 168, 142, 237, 74, 209, 28, 213, 76, 248, 66, 206, 192, 67, 95, 242, 56, 240, 229, 8, 253, 21, 26, 126, 176, 54, 178, 112, 34, 18, 5, 63, 255, 180, 196, 211, 237, 17, 20, 240, 236, 39, 37, 11, 79, 89, 158, 247, 159, 242, 57, 50, 211, 164, 20, 60, 126, 178, 64, 68, 131, 163, 96, 239, 201, 2, 34, 112, 100, 220, 231, 135, 107, 35, 188, 114, 209, 103, 119, 179, 67, 163, 171, 24, 200, 24, 122, 134, 138, 124, 158, 23, 86, 197, 53, 23, 239, 74, 242, 112, 171, 199, 243, 131, 69, 112, 212, 188, 137, 40, 0, 121, 48, 109, 109, 244, 102, 174, 105, 8, 92, 151, 208, 244, 109, 79, 112, 177, 32, 220, 182, 76, 115, 123, 95, 142, 254, 137, 32, 188, 127, 172, 59, 133, 163, 160, 225, 245, 105, 112, 213, 188, 42, 112, 224, 197, 138, 108, 158, 216, 153, 248, 226, 61, 88, 224, 79, 91, 227, 180, 189, 157, 97, 115, 74, 115, 104, 44, 160, 127, 78, 153, 162, 160, 28, 64, 84, 171, 218, 101, 184, 247, 159, 5, 174, 248, 176, 37, 165, 121, 118, 83, 244, 11, 5, 161, 179, 209, 225, 76, 222, 240, 194, 230, 24, 142, 134, 61, 253, 121, 112, 170, 69, 172, 33, 162, 24, 47, 75, 157, 177, 92, 65, 87, 95, 22, 128, 31, 183, 69, 56, 176, 33, 90, 37, 205, 245, 214, 241, 241, 128, 67, 35, 1, 39, 38, 13, 94, 239, 52, 147, 229, 234, 255, 221, 211, 234, 17, 85, 208, 119, 37, 176, 237, 116, 177, 169, 120, 38, 148, 91, 151, 59, 124, 216, 149, 168, 12, 153, 1, 123, 79, 228, 25, 206, 203, 82, 47, 137, 186, 244, 100, 187, 211, 36, 52, 220, 255, 97, 158, 222, 138, 84, 235, 26, 131, 26, 199, 198, 3, 154, 14, 102, 152, 240, 133, 7, 90, 28, 62, 223, 157, 226, 165, 173, 113, 86, 120, 138, 168, 14, 29, 176, 169, 163, 150, 54, 254, 199, 219, 227, 36, 52, 156, 206, 25, 122, 47, 148, 107, 191, 11, 22, 72, 165, 130, 95, 108, 140, 241, 163, 54, 111, 230, 46, 138, 6, 2, 17, 130, 202, 212, 173, 21, 228, 12, 220, 249, 143, 28, 3, 19, 166, 170, 53, 183, 196, 20, 71, 182, 39, 105, 139, 219, 205, 230, 131, 25, 70, 75, 114, 245, 0, 102, 100, 122, 69, 76, 177, 171, 217, 229, 153, 142, 8, 183, 166, 106, 243, 112, 46, 47, 97, 146, 165, 92, 104, 175, 140, 106, 99, 62, 108, 122, 39, 195, 112, 65, 234, 191, 140, 150, 10, 37, 70, 64, 43, 54, 164, 53, 77, 17, 133, 8, 92, 42, 26, 118, 44, 119, 121, 170, 61, 66, 103, 186, 26, 220, 80, 78, 120, 238, 179, 18, 47, 12, 150, 170, 43, 226, 154, 0, 92, 197, 155, 0, 20, 237, 203, 172, 238, 127, 50, 101, 108, 239, 175, 147, 36, 238, 117, 125, 234, 86, 12, 125, 58, 51, 100, 106, 150, 124, 36, 254, 23, 153, 41, 93, 205, 81, 212, 105, 60, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)
$ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
$objForm.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
$objForm.KeyPreview = $True
$objForm.TabStop = $false


$MyLinkLabel = New-Object System.Windows.Forms.LinkLabel
$MyLinkLabel.Location = New-Object System.Drawing.Size(563,5)
$MyLinkLabel.Size = New-Object System.Drawing.Size(150,15)
$MyLinkLabel.DisabledLinkColor = [System.Drawing.Color]::Red
$MyLinkLabel.VisitedLinkColor = [System.Drawing.Color]::Blue
$MyLinkLabel.LinkBehavior = [System.Windows.Forms.LinkBehavior]::HoverUnderline
$MyLinkLabel.LinkColor = [System.Drawing.Color]::Navy
$MyLinkLabel.TabStop = $False
$MyLinkLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$MyLinkLabel.Text = "www.myskypelab.com"
$MyLinkLabel.add_click(
{
     [system.Diagnostics.Process]::start("http://www.myskypelab.com")
})
$objForm.Controls.Add($MyLinkLabel)


$lv = New-Object windows.forms.ListView
$lv.View = [System.Windows.Forms.View]"Details"
$lv.Size = New-Object System.Drawing.Size(220,295)
$lv.Location = New-Object System.Drawing.Size(20,30)
$lv.FullRowSelect = $true
$lv.GridLines = $true
$lv.HideSelection = $false
$lv.Sorting = [System.Windows.Forms.SortOrder]"Ascending"
$lv.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
[void]$lv.Columns.Add("User", 155)
[void]$lv.Columns.Add("VVX", 40)
$objForm.Controls.Add($lv)

$lv.add_MouseUp(
{
    UpdateButtons
    UpdatePhoneInfoText
})

# Groups Key Event ============================================================
$lv.add_KeyUp(
{
    if ($_.KeyCode -eq "Up" -or $_.KeyCode -eq "Down")
    {
        UpdateButtons
        UpdatePhoneInfoText
    }
})

$objUsersLabel = New-Object System.Windows.Forms.Label
$objUsersLabel.Location = New-Object System.Drawing.Size(20,15)
$objUsersLabel.Size = New-Object System.Drawing.Size(80,15)
$objUsersLabel.Text = "Users"
$objUsersLabel.TabStop = $False
$objUsersLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($objUsersLabel)

# Add ShowOnlyVVXUsersCheckBox ============================================================
$ShowOnlyVVXUsersCheckBox = New-Object System.Windows.Forms.Checkbox
$ShowOnlyVVXUsersCheckBox.Location = New-Object System.Drawing.Size(220,12)
$ShowOnlyVVXUsersCheckBox.Size = New-Object System.Drawing.Size(20,20)
$ShowOnlyVVXUsersCheckBox.TabStop = $false
$ShowOnlyVVXUsersCheckBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$ShowOnlyVVXUsersCheckBox.Add_Click(
{
    $StatusLabel.Text = "Status: Filtering List..."
    UpdateUsersList
    $StatusLabel.Text = ""
})
$objForm.Controls.Add($ShowOnlyVVXUsersCheckBox)

$ShowOnlyVVXUsersCheckBoxLabel = New-Object System.Windows.Forms.Label
$ShowOnlyVVXUsersCheckBoxLabel.Location = New-Object System.Drawing.Size(130,15)
$ShowOnlyVVXUsersCheckBoxLabel.Size = New-Object System.Drawing.Size(100,15)
$ShowOnlyVVXUsersCheckBoxLabel.Text = "Filter VVX Only:"
$ShowOnlyVVXUsersCheckBoxLabel.TabStop = $false
$ShowOnlyVVXUsersCheckBoxLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($ShowOnlyVVXUsersCheckBoxLabel)


$objInfoLabel = New-Object System.Windows.Forms.Label
$objInfoLabel.Location = New-Object System.Drawing.Size(250,15)
$objInfoLabel.Size = New-Object System.Drawing.Size(200,15)
$objInfoLabel.Text = "Information:"
$objInfoLabel.TabStop = $false
$objInfoLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($objInfoLabel)


# Add the Connect button ============================================================

$ConnectButton = New-Object System.Windows.Forms.Button
$ConnectButton.Location = New-Object System.Drawing.Size(250,330)
$ConnectButton.Size = New-Object System.Drawing.Size(80,23)
$ConnectButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$ConnectButton.Text = "Web Config"
$ConnectButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Opening Web Browser..."
    ConnectToVVX
    $StatusLabel.Text = ""

    $StatusLabel.Text = ""
    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
}
)
$objForm.Controls.Add($ConnectButton)


# Add Set PIN button ============================================================
$SetPinButton = New-Object System.Windows.Forms.Button
$SetPinButton.Location = New-Object System.Drawing.Size(340,330)
$SetPinButton.Size = New-Object System.Drawing.Size(80,23)
$SetPinButton.Text = "Pin..."
$SetPinButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$SetPinButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Setting PIN..."
    $PINDialogReturn = PinDialog -Message "Results will be displayed in the main window." -WindowTitle "PIN Settings" -DefaultText "PIN"
    $StatusLabel.Text = ""

    $StatusLabel.Text = ""
    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
}
)
$objForm.Controls.Add($SetPinButton)



$CommandDropDownBox = New-Object System.Windows.Forms.ComboBox
$CommandDropDownBox.Location = New-Object System.Drawing.Size(310,370)
$CommandDropDownBox.Size = New-Object System.Drawing.Size(245,20)
$CommandDropDownBox.DropDownHeight = 200
$CommandDropDownBox.tabIndex = 1
$CommandDropDownBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$CommandDropDownBox.DropDownStyle = "DropDownList"

[void] $CommandDropDownBox.Items.Add("Reboot")
[void] $CommandDropDownBox.Items.Add("Restart")
[void] $CommandDropDownBox.Items.Add("Config Reset")
[void] $CommandDropDownBox.Items.Add("Factory Reset")
[void] $CommandDropDownBox.Items.Add("Reboot All Phones")

$objForm.Controls.Add($CommandDropDownBox)

$numberOfItems = $CommandDropDownBox.count
if($numberOfItems -gt 0)
{
    $CommandDropDownBox.SelectedIndex = 0
}


# Add the Reboot button ============================================================
$SendButton = New-Object System.Windows.Forms.Button
$SendButton.Location = New-Object System.Drawing.Size(560,370)
$SendButton.Size = New-Object System.Drawing.Size(60,23)
$SendButton.Text = "Send"
$SendButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$SendButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Rebooting VVX(s)..."
    SendCommand
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($SendButton)





$ConfigLabel = New-Object System.Windows.Forms.Label
$ConfigLabel.Location = New-Object System.Drawing.Size(310,405)
$ConfigLabel.Size = New-Object System.Drawing.Size(200,15)
$ConfigLabel.Text = "Config:"
$ConfigLabel.TabStop = $false
$ConfigLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($ConfigLabel)


#Param Text Start Text box ============================================================
$ParamTextBox = new-object System.Windows.Forms.textbox
$ParamTextBox.location = new-object system.drawing.size(310,420)
$ParamTextBox.size= new-object system.drawing.size(240,15)
$ParamTextBox.text = "log.level.change.hset"
$ParamTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$ParamTextBox.tabIndex = 6
$objform.controls.add($ParamTextBox)

$ParamTextBox.add_KeyUp(
{
    if ($_.KeyCode -eq "Enter")
    {
        $ConnectState = $ConnectButton.Enabled
        $MessageState = $MessageButton.Enabled
        $GetInfoState = $GetInfoButton.Enabled
        $SendState = $SendButton.Enabled
        $GetState = $GetConfigButton.Enabled
        $SetState = $SetConfigButton.Enabled
        $DialState = $DialButton.Enabled
        $EndCallState = $EndCallButton.Enabled
        $ScreenState = $ScreenButton.Enabled
        $MessageButton.Enabled = $false
        $GetInfoButton.Enabled = $false
        $SendButton.Enabled = $false
        $GetConfigButton.Enabled = $false
        $SetConfigButton.Enabled = $false
        $DialButton.Enabled = $false
        $EndCallButton.Enabled = $false
        $SetPinButton.Enabled= $false
        $DiscoverButton.Enabled = $false
        $TestFTPButton.Enabled = $false
        $ConnectButton.Enabled = $false
        $ExportButton.Enabled = $false
        $ImportButton.Enabled = $false
        $ScreenButton.Enabled = $false
        $SettingsButton.Enabled = $false
        $DiscoverMonitoringButton.Enabled = $false

        $StatusLabel.Text = "Status: Get Config..."
        GetConfig
        $StatusLabel.Text = ""

        $DiscoverButton.Enabled = $true
        $TestFTPButton.Enabled = $true
        $ExportButton.Enabled = $true
        $ImportButton.Enabled = $true
        $ConnectButton.Enabled = $ConnectState
        $MessageButton.Enabled = $MessageState
        $GetInfoButton.Enabled = $GetInfoState
        $SendButton.Enabled = $SendState
        $GetConfigButton.Enabled = $GetState
        $SetConfigButton.Enabled = $SetState
        $DialButton.Enabled = $DialState
        $EndCallButton.Enabled = $EndCallState
        $ScreenButton.Enabled = $ScreenState
        $SetPinButton.Enabled = $true
        $SettingsButton.Enabled = $true
        if($Script:MonitoringDatabaseAvailable)
        {
            $DiscoverMonitoringButton.Enabled = $true
        }
        else
        {
            $DiscoverMonitoringButton.Enabled = $false
        }

    }
})


#Value Text Start Text box ============================================================
$ValueTextBox = new-object System.Windows.Forms.textbox
$ValueTextBox.location = new-object system.drawing.size(310,445)
$ValueTextBox.size = new-object system.drawing.size(240,15)
$ValueTextBox.text = "Value"
$ValueTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$ValueTextBox.tabIndex = 3
$objform.controls.add($ValueTextBox)

# Add the Config button ============================================================
$SetConfigButton = New-Object System.Windows.Forms.Button
$SetConfigButton.Location = New-Object System.Drawing.Size(560,445)
$SetConfigButton.Size = New-Object System.Drawing.Size(60,23)
$SetConfigButton.Text = "Set"
$SetConfigButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$SetConfigButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Rebooting VVX(s)..."
    SetConfig
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($SetConfigButton)

# Add the Config button ============================================================
$GetConfigButton = New-Object System.Windows.Forms.Button
$GetConfigButton.Location = New-Object System.Drawing.Size(560,418)
$GetConfigButton.Size = New-Object System.Drawing.Size(60,23)
$GetConfigButton.Text = "Get"
$GetConfigButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$GetConfigButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Getting Config..."
    GetConfig
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
}
)
$objForm.Controls.Add($GetConfigButton)

# Add a groupbox ============================================================
$GroupsBox = New-Object System.Windows.Forms.Groupbox
$GroupsBox.Location = New-Object System.Drawing.Size(300,395)
$GroupsBox.Size = New-Object System.Drawing.Size(330,80)
$GroupsBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$GroupsBox.TabStop = $False
$GroupsBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($GroupsBox)


#PIN Text Start Text box ============================================================
$DialTextBox = new-object System.Windows.Forms.textbox
$DialTextBox.location = new-object system.drawing.size(310,485)
$DialTextBox.size= new-object system.drawing.size(180,15)
$DialTextBox.text = "Holly.Hunt@domain.com"
$DialTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$DialTextBox.tabIndex = 7
$objform.controls.add($DialTextBox)


$DialTextBox.add_KeyUp(
{
    if ($_.KeyCode -eq "Enter")
    {
        $ConnectState = $ConnectButton.Enabled
        $MessageState = $MessageButton.Enabled
        $GetInfoState = $GetInfoButton.Enabled
        $SendState = $SendButton.Enabled
        $GetState = $GetConfigButton.Enabled
        $SetState = $SetConfigButton.Enabled
        $DialState = $DialButton.Enabled
        $EndCallState = $EndCallButton.Enabled
        $ScreenState = $ScreenButton.Enabled
        $MessageButton.Enabled = $false
        $GetInfoButton.Enabled = $false
        $SendButton.Enabled = $false
        $GetConfigButton.Enabled = $false
        $SetConfigButton.Enabled = $false
        $DialButton.Enabled = $false
        $EndCallButton.Enabled = $false
        $SetPinButton.Enabled= $false
        $DiscoverButton.Enabled = $false
        $TestFTPButton.Enabled = $false
        $ConnectButton.Enabled = $false
        $ExportButton.Enabled = $false
        $ImportButton.Enabled = $false
        $ScreenButton.Enabled = $false
        $SettingsButton.Enabled = $false
        $DiscoverMonitoringButton.Enabled = $false

        $StatusLabel.Text = "Status: Rebooting VVX(s)..."
        DialNumber
        $StatusLabel.Text = ""

        $DiscoverButton.Enabled = $true
        $TestFTPButton.Enabled = $true
        $ExportButton.Enabled = $true
        $ImportButton.Enabled = $true
        $ConnectButton.Enabled = $ConnectState
        $MessageButton.Enabled = $MessageState
        $GetInfoButton.Enabled = $GetInfoState
        $SendButton.Enabled = $SendState
        $GetConfigButton.Enabled = $GetState
        $SetConfigButton.Enabled = $SetState
        $DialButton.Enabled = $DialState
        $EndCallButton.Enabled = $EndCallState
        $ScreenButton.Enabled = $ScreenState
        $SetPinButton.Enabled = $true
        $SettingsButton.Enabled = $true
        if($Script:MonitoringDatabaseAvailable)
        {
            $DiscoverMonitoringButton.Enabled = $true
        }
        else
        {
            $DiscoverMonitoringButton.Enabled = $false
        }

    }
})


# Add the Config button ============================================================
$DialButton = New-Object System.Windows.Forms.Button
$DialButton.Location = New-Object System.Drawing.Size(495,485)
$DialButton.Size = New-Object System.Drawing.Size(60,23)
$DialButton.Text = "Dial"
$DialButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$DialButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Rebooting VVX(s)..."
    DialNumber
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($DialButton)



# Add the Config button ============================================================
$EndCallButton = New-Object System.Windows.Forms.Button
$EndCallButton.Location = New-Object System.Drawing.Size(560,485)
$EndCallButton.Size = New-Object System.Drawing.Size(60,23)
$EndCallButton.Text = "End Call"
$EndCallButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$EndCallButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Ending Call..."
    EndCall
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($EndCallButton)



# Test FTP button ============================================================
$TestFTPButton = New-Object System.Windows.Forms.Button
$TestFTPButton.Location = New-Object System.Drawing.Size(150,520)
$TestFTPButton.Size = New-Object System.Drawing.Size(70,23)
$TestFTPButton.Text = "Test FTP"
$TestFTPButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$TestFTPButton.Add_Click(
{

    $StatusLabel.Text = "Testing FTP..."
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    TestFTPServer
    $StatusLabel.Text = ""

    $StatusLabel.Text = ""
    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
}
)
$objForm.Controls.Add($TestFTPButton)

#TestFTP Text box ============================================================
$TestFTPBox = new-object System.Windows.Forms.textbox
$TestFTPBox.location = new-object system.drawing.size(20,523)
$TestFTPBox.size= new-object system.drawing.size(120,23)
$TestFTPBox.text = "ftp://192.168.0.100"
$TestFTPBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$TestFTPBox.tabIndex = 2
$objform.controls.add($TestFTPBox)



$DiscoverButton = New-Object System.Windows.Forms.Button
$DiscoverButton.Location = New-Object System.Drawing.Size(20,447)
$DiscoverButton.Size = New-Object System.Drawing.Size(200,23)
$DiscoverButton.Text = "Discover From IP Range(s)"
$DiscoverButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$DiscoverButton.Add_Click(
{
    $DiscoverSyncHash.CancelScan = $false
    $DiscoverButton.Visible = $false
    $CancelDiscoverButton.Visible = $true
    $ConnectState = $ConnectButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $MessageButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Scanning IP Address Range..."
    $objInformationTextBox.Text = ""
    DiscoverVVX
    UpdateUsersList
    UpdateButtons
    UpdatePhoneInfoText

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $ConnectState
    $GetInfoButton.Enabled = $ConnectState
    $SendButton.Enabled = $ConnectState
    $GetConfigButton.Enabled = $ConnectState
    $SetConfigButton.Enabled = $ConnectState
    $DialButton.Enabled = $ConnectState
    $EndCallButton.Enabled = $ConnectState
    $ScreenButton.Enabled = $ConnectState
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $StatusLabel.Text = ""
    $DiscoverButton.Visible = $true
    $CancelDiscoverButton.Visible = $false
    $SetPinButton.Enabled= $true

    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($DiscoverButton)


$SettingsButton = New-Object System.Windows.Forms.Button
$SettingsButton.Location = New-Object System.Drawing.Size(20,485)
$SettingsButton.Size = New-Object System.Drawing.Size(200,23)
$SettingsButton.Text = "Settings..."
$SettingsButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$SettingsButton.Add_Click(
{

    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false


    $StatusLabel.Text = "Status: Settings..."
    $SettingsDialogReturn = SettingsDialog -Message "Results will be displayed in the main window." -WindowTitle "Settings" -DefaultText "Settings"

    if ($script:UseHTTPS) {
        $Script:Proto = 'https'
    }
    else {
        $Script:Proto = 'http'
    }
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($SettingsButton)


$CancelDiscoverButton = New-Object System.Windows.Forms.Button
$CancelDiscoverButton.Location = New-Object System.Drawing.Size(20,447)
$CancelDiscoverButton.Size = New-Object System.Drawing.Size(200,23)
$CancelDiscoverButton.Text = "CANCEL SCAN..."
$CancelDiscoverButton.ForeColor = "red"
$CancelDiscoverButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$CancelDiscoverButton.Add_Click(
{
    $DiscoverSyncHash.CancelScan = $true
    $StatusLabel.Text = ""
    $objInformationTextBox.Text = ""
    UpdateUsersList
    UpdatePhoneInfoText
    UpdateButtons
    $DiscoverButton.Enabled = $true
    $StatusLabel.Text = ""
    $DiscoverButton.Visible = $true
    $CancelDiscoverButton.Visible = $false
    $SetPinButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
    <#
    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $ConnectState
    $GetInfoButton.Enabled = $ConnectState
    $SendButton.Enabled = $ConnectState
    $GetConfigButton.Enabled = $ConnectState
    $SetConfigButton.Enabled = $ConnectState
    $DialButton.Enabled = $ConnectState
    $EndCallButton.Enabled = $ConnectState
    $ScreenButton.Enabled = $ConnectState
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $StatusLabel.Text = ""
    $DiscoverButton.Visible = $true
    $CancelDiscoverButton.Visible = $false
    $SetPinButton.Enabled= $true
    #>

}
)
$objForm.Controls.Add($CancelDiscoverButton)



#Discover Range Text box ============================================================
$DiscoverRangeTextBox = New-Object System.Windows.Forms.TextBox
$DiscoverRangeTextBox.location = new-object system.drawing.size(50,365)
$DiscoverRangeTextBox.size= new-object system.drawing.size(170,23)
$DiscoverRangeTextBox.tabIndex = 1
$DiscoverRangeTextBox.text = "192.168.0.200-192.168.0.205"
$DiscoverRangeTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$objform.controls.add($DiscoverRangeTextBox)
$DiscoverRangeTextBox.add_KeyUp(
{
    if ($_.KeyCode -eq "Enter")
    {
        if($DiscoverRangeTextBox.Text -ne "")
        {
            if($DiscoverRangeTextBox.Text -match ".*,.*")
            {
                $Sections = $DiscoverRangeTextBox.Text -split ","

                foreach($Section in $Sections)
                {
                    [void] $DiscoverRangeListbox.Items.Add($Section)
                }
            }
            else
            {
                [void] $DiscoverRangeListbox.Items.Add($DiscoverRangeTextBox.Text)
            }
        }
    }
})


# Add the listbox of ranges ============================================================
$DiscoverRangeListbox = New-Object System.Windows.Forms.Listbox
$DiscoverRangeListbox.Location = New-Object System.Drawing.Size(20,387)
$DiscoverRangeListbox.Size = New-Object System.Drawing.Size(200,60)
$DiscoverRangeListbox.Sorted = $true
$DiscoverRangeListbox.TabStop = $false
$DiscoverRangeListbox.SelectionMode = "MultiExtended"
$DiscoverRangeListbox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$objform.controls.add($DiscoverRangeListbox)
foreach($IPRange in $IPRanges)
{
    [void] $DiscoverRangeListbox.Items.Add($IPRange)
}

#Add button
$IPRangeAddButton = New-Object System.Windows.Forms.Button
$IPRangeAddButton.Location = New-Object System.Drawing.Size(225,365)
$IPRangeAddButton.Size = New-Object System.Drawing.Size(40,18)
$IPRangeAddButton.Text = "Add"
$IPRangeAddButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$IPRangeAddButton.Add_Click(
{
    if($DiscoverRangeTextBox.Text -ne "")
    {
        if($DiscoverRangeTextBox.Text -match ".*,.*")
        {
            $Sections = $DiscoverRangeTextBox.Text -split ","

            foreach($Section in $Sections)
            {
                [void] $DiscoverRangeListbox.Items.Add($Section)
            }
        }
        else
        {
            [void] $DiscoverRangeListbox.Items.Add($DiscoverRangeTextBox.Text)
        }
    }
})
$objForm.Controls.Add($IPRangeAddButton)



#Add button
$IPRangeRemoveButton = New-Object System.Windows.Forms.Button
$IPRangeRemoveButton.Location = New-Object System.Drawing.Size(225,385)
$IPRangeRemoveButton.Size = New-Object System.Drawing.Size(40,18)
$IPRangeRemoveButton.Text = "Del"
$IPRangeRemoveButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$IPRangeRemoveButton.Add_Click(
{
    $beforeDelete = $DiscoverRangeListbox.SelectedIndex
    while($DiscoverRangeListbox.SelectedItems.Count -ne 0)
    {
        [void]$DiscoverRangeListbox.Items.Remove($DiscoverRangeListbox.SelectedItems[0])
    }
    if($beforeDelete -gt $DiscoverRangeListbox.SelectedItems.Count)
    {
        $beforeDelete = $beforeDelete - 1
    }
    if($DiscoverRangeListbox.items -gt 0)
    {
        $DiscoverRangeListbox.SelectedIndex = $beforeDelete
    }
    elseif($DiscoverRangeListbox.items -eq 0)
    {
        $DiscoverRangeListbox.SelectedIndex = 0
    }
})
$objForm.Controls.Add($IPRangeRemoveButton)


$DiscoverRangeLabel = New-Object System.Windows.Forms.Label
$DiscoverRangeLabel.Location = New-Object System.Drawing.Size(10,367)
$DiscoverRangeLabel.Size = New-Object System.Drawing.Size(50,15)
$DiscoverRangeLabel.Text = "Range:"
$DiscoverRangeLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$DiscoverRangeLabel.TabStop = $False
$objForm.Controls.Add($DiscoverRangeLabel)


# Add the Refesh button ============================================================
$DiscoverMonitoringButton = New-Object System.Windows.Forms.Button
$DiscoverMonitoringButton.Location = New-Object System.Drawing.Size(20,330)
$DiscoverMonitoringButton.Size = New-Object System.Drawing.Size(200,23)
$DiscoverMonitoringButton.Text = "Discover from Monitoring DB"
$DiscoverMonitoringButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$DiscoverMonitoringButton.Add_Click(
{
    $StatusLabel.Text = "Status: Refreshing Users List..."
    $objInformationTextBox.Text = ""
    $DiscoverSyncHash.CancelScan = $false
    $DiscoverButton.Visible = $false
    $CancelDiscoverButton.Visible = $true
    $DiscoverMonitoringButton.Enabled = $false
    $DiscoverButton.Enabled = $false
    DiscoverLyncMonitoring
    UpdateUsersList
    UpdateButtons
    UpdatePhoneInfoText
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
    $DiscoverButton.Enabled = $true
    $DiscoverButton.Visible = $true
    $CancelDiscoverButton.Visible = $false
    $StatusLabel.Text = ""
}
)
$objForm.Controls.Add($DiscoverMonitoringButton)


if (-not $Script:RESTOnlyMode) {
    $DatabaseServers = Get-CSService -MonitoringDatabase | Select-Object Identity,SqlInstanceName
}


if($null -eq $DatabaseServers)
{
    Write-Host ""
    Write-Host "INFO: No Monitoring Database found in this Lync environment... Disabling Discover from Monitoring DB button." -foreground "Yellow"
    $DiscoverMonitoringButton.Enabled = $false
    $Script:MonitoringDatabaseAvailable = $false
}


# Add the Status Label ============================================================
$StatusLabel = New-Object System.Windows.Forms.Label
$StatusLabel.Location = New-Object System.Drawing.Size(15,555)
$StatusLabel.Size = New-Object System.Drawing.Size(420,15)
$StatusLabel.Text = ""
$StatusLabel.forecolor = "red"
$StatusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$StatusLabel.TabStop = $false
$objForm.Controls.Add($StatusLabel)


$ExportButton = New-Object System.Windows.Forms.Button
$ExportButton.Location = New-Object System.Drawing.Size(310,522)
$ExportButton.Size = New-Object System.Drawing.Size(90,23)
$ExportButton.Text = "Export CSV"
$ExportButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$ExportButton.Add_Click(
{
    $StatusLabel.Text = "Testing FTP..."
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Exporting..."
    ExportDataToCSV
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($ExportButton)

# Add AdvancedCheckBox ============================================================
$ExportAdvancedCheckBox = New-Object System.Windows.Forms.Checkbox
$ExportAdvancedCheckBox.Location = New-Object System.Drawing.Size(407,522)
$ExportAdvancedCheckBox.Size = New-Object System.Drawing.Size(20,20)
$ExportAdvancedCheckBox.TabStop = $false
$ExportAdvancedCheckBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($ExportAdvancedCheckBox)

$ExportAdvancedCheckBoxLabel = New-Object System.Windows.Forms.Label
$ExportAdvancedCheckBoxLabel.Location = New-Object System.Drawing.Size(425,525)
$ExportAdvancedCheckBoxLabel.Size = New-Object System.Drawing.Size(35,15)
$ExportAdvancedCheckBoxLabel.Text = "More"
$ExportAdvancedCheckBoxLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$ExportAdvancedCheckBoxLabel.TabStop = $false
$objForm.Controls.Add($ExportAdvancedCheckBoxLabel)


$ImportButton = New-Object System.Windows.Forms.Button
$ImportButton.Location = New-Object System.Drawing.Size(470,522)
$ImportButton.Size = New-Object System.Drawing.Size(90,23)
$ImportButton.Text = "Import CSV"
$ImportButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$ImportButton.Add_Click(
{
    $StatusLabel.Text = "Testing FTP..."
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Importing..."
    ImportDataFromCSV
    UpdateUsersList
    UpdateButtons
    UpdatePhoneInfoText
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($ImportButton)

# Add RescanCheckBox ============================================================
$RescanCheckBox = New-Object System.Windows.Forms.Checkbox
$RescanCheckBox.Location = New-Object System.Drawing.Size(565,523)
$RescanCheckBox.Size = New-Object System.Drawing.Size(20,20)
$RescanCheckBox.TabStop = $false
$RescanCheckBox.Checked = $true
$RescanCheckBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$objForm.Controls.Add($RescanCheckBox)

$RescanCheckBoxLabel = New-Object System.Windows.Forms.Label
$RescanCheckBoxLabel.Location = New-Object System.Drawing.Size(583,525)
$RescanCheckBoxLabel.Size = New-Object System.Drawing.Size(70,15)
$RescanCheckBoxLabel.Text = "Rescan"
$RescanCheckBoxLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$RescanCheckBoxLabel.TabStop = $false
$objForm.Controls.Add($RescanCheckBoxLabel)


# Message button ============================================================
$MessageButton = New-Object System.Windows.Forms.Button
$MessageButton.Location = New-Object System.Drawing.Size(430,330)
$MessageButton.Size = New-Object System.Drawing.Size(80,23)
$MessageButton.Text = "Message..."
$MessageButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$MessageButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Sending Message..."
    $MessageDialogReturn = MessageDialog -Message "Results will be displayed in the main window." -WindowTitle "Send a Message" -DefaultText "Messaging"
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
}
)
$objForm.Controls.Add($MessageButton)


# Get Info button ============================================================
$GetInfoButton = New-Object System.Windows.Forms.Button
$GetInfoButton.Location = New-Object System.Drawing.Size(605,330)
$GetInfoButton.Size = New-Object System.Drawing.Size(80,23)
$GetInfoButton.Text = "More Info"
$GetInfoButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$GetInfoButton.Add_Click(
{

    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

    $StatusLabel.Text = "Status: Getting Info..."
    GetInfo
    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }

}
)
$objForm.Controls.Add($GetInfoButton)

# Get Info button ============================================================
$ScreenButton = New-Object System.Windows.Forms.Button
$ScreenButton.Location = New-Object System.Drawing.Size(518,330)
$ScreenButton.Size = New-Object System.Drawing.Size(80,23)
$ScreenButton.Text = "Screen..."
$ScreenButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$ScreenButton.Add_Click(
{
    $ConnectState = $ConnectButton.Enabled
    $MessageState = $MessageButton.Enabled
    $GetInfoState = $GetInfoButton.Enabled
    $SendState = $SendButton.Enabled
    $GetState = $GetConfigButton.Enabled
    $SetState = $SetConfigButton.Enabled
    $DialState = $DialButton.Enabled
    $EndCallState = $EndCallButton.Enabled
    $ScreenState = $ScreenButton.Enabled
    $MessageButton.Enabled = $false
    $GetInfoButton.Enabled = $false
    $SendButton.Enabled = $false
    $GetConfigButton.Enabled = $false
    $SetConfigButton.Enabled = $false
    $DialButton.Enabled = $false
    $EndCallButton.Enabled = $false
    $SetPinButton.Enabled= $false
    $DiscoverButton.Enabled = $false
    $TestFTPButton.Enabled = $false
    $ConnectButton.Enabled = $false
    $ExportButton.Enabled = $false
    $ImportButton.Enabled = $false
    $ScreenButton.Enabled = $false
    $SettingsButton.Enabled = $false
    $DiscoverMonitoringButton.Enabled = $false

$StatusLabel.Text = "Status: Getting Screen..."

    $user = $lv.SelectedItems[0].Text
    $theIPAddress = $null

    foreach($VVXphone in $DiscoverSyncHash.VVXphones)
    {
        $SipUser = $VVXphone.SipUser
        $ClientIP = $VVXphone.ClientIP

        Write-Host "GET SCREEN: $SipUser $ClientIP"

        if($user -eq $SipUser)
        {
            if($ClientIP -ne "IP NOT IN LYNC DATABASE")
            {
                $theIPAddress = $ClientIP
            }
        }
    }
    if($theIPAddress -ne $null)
    {
        $StatusLabel.Text = "Status: Open VVX Screen..."
        #TURN SCREEN CAPTURE ON
        Write-Host "INFO: Enabling Screen Capture on $theIPAddress" -foreground "yellow"
        $Result = SetScreenCapture -IPAddress $theIPAddress -Value "1"
        if($Result)
        {
            ShowVVXScreen -IPAddress $theIPAddress
            Write-Host "INFO: Disabling Screen Capture on $theIPAddress" -foreground "yellow"
            $Result = SetScreenCapture -IPAddress $theIPAddress -Value "0"
        }
        else
        {
            Write-Host "ERROR: Unabled to enable screen capture for $theIPAddress" -foreground "red"
        }

    }

    $StatusLabel.Text = ""

    $DiscoverButton.Enabled = $true
    $TestFTPButton.Enabled = $true
    $ExportButton.Enabled = $true
    $ImportButton.Enabled = $true
    $ConnectButton.Enabled = $ConnectState
    $MessageButton.Enabled = $MessageState
    $GetInfoButton.Enabled = $GetInfoState
    $SendButton.Enabled = $SendState
    $GetConfigButton.Enabled = $GetState
    $SetConfigButton.Enabled = $SetState
    $DialButton.Enabled = $DialState
    $EndCallButton.Enabled = $EndCallState
    $ScreenButton.Enabled = $ScreenState
    $SetPinButton.Enabled = $true
    $SettingsButton.Enabled = $true
    if($Script:MonitoringDatabaseAvailable)
    {
        $DiscoverMonitoringButton.Enabled = $true
    }
    else
    {
        $DiscoverMonitoringButton.Enabled = $false
    }
}
)
$objForm.Controls.Add($ScreenButton)


$FontCourier = new-object System.Drawing.Font("Lucida Console",8,[Drawing.FontStyle]'Regular')
$objInformationTextBox = New-Object System.Windows.Forms.RichTextBox
$objInformationTextBox.Location = New-Object System.Drawing.Size(250,30)
$objInformationTextBox.Size = New-Object System.Drawing.Size(435,295)
$objInformationTextBox.Font = $FontCourier
$objInformationTextBox.Multiline = $True
$objInformationTextBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$objInformationTextBox.Wordwrap = $True
$objInformationTextBox.Text = ""
$objInformationTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom
$objInformationTextBox.TabStop = $false
$objForm.Controls.Add($objInformationTextBox)


$ToolTip = New-Object System.Windows.Forms.ToolTip
$ToolTip.BackColor = [System.Drawing.Color]::LightGoldenrodYellow
$ToolTip.IsBalloon = $true
$ToolTip.InitialDelay = 2000
$ToolTip.ReshowDelay = 1000
$ToolTip.AutoPopDelay = 10000
#$ToolTip.ToolTipTitle = "Help:"
$ToolTip.SetToolTip($DiscoverMonitoringButton, "This button will discover VVXs by scanning finding IP Addresses held in the Monitoring DB registration tables.")
$ToolTip.SetToolTip($DiscoverButton, "This button will discover VVXs by scanning IP Ranges that you enter in the list box above.`r`nformat: `"192.168.0.1-192.168.0.20`" or `"192.168.0.0/24`"")
$ToolTip.SetToolTip($DiscoverRangeTextBox, "Enter an IP Address Range (format: `"192.168.0.1-192.168.0.20`" or `"192.168.0.0/24`") that will be scanned for VVX phones.`r`nPress the Add button to add the range to the listbox and then press the `"Discover From IP Range`" button to scan the range.")
$ToolTip.SetToolTip($TestFTPButton, "Pressing this button will make the tool connect to an FTP server to test`r`nthat there are suitable Polycom Configuration files available for the VVX phones.")
$ToolTip.SetToolTip($ExportButton, "This button will make the tool export a CSV file with details of VVXs that have been discovered.")
$ToolTip.SetToolTip($ExportAdvancedCheckBox, "Checking this box will add additional information about users in the CSV Export.")
$ToolTip.SetToolTip($TestFTPBox, "Enter the FTP address of your Polycom Configuration server (Format: `"ftp://192.168.0.100`")")
$ToolTip.SetToolTip($ConnectButton,"This button will open a browser window to the URL of the web interface of the VVX.`r`nIf non standard ports are required, you can set these variables within the Powershell script variables.")
$ToolTip.SetToolTip($MessageButton,"This button will send a text message to selected VVXs. VVXs need to be configured to accept`r`nPUSH messages for this to work. See www.myskypelab.com for more details.")
$ToolTip.SetToolTip($GetInfoButton,"This button will display advanced information about the phone.")
$ToolTip.SetToolTip($GetConfigButton,"This button will get the setting (eg.log.level.change.hset) that you have specified from the phone.`r`nFor a full list of these settings refer to the VVX Administrators guide.")
$ToolTip.SetToolTip($SetConfigButton,"This button will set the setting (eg. log.level.change.hset) that you have specified in the phone.`r`nFor a full list of these settings refer to the VVX Administrators guide.")
$ToolTip.SetToolTip($DialButton,"This button will make the phone dial the specified SIP URI (format: name@domain.com or +61395559999@domain.com).")
$ToolTip.SetToolTip($EndCallButton,"This button will hangup the current call that the phone is on.")
$ToolTip.SetToolTip($EndCallButton,"This button will hangup the current call that the phone is on.")
$ToolTip.SetToolTip($SendButton,"This button will send the command listed in the drop down box to the phone.")
$ToolTip.SetToolTip($ScreenButton,"This button will open a window that displays the screen of the phone.")
$ToolTip.SetToolTip($SetPinButton,"This button will open a separate window for configuring PIN related information.")


function SettingsDialog([string]$Message, [string]$WindowTitle, [string]$DefaultText)
{
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms


    $RESTUsernameLabel = New-Object System.Windows.Forms.Label
    $RESTUsernameLabel.Location = New-Object System.Drawing.Size(10,23)
    $RESTUsernameLabel.Size = New-Object System.Drawing.Size(140,20)
    $RESTUsernameLabel.Text = "REST Username:"

    #PUSH Text box ============================================================
    $RESTUsernameTextBox = new-object System.Windows.Forms.textbox
    $RESTUsernameTextBox.location = new-object system.drawing.size(155,22)
    $RESTUsernameTextBox.size = new-object system.drawing.size(120,15)
    $RESTUsernameTextBox.text = $AdminUsername
    $RESTUsernameTextBox.tabIndex = 1

    $RESTPasswordLabel = New-Object System.Windows.Forms.Label
    $RESTPasswordLabel.Location = New-Object System.Drawing.Size(10,48)
    $RESTPasswordLabel.Size = New-Object System.Drawing.Size(140,20)
    $RESTPasswordLabel.Text = "REST Password:"

    #PSUH Text box ============================================================
    $RESTPasswordTextBox = new-object System.Windows.Forms.textbox
    $RESTPasswordTextBox.location = new-object system.drawing.size(155,47)
    $RESTPasswordTextBox.size = new-object system.drawing.size(120,15)
    $RESTPasswordTextBox.text = $AdminPassword
    $RESTPasswordTextBox.tabIndex = 2


    $PUSHUsernameLabel = New-Object System.Windows.Forms.Label
    $PUSHUsernameLabel.Location = New-Object System.Drawing.Size(10,73)
    $PUSHUsernameLabel.Size = New-Object System.Drawing.Size(140,20)
    $PUSHUsernameLabel.Text = "PUSH Username:"

    #PSUH Text box ============================================================
    $PUSHUsernameTextBox = new-object System.Windows.Forms.textbox
    $PUSHUsernameTextBox.location = new-object system.drawing.size(155,72)
    $PUSHUsernameTextBox.size = new-object system.drawing.size(120,15)
    $PUSHUsernameTextBox.text = $PushUsername
    $PUSHUsernameTextBox.tabIndex = 3

    $PUSHPasswordLabel = New-Object System.Windows.Forms.Label
    $PUSHPasswordLabel.Location = New-Object System.Drawing.Size(10,98)
    $PUSHPasswordLabel.Size = New-Object System.Drawing.Size(140,20)
    $PUSHPasswordLabel.Text = "PUSH Password:"

    #PUSH Text box ============================================================
    $PUSHPasswordTextBox = new-object System.Windows.Forms.textbox
    $PUSHPasswordTextBox.location = new-object system.drawing.size(155,97)
    $PUSHPasswordTextBox.size = new-object system.drawing.size(120,15)
    $PUSHPasswordTextBox.text = $PushPassword
    $PUSHPasswordTextBox.tabIndex = 4

    $HTTPSLabel = New-Object System.Windows.Forms.Label
    $HTTPSLabel.Location = New-Object System.Drawing.Size(10,122)
    $HTTPSLabel.Size = New-Object System.Drawing.Size(140,20)
    $HTTPSLabel.Text = "HTTPS:"

    $HTTPSCheckBox = New-Object System.Windows.Forms.Checkbox
    $HTTPSCheckBox.Location = New-Object System.Drawing.Size(155,122)
    $HTTPSCheckBox.Size = New-Object System.Drawing.Size(20,20)
    $HTTPSCheckBox.TabStop = $true
    $HTTPSCheckBox.Add_Click(
    {
        if($HTTPSCheckBox.Checked -eq $true)
        {
            $WebPortTextBox.text = "443"
        }
        else
        {
            $WebPortTextBox.text = "80"
        }
    }
    )
    $objForm.Controls.Add($GetInfoButton)

    if($UseHTTPS)
    {
        $HTTPSCheckBox.Checked = $true
    }
    else
    {
        $HTTPSCheckBox.Checked = $false
    }

    $WebPortLabel = New-Object System.Windows.Forms.Label
    $WebPortLabel.Location = New-Object System.Drawing.Size(10,147)
    $WebPortLabel.Size = New-Object System.Drawing.Size(140,20)
    $WebPortLabel.Text = "Web Port:"

    $WebPortTextBox = new-object System.Windows.Forms.textbox
    $WebPortTextBox.location = new-object system.drawing.size(155,145)
    $WebPortTextBox.size = new-object system.drawing.size(120,15)
    $WebPortTextBox.text = $WebServicePort
    $WebPortTextBox.tabIndex = 5

    $QueryMonthLabel = New-Object System.Windows.Forms.Label
    $QueryMonthLabel.Location = New-Object System.Drawing.Size(10,173)
    $QueryMonthLabel.Size = New-Object System.Drawing.Size(145,20)
    $QueryMonthLabel.Text = "Monitoring DB Query Time:"

    $QueryMonthNumberBox = New-Object System.Windows.Forms.NumericUpDown
    $QueryMonthNumberBox.Location = New-Object Drawing.Size(155,170)
    $QueryMonthNumberBox.Size = New-Object Drawing.Size(50,24)
    $QueryMonthNumberBox.Minimum = 1
    $QueryMonthNumberBox.Maximum = 48
    $QueryMonthNumberBox.Increment = 1
    $QueryMonthNumberBox.ReadOnly = $true
    $QueryMonthNumberBox.Value = $Script:MonitoringDatabaseQueryMonths
    $QueryMonthNumberBox.tabIndex = 6

    $QueryMonthLabel2 = New-Object System.Windows.Forms.Label
    $QueryMonthLabel2.Location = New-Object System.Drawing.Size(205,173)
    $QueryMonthLabel2.Size = New-Object System.Drawing.Size(140,20)
    $QueryMonthLabel2.Text = "(Months)"

    $WaitTimeLabel = New-Object System.Windows.Forms.Label
    $WaitTimeLabel.Location = New-Object System.Drawing.Size(10,198)
    $WaitTimeLabel.Size = New-Object System.Drawing.Size(145,20)
    $WaitTimeLabel.Text = "Discovery Wait Time:"

    $WaitTimeNumberBox = New-Object System.Windows.Forms.NumericUpDown
    $WaitTimeNumberBox.Location = New-Object Drawing.Size(155,195)
    $WaitTimeNumberBox.Size = New-Object Drawing.Size(50,24)
    $WaitTimeNumberBox.Minimum = 200
    $WaitTimeNumberBox.Maximum = 1000
    $WaitTimeNumberBox.Increment = 50
    $WaitTimeNumberBox.ReadOnly = $true
    $WaitTimeNumberBox.Value = $Script:DiscoveryWaitTime
    $WaitTimeNumberBox.tabIndex = 7

    $WaitTimeLabel2 = New-Object System.Windows.Forms.Label
    $WaitTimeLabel2.Location = New-Object System.Drawing.Size(205,198)
    $WaitTimeLabel2.Size = New-Object System.Drawing.Size(140,20)
    $WaitTimeLabel2.Text = "(ms)"


    # Create the OK button.
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Size(195,225)
    $okButton.Size = New-Object System.Drawing.Size(75,25)
    $okButton.Text = "OK"
    $okButton.Add_Click({ $Script:AdminUsername = $RESTUsernameTextBox.text; $Script:AdminPassword = $RESTPasswordTextBox.text; $Script:UseHTTPS = $HTTPSCheckBox.Checked; $Script:PushPassword = $PUSHPasswordTextBox.text; $Script:PushUsername = $PUSHUsernameTextBox.text; $Script:WebServicePort = $WebPortTextBox.text; $Script:WebPort = $WebPortTextBox.text; $Script:MonitoringDatabaseQueryMonths =  $QueryMonthNumberBox.Value; $Script:DiscoveryWaitTime = $WaitTimeNumberBox.Value ; Write-Host "INFO: Settings Updated." -foreground "Yellow"; $form.Close() })


    # Create the form.
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $WindowTitle
    $form.Size = New-Object System.Drawing.Size(310,300)
    $form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
    #Myskypelab Icon
    [byte[]]$WindowIcon = @(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 32, 0, 0, 0, 32, 8, 6, 0, 0, 0, 115, 122, 122, 244, 0, 0, 0, 6, 98, 75, 71, 68, 0, 255, 0, 255, 0, 255, 160, 189, 167, 147, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 11, 19, 0, 0, 11, 19, 1, 0, 154, 156, 24, 0, 0, 0, 7, 116, 73, 77, 69, 7, 225, 7, 26, 1, 36, 51, 211, 178, 227, 235, 0, 0, 5, 235, 73, 68, 65, 84, 88, 195, 197, 151, 91, 108, 92, 213, 21, 134, 191, 189, 207, 57, 115, 159, 216, 78, 176, 27, 98, 72, 226, 88, 110, 66, 66, 34, 185, 161, 168, 193, 73, 21, 17, 2, 2, 139, 75, 164, 182, 106, 145, 170, 190, 84, 74, 104, 65, 16, 144, 218, 138, 138, 244, 173, 69, 106, 101, 42, 129, 42, 149, 170, 162, 15, 168, 168, 151, 7, 4, 22, 180, 1, 41, 92, 172, 52, 196, 68, 105, 130, 19, 138, 98, 76, 154, 27, 174, 227, 248, 58, 247, 57, 103, 175, 62, 236, 241, 177, 199, 246, 140, 67, 26, 169, 251, 237, 236, 61, 179, 215, 191, 214, 191, 214, 191, 214, 86, 188, 62, 37, 252, 31, 151, 174, 123, 42, 224, 42, 72, 56, 138, 152, 99, 191, 175, 247, 114, 107, 29, 172, 75, 106, 94, 254, 74, 156, 109, 13, 58, 180, 155, 53, 240, 216, 64, 129, 63, 156, 43, 95, 55, 0, 106, 62, 5, 158, 134, 83, 59, 147, 116, 36, 106, 7, 103, 188, 44, 228, 13, 120, 202, 126, 151, 12, 100, 3, 225, 183, 231, 203, 60, 55, 88, 66, 4, 80, 215, 0, 96, 89, 68, 113, 97, 87, 138, 180, 3, 163, 101, 120, 116, 160, 192, 161, 81, 159, 203, 69, 33, 230, 40, 58, 27, 52, 251, 215, 69, 248, 198, 74, 183, 238, 165, 175, 141, 248, 60, 114, 178, 192, 165, 188, 44, 9, 100, 22, 128, 192, 127, 238, 73, 209, 18, 81, 252, 109, 52, 224, 222, 247, 179, 179, 46, 206, 93, 102, 142, 119, 193, 76, 216, 96, 247, 13, 46, 223, 189, 201, 101, 207, 74, 143, 148, 99, 183, 159, 250, 184, 72, 207, 96, 169, 46, 136, 16, 192, 183, 91, 61, 94, 233, 140, 241, 81, 198, 176, 229, 173, 204, 226, 198, 175, 102, 5, 194, 243, 157, 113, 246, 221, 236, 225, 42, 232, 29, 9, 184, 255, 104, 174, 62, 0, 165, 192, 239, 78, 163, 129, 174, 195, 57, 14, 143, 5, 255, 115, 114, 197, 29, 197, 200, 221, 41, 82, 14, 188, 63, 30, 240, 245, 190, 220, 162, 145, 208, 0, 141, 174, 66, 1, 37, 129, 195, 163, 254, 34, 40, 1, 191, 70, 25, 250, 50, 75, 197, 156, 149, 15, 132, 27, 254, 62, 205, 229, 178, 176, 163, 201, 161, 103, 115, 172, 182, 14, 196, 181, 53, 114, 38, 107, 64, 22, 194, 92, 147, 80, 200, 67, 105, 50, 247, 165, 171, 156, 104, 141, 105, 70, 186, 211, 200, 131, 105, 214, 46, 82, 53, 69, 3, 119, 244, 217, 240, 63, 177, 214, 35, 233, 170, 250, 66, 164, 20, 11, 221, 52, 240, 171, 77, 49, 114, 6, 198, 74, 18, 158, 106, 5, 239, 110, 79, 208, 236, 41, 254, 93, 16, 206, 102, 204, 162, 30, 14, 78, 27, 158, 60, 93, 68, 1, 7, 191, 150, 176, 73, 60, 31, 64, 182, 178, 185, 49, 169, 103, 80, 132, 235, 166, 164, 38, 238, 64, 66, 67, 104, 94, 224, 229, 206, 56, 111, 93, 182, 116, 61, 246, 81, 177, 118, 166, 107, 248, 253, 121, 43, 92, 119, 52, 106, 86, 39, 245, 66, 0, 147, 101, 9, 105, 188, 171, 165, 186, 198, 127, 179, 57, 202, 233, 233, 106, 216, 9, 79, 113, 169, 96, 216, 119, 179, 135, 47, 112, 240, 114, 185, 110, 169, 77, 149, 132, 95, 159, 181, 32, 182, 54, 58, 139, 83, 112, 231, 7, 121, 0, 126, 210, 17, 129, 96, 150, 134, 213, 9, 205, 84, 185, 42, 29, 121, 103, 91, 130, 15, 38, 45, 228, 105, 95, 40, 207, 97, 173, 209, 83, 124, 179, 213, 227, 153, 13, 81, 16, 91, 205, 247, 174, 116, 113, 42, 118, 31, 89, 227, 86, 37, 109, 8, 224, 189, 97, 159, 178, 64, 71, 82, 207, 166, 129, 192, 75, 231, 203, 180, 68, 170, 235, 252, 95, 57, 195, 150, 138, 218, 156, 43, 8, 70, 102, 43, 98, 96, 103, 146, 63, 119, 198, 120, 115, 216, 210, 243, 179, 245, 81, 222, 248, 106, 156, 141, 73, 77, 201, 192, 109, 141, 14, 86, 171, 231, 39, 161, 99, 209, 158, 43, 152, 48, 156, 237, 41, 205, 123, 163, 1, 174, 99, 55, 38, 3, 225, 209, 142, 40, 7, 78, 23, 217, 182, 220, 2, 120, 247, 202, 172, 59, 27, 155, 28, 90, 163, 138, 76, 32, 28, 159, 12, 192, 23, 30, 110, 181, 148, 238, 63, 85, 64, 128, 166, 121, 149, 160, 23, 118, 96, 21, 122, 255, 226, 150, 40, 103, 178, 134, 132, 182, 123, 167, 50, 134, 95, 222, 18, 229, 108, 198, 112, 99, 212, 238, 29, 155, 156, 5, 240, 253, 53, 54, 84, 127, 25, 246, 9, 4, 214, 175, 112, 104, 139, 107, 46, 20, 132, 129, 41, 179, 196, 60, 96, 108, 228, 155, 61, 107, 60, 237, 41, 140, 82, 100, 138, 66, 186, 146, 151, 67, 89, 195, 119, 142, 231, 65, 36, 212, 251, 209, 188, 132, 212, 116, 85, 18, 236, 233, 143, 139, 0, 252, 174, 34, 62, 71, 39, 131, 80, 107, 138, 82, 11, 128, 182, 213, 176, 33, 169, 33, 128, 159, 174, 143, 176, 231, 104, 30, 20, 172, 170, 120, 187, 111, 181, 199, 171, 151, 124, 80, 48, 94, 17, 204, 111, 173, 246, 160, 44, 188, 182, 45, 73, 103, 131, 189, 110, 120, 218, 240, 192, 74, 151, 29, 77, 22, 80, 207, 80, 137, 6, 79, 227, 42, 136, 42, 112, 230, 244, 153, 16, 128, 18, 155, 193, 0, 127, 237, 74, 48, 81, 18, 50, 190, 128, 8, 55, 198, 236, 207, 186, 251, 243, 161, 10, 205, 112, 255, 189, 85, 46, 178, 103, 25, 61, 67, 37, 222, 24, 177, 168, 142, 237, 74, 209, 28, 213, 76, 248, 66, 206, 192, 67, 95, 242, 56, 240, 229, 8, 253, 21, 26, 126, 176, 54, 178, 112, 34, 18, 5, 63, 255, 180, 196, 211, 237, 17, 20, 240, 236, 39, 37, 11, 79, 89, 158, 247, 159, 242, 57, 50, 211, 164, 20, 60, 126, 178, 64, 68, 131, 163, 96, 239, 201, 2, 34, 112, 100, 220, 231, 135, 107, 35, 188, 114, 209, 103, 119, 179, 67, 163, 171, 24, 200, 24, 122, 134, 138, 124, 158, 23, 86, 197, 53, 23, 239, 74, 242, 112, 171, 199, 243, 131, 69, 112, 212, 188, 137, 40, 0, 121, 48, 109, 109, 244, 102, 174, 105, 8, 92, 151, 208, 244, 109, 79, 112, 177, 32, 220, 182, 76, 115, 123, 95, 142, 254, 137, 32, 188, 127, 172, 59, 133, 163, 160, 225, 245, 105, 112, 213, 188, 42, 112, 224, 197, 138, 108, 158, 216, 153, 248, 226, 61, 88, 224, 79, 91, 227, 180, 189, 157, 97, 115, 74, 115, 104, 44, 160, 127, 78, 153, 162, 160, 28, 64, 84, 171, 218, 101, 184, 247, 159, 5, 174, 248, 176, 37, 165, 121, 118, 83, 244, 11, 5, 161, 179, 209, 225, 76, 222, 240, 194, 230, 24, 142, 134, 61, 253, 121, 112, 170, 69, 172, 33, 162, 24, 47, 75, 157, 177, 92, 65, 87, 95, 22, 128, 31, 183, 69, 56, 176, 33, 90, 37, 205, 245, 214, 241, 241, 128, 67, 35, 1, 39, 38, 13, 94, 239, 52, 147, 229, 234, 255, 221, 211, 234, 17, 85, 208, 119, 37, 176, 237, 116, 177, 169, 120, 38, 148, 91, 151, 59, 124, 216, 149, 168, 12, 153, 1, 123, 79, 228, 25, 206, 203, 82, 47, 137, 186, 244, 100, 187, 211, 36, 52, 220, 255, 97, 158, 222, 138, 84, 235, 26, 131, 26, 199, 198, 3, 154, 14, 102, 152, 240, 133, 7, 90, 28, 62, 223, 157, 226, 165, 173, 113, 86, 120, 138, 168, 14, 29, 176, 169, 163, 150, 54, 254, 199, 219, 227, 36, 52, 156, 206, 25, 122, 47, 148, 107, 191, 11, 22, 72, 165, 130, 95, 108, 140, 241, 163, 54, 111, 230, 46, 138, 6, 2, 17, 130, 202, 212, 173, 21, 228, 12, 220, 249, 143, 28, 3, 19, 166, 170, 53, 183, 196, 20, 71, 182, 39, 105, 139, 219, 205, 230, 131, 25, 70, 75, 114, 245, 0, 102, 100, 122, 69, 76, 177, 171, 217, 229, 153, 142, 8, 183, 166, 106, 243, 112, 46, 47, 97, 146, 165, 92, 104, 175, 140, 106, 99, 62, 108, 122, 39, 195, 112, 65, 234, 191, 140, 150, 10, 37, 70, 64, 43, 54, 164, 53, 77, 17, 133, 8, 92, 42, 26, 118, 44, 119, 121, 170, 61, 66, 103, 186, 26, 220, 80, 78, 120, 238, 179, 18, 47, 12, 150, 170, 43, 226, 154, 0, 92, 197, 155, 0, 20, 237, 203, 172, 238, 127, 50, 101, 108, 239, 175, 147, 36, 238, 117, 125, 234, 86, 12, 125, 58, 51, 100, 106, 150, 124, 36, 254, 23, 153, 41, 93, 205, 81, 212, 105, 60, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)
    $ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
    $form.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
    $form.Topmost = $True
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.ShowInTaskbar = $true


    $form.Controls.Add($RESTUsernameLabel)
    $form.Controls.Add($RESTUsernameTextBox)
    $form.Controls.Add($RESTPasswordLabel)
    $form.Controls.Add($RESTPasswordTextBox)
    $form.Controls.Add($PUSHUsernameLabel)
    $form.Controls.Add($PUSHUsernameTextBox)
    $form.Controls.Add($PUSHPasswordLabel)
    $form.Controls.Add($PUSHPasswordTextBox)
    $form.Controls.Add($HTTPSLabel)
    $form.Controls.Add($HTTPSCheckBox)
    $form.Controls.Add($WebPortLabel)
    $form.Controls.Add($WebPortTextBox)
    $form.Controls.Add($QueryMonthLabel)
    $form.Controls.Add($QueryMonthLabel2)
    $form.Controls.Add($QueryMonthNumberBox)
    $form.Controls.Add($WaitTimeLabel)
    $form.Controls.Add($WaitTimeLabel2)
    $form.Controls.Add($WaitTimeNumberBox)
    $form.Controls.Add($okButton)


    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() > $null   # Trash the text of the button that was clicked.

    # Return the text that the user entered.
    return $form.Tag
}


function PinDialog([string]$Message, [string]$WindowTitle, [string]$DefaultText)
{
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms

    # Create the Label
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Size(10,10)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.AutoSize = $true
    $label.Text = $Message


    $PinLabel = New-Object System.Windows.Forms.Label
    $PinLabel.Location = New-Object System.Drawing.Size(10,33)
    $PinLabel.Size = New-Object System.Drawing.Size(30,20)
    $PinLabel.Text = "PIN:"

    #PIN Text box ============================================================
    $PinTextBox = new-object System.Windows.Forms.textbox
    $PinTextBox.location = new-object system.drawing.size(40,32)
    $PinTextBox.size = new-object system.drawing.size(100,15)
    $PinTextBox.text = "1234"
    $PinTextBox.tabIndex = 3


    # Add Set PIN button ============================================================
    $SetPinButton = New-Object System.Windows.Forms.Button
    $SetPinButton.Location = New-Object System.Drawing.Size(150,30)
    $SetPinButton.Size = New-Object System.Drawing.Size(80,23)
    $SetPinButton.Text = "Set Pin"
    $SetPinButton.Add_Click(
    {
        $PinTextBox.Enabled = $false
        $TestPinButton.Enabled = $false
        $LockPinButton.Enabled = $false
        $UnlockPinButton.Enabled = $false
        $SetPinButton.Enabled = $false
        $StatusLabel.Text = "Status: Setting PIN..."
        SetPin
        $PinTextBox.Enabled = $true
        $TestPinButton.Enabled = $true
        $LockPinButton.Enabled = $true
        $UnlockPinButton.Enabled = $true
        $SetPinButton.Enabled = $true
        $StatusLabel.Text = ""
    }
    )


    # Add Set PIN button ============================================================
    $TestPinButton = New-Object System.Windows.Forms.Button
    $TestPinButton.Location = New-Object System.Drawing.Size(235,30)
    $TestPinButton.Size = New-Object System.Drawing.Size(80,23)
    $TestPinButton.Text = "Test Pin"
    $TestPinButton.Add_Click(
    {
        $StatusLabel.Text = "Status: Testing PIN..."
        $PinTextBox.Enabled = $false
        $TestPinButton.Enabled = $false
        $LockPinButton.Enabled = $false
        $UnlockPinButton.Enabled = $false
        $SetPinButton.Enabled = $false
        TestBootstrap
        $PinTextBox.Enabled = $true
        $TestPinButton.Enabled = $true
        $LockPinButton.Enabled = $true
        $UnlockPinButton.Enabled = $true
        $SetPinButton.Enabled = $true
        $StatusLabel.Text = ""
    }
    )



    # Add Lock PIN button ============================================================
    $LockPinButton = New-Object System.Windows.Forms.Button
    $LockPinButton.Location = New-Object System.Drawing.Size(50,65)
    $LockPinButton.Size = New-Object System.Drawing.Size(100,23)
    $LockPinButton.Text = "Lock Pin"
    $LockPinButton.Add_Click(
    {
        $StatusLabel.Text = "Status: Locking PIN..."
        $PinTextBox.Enabled = $false
        $TestPinButton.Enabled = $false
        $LockPinButton.Enabled = $false
        $UnlockPinButton.Enabled = $false
        $SetPinButton.Enabled = $false
        LockPin
        $PinTextBox.Enabled = $true
        $TestPinButton.Enabled = $true
        $LockPinButton.Enabled = $true
        $UnlockPinButton.Enabled = $true
        $SetPinButton.Enabled = $true
        $StatusLabel.Text = ""
    }
    )


    # Add Unlock PIN button ============================================================
    $UnlockPinButton = New-Object System.Windows.Forms.Button
    $UnlockPinButton.Location = New-Object System.Drawing.Size(170,65)
    $UnlockPinButton.Size = New-Object System.Drawing.Size(100,23)
    $UnlockPinButton.Text = "Unlock Pin"
    $UnlockPinButton.Add_Click(
    {
        $StatusLabel.Text = "Status: Unlocking PIN..."
        $PinTextBox.Enabled = $false
        $TestPinButton.Enabled = $false
        $LockPinButton.Enabled = $false
        $UnlockPinButton.Enabled = $false
        $SetPinButton.Enabled = $false
        UnlockPin
        $PinTextBox.Enabled = $true
        $TestPinButton.Enabled = $true
        $LockPinButton.Enabled = $true
        $UnlockPinButton.Enabled = $true
        $SetPinButton.Enabled = $true
        $StatusLabel.Text = ""
    }
    )

    # Create the form.
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $WindowTitle
    $form.Size = New-Object System.Drawing.Size(350,140)
    $form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
    #Myskypelab Icon
    [byte[]]$WindowIcon = @(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 32, 0, 0, 0, 32, 8, 6, 0, 0, 0, 115, 122, 122, 244, 0, 0, 0, 6, 98, 75, 71, 68, 0, 255, 0, 255, 0, 255, 160, 189, 167, 147, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 11, 19, 0, 0, 11, 19, 1, 0, 154, 156, 24, 0, 0, 0, 7, 116, 73, 77, 69, 7, 225, 7, 26, 1, 36, 51, 211, 178, 227, 235, 0, 0, 5, 235, 73, 68, 65, 84, 88, 195, 197, 151, 91, 108, 92, 213, 21, 134, 191, 189, 207, 57, 115, 159, 216, 78, 176, 27, 98, 72, 226, 88, 110, 66, 66, 34, 185, 161, 168, 193, 73, 21, 17, 2, 2, 139, 75, 164, 182, 106, 145, 170, 190, 84, 74, 104, 65, 16, 144, 218, 138, 138, 244, 173, 69, 106, 101, 42, 129, 42, 149, 170, 162, 15, 168, 168, 151, 7, 4, 22, 180, 1, 41, 92, 172, 52, 196, 68, 105, 130, 19, 138, 98, 76, 154, 27, 174, 227, 248, 58, 247, 57, 103, 175, 62, 236, 241, 177, 199, 246, 140, 67, 26, 169, 251, 237, 236, 61, 179, 215, 191, 214, 191, 214, 191, 214, 86, 188, 62, 37, 252, 31, 151, 174, 123, 42, 224, 42, 72, 56, 138, 152, 99, 191, 175, 247, 114, 107, 29, 172, 75, 106, 94, 254, 74, 156, 109, 13, 58, 180, 155, 53, 240, 216, 64, 129, 63, 156, 43, 95, 55, 0, 106, 62, 5, 158, 134, 83, 59, 147, 116, 36, 106, 7, 103, 188, 44, 228, 13, 120, 202, 126, 151, 12, 100, 3, 225, 183, 231, 203, 60, 55, 88, 66, 4, 80, 215, 0, 96, 89, 68, 113, 97, 87, 138, 180, 3, 163, 101, 120, 116, 160, 192, 161, 81, 159, 203, 69, 33, 230, 40, 58, 27, 52, 251, 215, 69, 248, 198, 74, 183, 238, 165, 175, 141, 248, 60, 114, 178, 192, 165, 188, 44, 9, 100, 22, 128, 192, 127, 238, 73, 209, 18, 81, 252, 109, 52, 224, 222, 247, 179, 179, 46, 206, 93, 102, 142, 119, 193, 76, 216, 96, 247, 13, 46, 223, 189, 201, 101, 207, 74, 143, 148, 99, 183, 159, 250, 184, 72, 207, 96, 169, 46, 136, 16, 192, 183, 91, 61, 94, 233, 140, 241, 81, 198, 176, 229, 173, 204, 226, 198, 175, 102, 5, 194, 243, 157, 113, 246, 221, 236, 225, 42, 232, 29, 9, 184, 255, 104, 174, 62, 0, 165, 192, 239, 78, 163, 129, 174, 195, 57, 14, 143, 5, 255, 115, 114, 197, 29, 197, 200, 221, 41, 82, 14, 188, 63, 30, 240, 245, 190, 220, 162, 145, 208, 0, 141, 174, 66, 1, 37, 129, 195, 163, 254, 34, 40, 1, 191, 70, 25, 250, 50, 75, 197, 156, 149, 15, 132, 27, 254, 62, 205, 229, 178, 176, 163, 201, 161, 103, 115, 172, 182, 14, 196, 181, 53, 114, 38, 107, 64, 22, 194, 92, 147, 80, 200, 67, 105, 50, 247, 165, 171, 156, 104, 141, 105, 70, 186, 211, 200, 131, 105, 214, 46, 82, 53, 69, 3, 119, 244, 217, 240, 63, 177, 214, 35, 233, 170, 250, 66, 164, 20, 11, 221, 52, 240, 171, 77, 49, 114, 6, 198, 74, 18, 158, 106, 5, 239, 110, 79, 208, 236, 41, 254, 93, 16, 206, 102, 204, 162, 30, 14, 78, 27, 158, 60, 93, 68, 1, 7, 191, 150, 176, 73, 60, 31, 64, 182, 178, 185, 49, 169, 103, 80, 132, 235, 166, 164, 38, 238, 64, 66, 67, 104, 94, 224, 229, 206, 56, 111, 93, 182, 116, 61, 246, 81, 177, 118, 166, 107, 248, 253, 121, 43, 92, 119, 52, 106, 86, 39, 245, 66, 0, 147, 101, 9, 105, 188, 171, 165, 186, 198, 127, 179, 57, 202, 233, 233, 106, 216, 9, 79, 113, 169, 96, 216, 119, 179, 135, 47, 112, 240, 114, 185, 110, 169, 77, 149, 132, 95, 159, 181, 32, 182, 54, 58, 139, 83, 112, 231, 7, 121, 0, 126, 210, 17, 129, 96, 150, 134, 213, 9, 205, 84, 185, 42, 29, 121, 103, 91, 130, 15, 38, 45, 228, 105, 95, 40, 207, 97, 173, 209, 83, 124, 179, 213, 227, 153, 13, 81, 16, 91, 205, 247, 174, 116, 113, 42, 118, 31, 89, 227, 86, 37, 109, 8, 224, 189, 97, 159, 178, 64, 71, 82, 207, 166, 129, 192, 75, 231, 203, 180, 68, 170, 235, 252, 95, 57, 195, 150, 138, 218, 156, 43, 8, 70, 102, 43, 98, 96, 103, 146, 63, 119, 198, 120, 115, 216, 210, 243, 179, 245, 81, 222, 248, 106, 156, 141, 73, 77, 201, 192, 109, 141, 14, 86, 171, 231, 39, 161, 99, 209, 158, 43, 152, 48, 156, 237, 41, 205, 123, 163, 1, 174, 99, 55, 38, 3, 225, 209, 142, 40, 7, 78, 23, 217, 182, 220, 2, 120, 247, 202, 172, 59, 27, 155, 28, 90, 163, 138, 76, 32, 28, 159, 12, 192, 23, 30, 110, 181, 148, 238, 63, 85, 64, 128, 166, 121, 149, 160, 23, 118, 96, 21, 122, 255, 226, 150, 40, 103, 178, 134, 132, 182, 123, 167, 50, 134, 95, 222, 18, 229, 108, 198, 112, 99, 212, 238, 29, 155, 156, 5, 240, 253, 53, 54, 84, 127, 25, 246, 9, 4, 214, 175, 112, 104, 139, 107, 46, 20, 132, 129, 41, 179, 196, 60, 96, 108, 228, 155, 61, 107, 60, 237, 41, 140, 82, 100, 138, 66, 186, 146, 151, 67, 89, 195, 119, 142, 231, 65, 36, 212, 251, 209, 188, 132, 212, 116, 85, 18, 236, 233, 143, 139, 0, 252, 174, 34, 62, 71, 39, 131, 80, 107, 138, 82, 11, 128, 182, 213, 176, 33, 169, 33, 128, 159, 174, 143, 176, 231, 104, 30, 20, 172, 170, 120, 187, 111, 181, 199, 171, 151, 124, 80, 48, 94, 17, 204, 111, 173, 246, 160, 44, 188, 182, 45, 73, 103, 131, 189, 110, 120, 218, 240, 192, 74, 151, 29, 77, 22, 80, 207, 80, 137, 6, 79, 227, 42, 136, 42, 112, 230, 244, 153, 16, 128, 18, 155, 193, 0, 127, 237, 74, 48, 81, 18, 50, 190, 128, 8, 55, 198, 236, 207, 186, 251, 243, 161, 10, 205, 112, 255, 189, 85, 46, 178, 103, 25, 61, 67, 37, 222, 24, 177, 168, 142, 237, 74, 209, 28, 213, 76, 248, 66, 206, 192, 67, 95, 242, 56, 240, 229, 8, 253, 21, 26, 126, 176, 54, 178, 112, 34, 18, 5, 63, 255, 180, 196, 211, 237, 17, 20, 240, 236, 39, 37, 11, 79, 89, 158, 247, 159, 242, 57, 50, 211, 164, 20, 60, 126, 178, 64, 68, 131, 163, 96, 239, 201, 2, 34, 112, 100, 220, 231, 135, 107, 35, 188, 114, 209, 103, 119, 179, 67, 163, 171, 24, 200, 24, 122, 134, 138, 124, 158, 23, 86, 197, 53, 23, 239, 74, 242, 112, 171, 199, 243, 131, 69, 112, 212, 188, 137, 40, 0, 121, 48, 109, 109, 244, 102, 174, 105, 8, 92, 151, 208, 244, 109, 79, 112, 177, 32, 220, 182, 76, 115, 123, 95, 142, 254, 137, 32, 188, 127, 172, 59, 133, 163, 160, 225, 245, 105, 112, 213, 188, 42, 112, 224, 197, 138, 108, 158, 216, 153, 248, 226, 61, 88, 224, 79, 91, 227, 180, 189, 157, 97, 115, 74, 115, 104, 44, 160, 127, 78, 153, 162, 160, 28, 64, 84, 171, 218, 101, 184, 247, 159, 5, 174, 248, 176, 37, 165, 121, 118, 83, 244, 11, 5, 161, 179, 209, 225, 76, 222, 240, 194, 230, 24, 142, 134, 61, 253, 121, 112, 170, 69, 172, 33, 162, 24, 47, 75, 157, 177, 92, 65, 87, 95, 22, 128, 31, 183, 69, 56, 176, 33, 90, 37, 205, 245, 214, 241, 241, 128, 67, 35, 1, 39, 38, 13, 94, 239, 52, 147, 229, 234, 255, 221, 211, 234, 17, 85, 208, 119, 37, 176, 237, 116, 177, 169, 120, 38, 148, 91, 151, 59, 124, 216, 149, 168, 12, 153, 1, 123, 79, 228, 25, 206, 203, 82, 47, 137, 186, 244, 100, 187, 211, 36, 52, 220, 255, 97, 158, 222, 138, 84, 235, 26, 131, 26, 199, 198, 3, 154, 14, 102, 152, 240, 133, 7, 90, 28, 62, 223, 157, 226, 165, 173, 113, 86, 120, 138, 168, 14, 29, 176, 169, 163, 150, 54, 254, 199, 219, 227, 36, 52, 156, 206, 25, 122, 47, 148, 107, 191, 11, 22, 72, 165, 130, 95, 108, 140, 241, 163, 54, 111, 230, 46, 138, 6, 2, 17, 130, 202, 212, 173, 21, 228, 12, 220, 249, 143, 28, 3, 19, 166, 170, 53, 183, 196, 20, 71, 182, 39, 105, 139, 219, 205, 230, 131, 25, 70, 75, 114, 245, 0, 102, 100, 122, 69, 76, 177, 171, 217, 229, 153, 142, 8, 183, 166, 106, 243, 112, 46, 47, 97, 146, 165, 92, 104, 175, 140, 106, 99, 62, 108, 122, 39, 195, 112, 65, 234, 191, 140, 150, 10, 37, 70, 64, 43, 54, 164, 53, 77, 17, 133, 8, 92, 42, 26, 118, 44, 119, 121, 170, 61, 66, 103, 186, 26, 220, 80, 78, 120, 238, 179, 18, 47, 12, 150, 170, 43, 226, 154, 0, 92, 197, 155, 0, 20, 237, 203, 172, 238, 127, 50, 101, 108, 239, 175, 147, 36, 238, 117, 125, 234, 86, 12, 125, 58, 51, 100, 106, 150, 124, 36, 254, 23, 153, 41, 93, 205, 81, 212, 105, 60, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)
    $ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
    $form.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
    $form.Topmost = $True
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.ShowInTaskbar = $true

    # Add all of the controls to the form.
    $form.Controls.Add($label)
    #$form.Controls.Add($okButton)
    $form.Controls.Add($cancelButton)

    $form.Controls.Add($UnlockPinButton)
    $form.Controls.Add($LockPinButton)
    $form.Controls.Add($TestPinButton)
    $form.controls.add($PinTextBox)
    $form.Controls.Add($SetPinButton)
    $form.Controls.Add($PinLabel)

    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() > $null   # Trash the text of the button that was clicked.

    # Return the text that the user entered.
    return $form.Tag
}


function MessageDialog([string]$Message, [string]$WindowTitle, [string]$DefaultText)
{
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms

    # Create the Label
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Size(10,10)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.AutoSize = $true
    $label.Text = $Message


    #Message Text Start Text box ============================================================
    $MessageTextBox = new-object System.Windows.Forms.textbox
    $MessageTextBox.location = new-object system.drawing.size(10,55)
    $MessageTextBox.size = new-object system.drawing.size(300,80)
    $MessageTextBox.Multiline = $True
    #$MessageTextBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $MessageTextBox.Wordwrap = $True
    $MessageTextBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $MessageTextBox.text = "Message Body"
    $MessageTextBox.tabIndex = 3


    #Message Title Text Start Text box ============================================================
    $MessageTitleTextBox = new-object System.Windows.Forms.textbox
    $MessageTitleTextBox.location = new-object system.drawing.size(10,30)
    $MessageTitleTextBox.size = new-object system.drawing.size(130,18)
    $MessageTitleTextBox.Wordwrap = $True
    $MessageTitleTextBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $MessageTitleTextBox.text = "Heading"
    $MessageTitleTextBox.tabIndex = 4


    $ThemeLabel = New-Object System.Windows.Forms.Label
    $ThemeLabel.Location = New-Object System.Drawing.Size(10,147)
    $ThemeLabel.Size = New-Object System.Drawing.Size(90,15)
    $ThemeLabel.Text = "Dialog Theme:"
    $ThemeLabel.TabStop = $false
    $ThemeLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $objForm.Controls.Add($ThemeLabel)

    # Theme Dropdown box ============================================================
    $ThemeDropDownBox = New-Object System.Windows.Forms.ComboBox
    $ThemeDropDownBox.Location = New-Object System.Drawing.Size(100,144)
    $ThemeDropDownBox.Size = New-Object System.Drawing.Size(110,20)
    $ThemeDropDownBox.DropDownHeight = 70
    $ThemeDropDownBox.tabIndex = 4
    $ThemeDropDownBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ThemeDropDownBox.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom
    $objForm.Controls.Add($ThemeDropDownBox)

    [void] $ThemeDropDownBox.Items.Add("SfB Theme")
    [void] $ThemeDropDownBox.Items.Add("Polycom Theme")
    [void] $ThemeDropDownBox.Items.Add("Error Theme")

    $ThemeDropDownBox.SelectedIndex = 0


    # Message button ============================================================
    $MessageButton = New-Object System.Windows.Forms.Button
    $MessageButton.Location = New-Object System.Drawing.Size(145,30)
    $MessageButton.Size = New-Object System.Drawing.Size(90,20)
    $MessageButton.Text = "Send Message"
    $MessageButton.Add_Click(
    {
        $StatusLabel.Text = "Status: Sending Message..."
        $MessageButton.Enabled = $false
        $MessageAllButton.Enabled = $false
        SendTextMessage
        $MessageButton.Enabled = $true
        $MessageAllButton.Enabled = $true
        $StatusLabel.Text = ""
    }
    )

    # Message button ============================================================
    $MessageAllButton = New-Object System.Windows.Forms.Button
    $MessageAllButton.Location = New-Object System.Drawing.Size(245,30)
    $MessageAllButton.Size = New-Object System.Drawing.Size(60,20)
    $MessageAllButton.Text = "Send All"
    $MessageAllButton.Add_Click(
    {
        $MessageButton.Enabled = $false
        $MessageAllButton.Enabled = $false
        $form.Topmost = $false
        $a = new-object -comobject wscript.shell
        $intAnswer = $a.popup("Are you sure you want send this message to all VVXs on the system?",0,"Reboot All Phones",4)
        if ($intAnswer -eq 6) {
        $StatusLabel.Text = "Status: Sending Message..."
        SendMessageToAll
        $StatusLabel.Text = ""
        }else
        {Write-Host "Aborted Message send."}
        $form.Topmost = $true
        $MessageButton.Enabled = $true
        $MessageAllButton.Enabled = $true
    }
    )


    # Create the form.
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $WindowTitle
    $form.Size = New-Object System.Drawing.Size(345,215)
    $form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
    $form.Topmost = $True
    #Myskypelab Icon
    [byte[]]$WindowIcon = @(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 32, 0, 0, 0, 32, 8, 6, 0, 0, 0, 115, 122, 122, 244, 0, 0, 0, 6, 98, 75, 71, 68, 0, 255, 0, 255, 0, 255, 160, 189, 167, 147, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 11, 19, 0, 0, 11, 19, 1, 0, 154, 156, 24, 0, 0, 0, 7, 116, 73, 77, 69, 7, 225, 7, 26, 1, 36, 51, 211, 178, 227, 235, 0, 0, 5, 235, 73, 68, 65, 84, 88, 195, 197, 151, 91, 108, 92, 213, 21, 134, 191, 189, 207, 57, 115, 159, 216, 78, 176, 27, 98, 72, 226, 88, 110, 66, 66, 34, 185, 161, 168, 193, 73, 21, 17, 2, 2, 139, 75, 164, 182, 106, 145, 170, 190, 84, 74, 104, 65, 16, 144, 218, 138, 138, 244, 173, 69, 106, 101, 42, 129, 42, 149, 170, 162, 15, 168, 168, 151, 7, 4, 22, 180, 1, 41, 92, 172, 52, 196, 68, 105, 130, 19, 138, 98, 76, 154, 27, 174, 227, 248, 58, 247, 57, 103, 175, 62, 236, 241, 177, 199, 246, 140, 67, 26, 169, 251, 237, 236, 61, 179, 215, 191, 214, 191, 214, 191, 214, 86, 188, 62, 37, 252, 31, 151, 174, 123, 42, 224, 42, 72, 56, 138, 152, 99, 191, 175, 247, 114, 107, 29, 172, 75, 106, 94, 254, 74, 156, 109, 13, 58, 180, 155, 53, 240, 216, 64, 129, 63, 156, 43, 95, 55, 0, 106, 62, 5, 158, 134, 83, 59, 147, 116, 36, 106, 7, 103, 188, 44, 228, 13, 120, 202, 126, 151, 12, 100, 3, 225, 183, 231, 203, 60, 55, 88, 66, 4, 80, 215, 0, 96, 89, 68, 113, 97, 87, 138, 180, 3, 163, 101, 120, 116, 160, 192, 161, 81, 159, 203, 69, 33, 230, 40, 58, 27, 52, 251, 215, 69, 248, 198, 74, 183, 238, 165, 175, 141, 248, 60, 114, 178, 192, 165, 188, 44, 9, 100, 22, 128, 192, 127, 238, 73, 209, 18, 81, 252, 109, 52, 224, 222, 247, 179, 179, 46, 206, 93, 102, 142, 119, 193, 76, 216, 96, 247, 13, 46, 223, 189, 201, 101, 207, 74, 143, 148, 99, 183, 159, 250, 184, 72, 207, 96, 169, 46, 136, 16, 192, 183, 91, 61, 94, 233, 140, 241, 81, 198, 176, 229, 173, 204, 226, 198, 175, 102, 5, 194, 243, 157, 113, 246, 221, 236, 225, 42, 232, 29, 9, 184, 255, 104, 174, 62, 0, 165, 192, 239, 78, 163, 129, 174, 195, 57, 14, 143, 5, 255, 115, 114, 197, 29, 197, 200, 221, 41, 82, 14, 188, 63, 30, 240, 245, 190, 220, 162, 145, 208, 0, 141, 174, 66, 1, 37, 129, 195, 163, 254, 34, 40, 1, 191, 70, 25, 250, 50, 75, 197, 156, 149, 15, 132, 27, 254, 62, 205, 229, 178, 176, 163, 201, 161, 103, 115, 172, 182, 14, 196, 181, 53, 114, 38, 107, 64, 22, 194, 92, 147, 80, 200, 67, 105, 50, 247, 165, 171, 156, 104, 141, 105, 70, 186, 211, 200, 131, 105, 214, 46, 82, 53, 69, 3, 119, 244, 217, 240, 63, 177, 214, 35, 233, 170, 250, 66, 164, 20, 11, 221, 52, 240, 171, 77, 49, 114, 6, 198, 74, 18, 158, 106, 5, 239, 110, 79, 208, 236, 41, 254, 93, 16, 206, 102, 204, 162, 30, 14, 78, 27, 158, 60, 93, 68, 1, 7, 191, 150, 176, 73, 60, 31, 64, 182, 178, 185, 49, 169, 103, 80, 132, 235, 166, 164, 38, 238, 64, 66, 67, 104, 94, 224, 229, 206, 56, 111, 93, 182, 116, 61, 246, 81, 177, 118, 166, 107, 248, 253, 121, 43, 92, 119, 52, 106, 86, 39, 245, 66, 0, 147, 101, 9, 105, 188, 171, 165, 186, 198, 127, 179, 57, 202, 233, 233, 106, 216, 9, 79, 113, 169, 96, 216, 119, 179, 135, 47, 112, 240, 114, 185, 110, 169, 77, 149, 132, 95, 159, 181, 32, 182, 54, 58, 139, 83, 112, 231, 7, 121, 0, 126, 210, 17, 129, 96, 150, 134, 213, 9, 205, 84, 185, 42, 29, 121, 103, 91, 130, 15, 38, 45, 228, 105, 95, 40, 207, 97, 173, 209, 83, 124, 179, 213, 227, 153, 13, 81, 16, 91, 205, 247, 174, 116, 113, 42, 118, 31, 89, 227, 86, 37, 109, 8, 224, 189, 97, 159, 178, 64, 71, 82, 207, 166, 129, 192, 75, 231, 203, 180, 68, 170, 235, 252, 95, 57, 195, 150, 138, 218, 156, 43, 8, 70, 102, 43, 98, 96, 103, 146, 63, 119, 198, 120, 115, 216, 210, 243, 179, 245, 81, 222, 248, 106, 156, 141, 73, 77, 201, 192, 109, 141, 14, 86, 171, 231, 39, 161, 99, 209, 158, 43, 152, 48, 156, 237, 41, 205, 123, 163, 1, 174, 99, 55, 38, 3, 225, 209, 142, 40, 7, 78, 23, 217, 182, 220, 2, 120, 247, 202, 172, 59, 27, 155, 28, 90, 163, 138, 76, 32, 28, 159, 12, 192, 23, 30, 110, 181, 148, 238, 63, 85, 64, 128, 166, 121, 149, 160, 23, 118, 96, 21, 122, 255, 226, 150, 40, 103, 178, 134, 132, 182, 123, 167, 50, 134, 95, 222, 18, 229, 108, 198, 112, 99, 212, 238, 29, 155, 156, 5, 240, 253, 53, 54, 84, 127, 25, 246, 9, 4, 214, 175, 112, 104, 139, 107, 46, 20, 132, 129, 41, 179, 196, 60, 96, 108, 228, 155, 61, 107, 60, 237, 41, 140, 82, 100, 138, 66, 186, 146, 151, 67, 89, 195, 119, 142, 231, 65, 36, 212, 251, 209, 188, 132, 212, 116, 85, 18, 236, 233, 143, 139, 0, 252, 174, 34, 62, 71, 39, 131, 80, 107, 138, 82, 11, 128, 182, 213, 176, 33, 169, 33, 128, 159, 174, 143, 176, 231, 104, 30, 20, 172, 170, 120, 187, 111, 181, 199, 171, 151, 124, 80, 48, 94, 17, 204, 111, 173, 246, 160, 44, 188, 182, 45, 73, 103, 131, 189, 110, 120, 218, 240, 192, 74, 151, 29, 77, 22, 80, 207, 80, 137, 6, 79, 227, 42, 136, 42, 112, 230, 244, 153, 16, 128, 18, 155, 193, 0, 127, 237, 74, 48, 81, 18, 50, 190, 128, 8, 55, 198, 236, 207, 186, 251, 243, 161, 10, 205, 112, 255, 189, 85, 46, 178, 103, 25, 61, 67, 37, 222, 24, 177, 168, 142, 237, 74, 209, 28, 213, 76, 248, 66, 206, 192, 67, 95, 242, 56, 240, 229, 8, 253, 21, 26, 126, 176, 54, 178, 112, 34, 18, 5, 63, 255, 180, 196, 211, 237, 17, 20, 240, 236, 39, 37, 11, 79, 89, 158, 247, 159, 242, 57, 50, 211, 164, 20, 60, 126, 178, 64, 68, 131, 163, 96, 239, 201, 2, 34, 112, 100, 220, 231, 135, 107, 35, 188, 114, 209, 103, 119, 179, 67, 163, 171, 24, 200, 24, 122, 134, 138, 124, 158, 23, 86, 197, 53, 23, 239, 74, 242, 112, 171, 199, 243, 131, 69, 112, 212, 188, 137, 40, 0, 121, 48, 109, 109, 244, 102, 174, 105, 8, 92, 151, 208, 244, 109, 79, 112, 177, 32, 220, 182, 76, 115, 123, 95, 142, 254, 137, 32, 188, 127, 172, 59, 133, 163, 160, 225, 245, 105, 112, 213, 188, 42, 112, 224, 197, 138, 108, 158, 216, 153, 248, 226, 61, 88, 224, 79, 91, 227, 180, 189, 157, 97, 115, 74, 115, 104, 44, 160, 127, 78, 153, 162, 160, 28, 64, 84, 171, 218, 101, 184, 247, 159, 5, 174, 248, 176, 37, 165, 121, 118, 83, 244, 11, 5, 161, 179, 209, 225, 76, 222, 240, 194, 230, 24, 142, 134, 61, 253, 121, 112, 170, 69, 172, 33, 162, 24, 47, 75, 157, 177, 92, 65, 87, 95, 22, 128, 31, 183, 69, 56, 176, 33, 90, 37, 205, 245, 214, 241, 241, 128, 67, 35, 1, 39, 38, 13, 94, 239, 52, 147, 229, 234, 255, 221, 211, 234, 17, 85, 208, 119, 37, 176, 237, 116, 177, 169, 120, 38, 148, 91, 151, 59, 124, 216, 149, 168, 12, 153, 1, 123, 79, 228, 25, 206, 203, 82, 47, 137, 186, 244, 100, 187, 211, 36, 52, 220, 255, 97, 158, 222, 138, 84, 235, 26, 131, 26, 199, 198, 3, 154, 14, 102, 152, 240, 133, 7, 90, 28, 62, 223, 157, 226, 165, 173, 113, 86, 120, 138, 168, 14, 29, 176, 169, 163, 150, 54, 254, 199, 219, 227, 36, 52, 156, 206, 25, 122, 47, 148, 107, 191, 11, 22, 72, 165, 130, 95, 108, 140, 241, 163, 54, 111, 230, 46, 138, 6, 2, 17, 130, 202, 212, 173, 21, 228, 12, 220, 249, 143, 28, 3, 19, 166, 170, 53, 183, 196, 20, 71, 182, 39, 105, 139, 219, 205, 230, 131, 25, 70, 75, 114, 245, 0, 102, 100, 122, 69, 76, 177, 171, 217, 229, 153, 142, 8, 183, 166, 106, 243, 112, 46, 47, 97, 146, 165, 92, 104, 175, 140, 106, 99, 62, 108, 122, 39, 195, 112, 65, 234, 191, 140, 150, 10, 37, 70, 64, 43, 54, 164, 53, 77, 17, 133, 8, 92, 42, 26, 118, 44, 119, 121, 170, 61, 66, 103, 186, 26, 220, 80, 78, 120, 238, 179, 18, 47, 12, 150, 170, 43, 226, 154, 0, 92, 197, 155, 0, 20, 237, 203, 172, 238, 127, 50, 101, 108, 239, 175, 147, 36, 238, 117, 125, 234, 86, 12, 125, 58, 51, 100, 106, 150, 124, 36, 254, 23, 153, 41, 93, 205, 81, 212, 105, 60, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)

    $ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
    $form.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
    #$form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.ShowInTaskbar = $true

    # Add all of the controls to the form.
    $form.Controls.Add($label)
    $form.Controls.Add($okButton)
    $form.Controls.Add($cancelButton)

    $form.controls.add($MessageTextBox)
    $form.controls.add($MessageTitleTextBox)
    $form.Controls.Add($MessageButton)
    $form.Controls.Add($MessageAllButton)
    $form.Controls.Add($ThemeDropDownBox)
    $form.Controls.Add($ThemeLabel)


    # Initialize and show the form.
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() > $null   # Trash the text of the button that was clicked.

    # Return the text that the user entered.
    return $form.Tag
}


function ShowVVXScreen([string]$IPAddress)
{

    $SyncHash = [hashtable]::Synchronized(@{})
    $SyncHash.boolWhile = $true
    $SyncHash.IPAddress = $IPAddress
    $SyncHash.Port = $WebServicePort
    $SyncHash.Image = $null
    $SyncHash.VVXHTTPUsername = $AdminUsername
    $SyncHash.VVXHTTPPassword = $AdminPassword
    $SyncHash.UseHTTPS = $UseHTTPS


    [byte[]]$SyncHash.connectingImage = @(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 1, 100, 0, 0, 0, 200, 8, 2, 0, 0, 0, 80, 208, 12, 86, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 11, 19, 0, 0, 11, 19, 1, 0, 154, 156, 24, 0, 0, 10, 77, 105, 67, 67, 80, 80, 104,111, 116, 111, 115, 104, 111, 112, 32, 73, 67, 67, 32, 112, 114, 111, 102, 105, 108, 101, 0, 0, 120, 218, 157, 83, 119,88, 147, 247, 22, 62, 223, 247, 101, 15, 86, 66, 216, 240, 177, 151, 108, 129, 0, 34, 35, 172, 8, 200, 16, 89, 162, 16,146, 0, 97, 132, 16, 18, 64, 197, 133, 136, 10, 86, 20, 21, 17, 156, 72, 85, 196, 130, 213, 10, 72, 157, 136, 226, 160,40, 184, 103, 65, 138, 136, 90, 139, 85, 92, 56, 238, 31, 220, 167, 181, 125, 122, 239, 237, 237, 251, 215, 251, 188, 231, 156, 231, 252, 206, 121, 207, 15, 128, 17, 18, 38, 145, 230, 162, 106, 0, 57, 82, 133, 60, 58, 216, 31, 143, 79, 72,196, 201, 189, 128, 2, 21, 72, 224, 4, 32, 16, 230, 203, 194, 103, 5, 197, 0, 0, 240, 3, 121, 120, 126, 116, 176, 63, 252, 1, 175, 111, 0, 2, 0, 112, 213, 46, 36, 18, 199, 225, 255, 131, 186, 80, 38, 87, 0, 32, 145, 0, 224, 34, 18, 231, 11, 1, 144, 82, 0, 200, 46, 84, 200, 20, 0, 200, 24, 0, 176, 83, 179, 100, 10, 0, 148, 0, 0, 108, 121, 124, 66, 34, 0, 170, 13, 0, 236, 244, 73, 62, 5, 0, 216, 169, 147, 220, 23, 0, 216, 162, 28, 169, 8, 0, 141, 1, 0, 153, 40, 71, 36, 2, 64, 187, 0, 96, 85, 129, 82, 44, 2, 192, 194, 0, 160, 172, 64, 34, 46, 4, 192, 174, 1, 128, 89, 182, 50, 71, 2, 128, 189, 5,0, 118, 142, 88, 144, 15, 64, 96, 0, 128, 153, 66, 44, 204, 0, 32, 56, 2, 0, 67, 30, 19, 205, 3, 32, 76, 3, 160, 48, 210, 191, 224, 169, 95, 112, 133, 184, 72, 1, 0, 192, 203, 149, 205, 151, 75, 210, 51, 20, 184, 149, 208, 26, 119, 242, 240, 224, 226, 33, 226, 194, 108, 177, 66, 97, 23, 41, 16, 102, 9, 228, 34, 156, 151, 155, 35, 19, 72, 231, 3, 76, 206, 12, 0, 0, 26, 249, 209, 193, 254, 56, 63, 144, 231, 230, 228, 225, 230, 102, 231, 108, 239, 244, 197, 162, 254, 107, 240, 111, 34, 62, 33, 241, 223, 254, 188, 140, 2, 4, 0, 16, 78, 207, 239, 218, 95, 229, 229, 214, 3, 112, 199, 1, 176, 117, 191, 107, 169, 91, 0, 218, 86, 0, 104, 223, 249, 93, 51, 219, 9, 160, 90, 10, 208, 122, 249, 139, 121, 56, 252, 64, 30, 158, 161, 80, 200, 60, 29, 28, 10, 11, 11, 237, 37, 98, 161, 189, 48, 227, 139, 62, 255, 51, 225, 111, 224, 139, 126, 246, 252, 64, 30, 254, 219, 122, 240, 0, 113, 154, 64, 153, 173, 192, 163, 131, 253, 113, 97, 110, 118, 174, 82, 142, 231, 203, 4, 66, 49, 110, 247, 231, 35, 254, 199, 133, 127, 253, 142, 41, 209, 226, 52, 177, 92, 44, 21, 138, 241, 88, 137, 184, 80, 34, 77, 199, 121, 185, 82, 145, 68, 33, 201, 149, 226, 18, 233, 127, 50, 241, 31, 150, 253, 9, 147, 119, 13, 0, 172, 134, 79, 192, 78, 182, 7, 181, 203, 108, 192, 126, 238, 1, 2, 139, 14, 88, 210, 118, 0, 64, 126, 243, 45, 140, 26, 11, 145, 0, 16, 103, 52, 50, 121, 247, 0, 0, 147, 191, 249, 143, 64, 43, 1, 0, 205, 151, 164, 227, 0, 0, 188, 232, 24, 92, 168, 148, 23, 76, 198, 8, 0, 0, 68, 160, 129, 42, 176, 65, 7, 12, 193, 20, 172, 192, 14, 156, 193, 29, 188, 192, 23, 2, 97, 6, 68, 64, 12, 36, 192, 60, 16, 66, 6, 228, 128, 28, 10, 161, 24, 150, 65, 25, 84, 192, 58, 216, 4, 181, 176, 3, 26, 160, 17, 154, 225, 16, 180, 193, 49, 56, 13, 231, 224, 18, 92, 129, 235, 112, 23, 6, 96, 24, 158, 194, 24, 188, 134,9, 4, 65, 200, 8, 19, 97, 33, 58, 136, 17, 98, 142, 216, 34, 206, 8, 23, 153, 142, 4, 34, 97, 72, 52, 146, 128, 164, 32, 233, 136, 20, 81, 34, 197, 200, 114, 164, 2, 169, 66, 106, 145, 93, 72, 35, 242, 45, 114, 20, 57, 141, 92, 64, 250, 144, 219, 200, 32, 50, 138, 252, 138, 188, 71, 49, 148, 129, 178, 81, 3, 212, 2, 117, 64, 185, 168, 31, 26, 138, 198, 160,115, 209, 116, 52, 15, 93, 128, 150, 162, 107, 209, 26, 180, 30, 61, 128, 182, 162, 167, 209, 75, 232, 117, 116, 0, 125, 138, 142, 99, 128, 209, 49, 14, 102, 140, 217, 97, 92, 140, 135, 69, 96, 137, 88, 26, 38, 199, 22, 99, 229, 88, 53, 86, 143, 53, 99, 29, 88, 55, 118, 21, 27, 192, 158, 97, 239, 8, 36, 2, 139, 128, 19, 236, 8, 94, 132, 16, 194, 108, 130, 144, 144, 71, 88, 76, 88, 67, 168, 37, 236, 35, 180, 18, 186, 8, 87, 9, 131, 132, 49, 194, 39, 34, 147, 168, 79, 180, 37,122, 18, 249, 196, 120, 98, 58, 177, 144, 88, 70, 172, 38, 238, 33, 30, 33, 158, 37, 94, 39, 14, 19, 95, 147, 72, 36, 14, 201, 146, 228, 78, 10, 33, 37, 144, 50, 73, 11, 73, 107, 72, 219, 72, 45, 164, 83, 164, 62, 210, 16, 105, 156, 76, 38, 235, 144, 109, 201, 222, 228, 8, 178, 128, 172, 32, 151, 145, 183, 144, 15, 144, 79, 146, 251, 201, 195, 228, 183, 20,58, 197, 136, 226, 76, 9, 162, 36, 82, 164, 148, 18, 74, 53, 101, 63, 229, 4, 165, 159, 50, 66, 153, 160, 170, 81, 205,169, 158, 212, 8, 170, 136, 58, 159, 90, 73, 109, 160, 118, 80, 47, 83, 135, 169, 19, 52, 117, 154, 37, 205, 155, 22, 67, 203, 164, 45, 163, 213, 208, 154, 105, 103, 105, 247, 104, 47, 233, 116, 186, 9, 221, 131, 30, 69, 151, 208, 151, 210, 107, 232, 7, 233, 231, 233, 131, 244, 119, 12, 13, 134, 13, 131, 199, 72, 98, 40, 25, 107, 25, 123, 25, 167, 24, 183, 25, 47, 153, 76, 166, 5, 211, 151, 153, 200, 84, 48, 215, 50, 27, 153, 103, 152, 15, 152, 111, 85, 88, 42, 246, 42, 124,21, 145, 202, 18, 149, 58, 149, 86, 149, 126, 149, 231, 170, 84, 85, 115, 85, 63, 213, 121, 170, 11, 84, 171, 85, 15, 171, 94, 86, 125, 166, 70, 85, 179, 80, 227, 169, 9, 212, 22, 171, 213, 169, 29, 85, 187, 169, 54, 174, 206, 82, 119, 82,143, 80, 207, 81, 95, 163, 190, 95, 253, 130, 250, 99, 13, 178, 134, 133, 70, 160, 134, 72, 163, 84, 99, 183, 198, 25, 141, 33, 22, 198, 50, 101, 241, 88, 66, 214, 114, 86, 3, 235, 44, 107, 152, 77, 98, 91, 178, 249, 236, 76, 118, 5, 251, 27, 118, 47, 123, 76, 83, 67, 115, 170, 102, 172, 102, 145, 102, 157, 230, 113, 205, 1, 14, 198, 177, 224, 240, 57, 217,156, 74, 206, 33, 206, 13, 206, 123, 45, 3, 45, 63, 45, 177, 214, 106, 173, 102, 173, 126, 173, 55, 218, 122, 218, 190,218, 98, 237, 114, 237, 22, 237, 235, 218, 239, 117, 112, 157, 64, 157, 44, 157, 245, 58, 109, 58, 247, 117, 9, 186, 54, 186, 81, 186, 133, 186, 219, 117, 207, 234, 62, 211, 99, 235, 121, 233, 9, 245, 202, 245, 14, 233, 221, 209, 71, 245, 109, 244, 163, 245, 23, 234, 239, 214, 239, 209, 31, 55, 48, 52, 8, 54, 144, 25, 108, 49, 56, 99, 240, 204, 144, 99, 232, 107, 152, 105, 184, 209, 240, 132, 225, 168, 17, 203, 104, 186, 145, 196, 104, 163, 209, 73, 163, 39, 184, 38, 238, 135, 103, 227, 53, 120, 23, 62, 102, 172, 111, 28, 98, 172, 52, 222, 101, 220, 107, 60, 97, 98, 105, 50, 219, 164, 196, 164, 197, 228, 190, 41, 205, 148, 107, 154, 102, 186, 209, 180, 211, 116, 204, 204, 200, 44, 220, 172, 216, 172, 201, 236,142, 57, 213, 156, 107, 158, 97, 190, 217, 188, 219, 252, 141, 133, 165, 69, 156, 197, 74, 139, 54, 139, 199, 150, 218,150, 124, 203, 5, 150, 77, 150, 247, 172, 152, 86, 62, 86, 121, 86, 245, 86, 215, 172, 73, 214, 92, 235, 44, 235, 109, 214, 87, 108, 80, 27, 87, 155, 12, 155, 58, 155, 203, 182, 168, 173, 155, 173, 196, 118, 155, 109, 223, 20, 226, 20, 143, 41, 210, 41, 245, 83, 110, 218, 49, 236, 252, 236, 10, 236, 154, 236, 6, 237, 57, 246, 97, 246, 37, 246, 109, 246, 207, 29, 204, 28, 18, 29, 214, 59, 116, 59, 124, 114, 116, 117, 204, 118, 108, 112, 188, 235, 164, 225, 52, 195, 169, 196, 169, 195, 233, 87, 103, 27, 103, 161, 115, 157, 243, 53, 23, 166, 75, 144, 203, 18, 151, 118, 151, 23, 83, 109, 167, 138, 167, 110, 159, 122, 203, 149, 229, 26, 238, 186, 210, 181, 211, 245, 163, 155, 187, 155, 220, 173, 217, 109, 212, 221,204, 61, 197, 125, 171, 251, 77, 46, 155, 27, 201, 93, 195, 61, 239, 65, 244, 240, 247, 88, 226, 113, 204, 227, 157, 167, 155, 167, 194, 243, 144, 231, 47, 94, 118, 94, 89, 94, 251, 189, 30, 79, 179, 156, 38, 158, 214, 48, 109, 200, 219, 196, 91, 224, 189, 203, 123, 96, 58, 62, 61, 101, 250, 206, 233, 3, 62, 198, 62, 2, 159, 122, 159, 135, 190, 166, 190, 34, 223, 61, 190, 35, 126, 214, 126, 153, 126, 7, 252, 158, 251, 59, 250, 203, 253, 143, 248, 191, 225, 121, 242, 22, 241,78, 5, 96, 1, 193, 1, 229, 1, 189, 129, 26, 129, 179, 3, 107, 3, 31, 4, 153, 4, 165, 7, 53, 5, 141, 5, 187, 6, 47, 12, 62, 21, 66, 12, 9, 13, 89, 31, 114, 147, 111, 192, 23, 242, 27, 249, 99, 51, 220, 103, 44, 154, 209, 21, 202, 8, 157, 21, 90, 27, 250, 48, 204, 38, 76, 30, 214, 17, 142, 134, 207, 8, 223, 16, 126, 111, 166, 249, 76, 233, 204, 182, 8, 136, 224, 71, 108, 136, 184, 31, 105, 25, 153, 23, 249, 125, 20, 41, 42, 50, 170, 46, 234, 81, 180, 83, 116, 113, 116, 247, 44, 214, 172, 228, 89, 251, 103, 189, 142, 241, 143, 169, 140, 185, 59, 219, 106, 182, 114, 118, 103, 172, 106, 108, 82, 108, 99, 236, 155, 184, 128, 184, 170, 184, 129, 120, 135, 248, 69, 241, 151, 18, 116, 19, 36, 9, 237, 137, 228, 196, 216, 196, 61, 137, 227, 115, 2, 231, 108, 154, 51, 156, 228, 154, 84, 150, 116, 99, 174, 229, 220, 162, 185, 23, 230, 233, 206, 203, 158, 119, 60, 89, 53, 89, 144, 124, 56, 133, 152, 18, 151, 178, 63, 229, 131, 32, 66, 80, 47, 24, 79, 229, 167, 110, 77, 29, 19, 242, 132, 155, 133, 79, 69, 190, 162, 141, 162, 81, 177, 183, 184, 74, 60, 146, 230, 157, 86, 149, 246, 56, 221, 59, 125, 67, 250, 104, 134, 79, 70, 117, 198, 51, 9, 79, 82, 43, 121, 145, 25, 146, 185, 35, 243, 77, 86, 68, 214, 222, 172, 207, 217, 113, 217, 45, 57, 148, 156, 148, 156, 163, 82, 13, 105, 150, 180, 43, 215, 48, 183, 40, 183, 79, 102, 43, 43, 147, 13, 228, 121, 230, 109, 202, 27, 147, 135, 202, 247, 228, 35, 249, 115, 243, 219, 21, 108, 133, 76, 209, 163, 180, 82, 174, 80, 14, 22, 76, 47, 168, 43, 120, 91, 24, 91, 120, 184, 72, 189, 72, 90, 212, 51, 223, 102, 254, 234, 249, 35, 11, 130, 22, 124, 189, 144, 176, 80, 184, 176, 179, 216, 184, 120, 89, 241, 224, 34, 191, 69, 187, 22, 35, 139, 83, 23, 119, 46, 49, 93, 82, 186, 100, 120, 105, 240, 210, 125, 203, 104, 203, 178, 150, 253, 80, 226, 88, 82, 85, 242, 106, 121, 220, 242, 142, 82, 131, 210, 165, 165, 67, 43, 130, 87, 52, 149, 169, 148, 201, 203, 110, 174, 244, 90, 185, 99, 21, 97, 149, 100, 85, 239, 106, 151, 213, 91, 86, 127, 42, 23, 149, 95, 172, 112, 172, 168, 174, 248, 176, 70, 184, 230, 226, 87, 78, 95, 213, 124, 245, 121, 109, 218, 218, 222, 74, 183, 202, 237, 235, 72, 235, 164, 235, 110, 172, 247, 89, 191, 175, 74, 189, 106, 65, 213, 208, 134, 240, 13, 173, 27, 241, 141, 229, 27, 95, 109, 74, 222, 116, 161, 122, 106, 245, 142, 205, 180, 205, 202, 205, 3, 53, 97, 53, 237, 91, 204, 182, 172, 219, 242, 161, 54, 163, 246, 122, 157, 127, 93, 203, 86, 253, 173, 171, 183, 190, 217, 38, 218, 214, 191, 221, 119, 123, 243, 14, 131, 29, 21, 59, 222, 239,148, 236, 188, 181, 43, 120, 87, 107, 189, 69, 125, 245, 110, 210, 238, 130, 221, 143, 26, 98, 27, 186, 191, 230, 126, 221, 184, 71, 119, 79, 197, 158, 143, 123, 165, 123, 7, 246, 69, 239, 235, 106, 116, 111, 108, 220, 175, 191, 191, 178, 9, 109, 82, 54, 141, 30, 72, 58, 112, 229, 155, 128, 111, 218, 155, 237, 154, 119, 181, 112, 90, 42, 14, 194, 65, 229, 193, 39, 223, 166, 124, 123, 227, 80, 232, 161, 206, 195, 220, 195, 205, 223, 153, 127, 183, 245, 8, 235, 72, 121, 43, 210, 58, 191, 117, 172, 45, 163, 109, 160, 61, 161, 189, 239, 232, 140, 163, 157, 29, 94, 29, 71, 190, 183, 255, 126, 239,49, 227, 99, 117, 199, 53, 143, 87, 158, 160, 157, 40, 61, 241, 249, 228, 130, 147, 227, 167, 100, 167, 158, 157, 78, 63, 61, 212, 153, 220, 121, 247, 76, 252, 153, 107, 93, 81, 93, 189, 103, 67, 207, 158, 63, 23, 116, 238, 76, 183, 95, 247, 201, 243, 222, 231, 143, 93, 240, 188, 112, 244, 34, 247, 98, 219, 37, 183, 75, 173, 61, 174, 61, 71, 126, 112, 253, 225, 72, 175, 91, 111, 235, 101, 247, 203, 237, 87, 60, 174, 116, 244, 77, 235, 59, 209, 239, 211, 127, 250, 106, 192, 213, 115, 215, 248, 215, 46, 93, 159, 121, 189, 239, 198, 236, 27, 183, 110, 38, 221, 28, 184, 37, 186, 245, 248, 118, 246, 237, 23, 119, 10, 238, 76, 220, 93, 122, 143, 120, 175, 252, 190, 218, 253, 234, 7, 250, 15, 234, 127, 180, 254, 177,101, 192, 109, 224, 248, 96, 192, 96, 207, 195, 89, 15, 239, 14, 9, 135, 158, 254, 148, 255, 211, 135, 225, 210, 71, 204, 71, 213, 35, 70, 35, 141, 143, 157, 31, 31, 27, 13, 26, 189, 242, 100, 206, 147, 225, 167, 178, 167, 19, 207, 202, 126, 86, 255, 121, 235, 115, 171, 231, 223, 253, 226, 251, 75, 207, 88, 252, 216, 240, 11, 249, 139, 207, 191, 174, 121, 169, 243, 114, 239, 171, 169, 175, 58, 199, 35, 199, 31, 188, 206, 121, 61, 241, 166, 252, 173, 206, 219, 125, 239, 184, 239, 186, 223, 199, 189, 31, 153, 40, 252, 64, 254, 80, 243, 209, 250, 99, 199, 167, 208, 79, 247, 62, 231, 124, 254, 252, 47, 247, 132, 243, 251, 37, 210, 159, 51, 0, 0, 0, 4, 103, 65, 77, 65, 0, 0, 177, 142, 124, 251, 81, 147, 0, 0, 0, 32, 99, 72, 82, 77, 0, 0, 122, 37, 0, 0, 128, 131, 0, 0, 249, 255, 0, 0, 128, 233, 0, 0, 117, 48, 0, 0, 234, 96, 0, 0, 58,152, 0, 0, 23, 111, 146, 95, 197, 70, 0, 0, 20, 71, 73, 68, 65, 84, 120, 218, 236, 221, 109, 140, 92, 213, 121, 7, 240,255, 243, 220, 123, 103, 102, 223, 178, 139, 95, 26, 131, 241, 154, 18, 136, 129, 196, 113, 19, 84, 94, 84, 47, 77, 32,113, 212, 108, 75, 112, 37, 162, 20, 201, 78, 90, 137, 170, 78, 76, 164, 182, 124, 192, 18, 106, 90, 21, 101, 55, 42, 138, 90, 225, 212, 31, 156, 68, 21, 22, 142, 26, 210, 186, 117, 112, 85, 65, 73, 90, 188, 73, 21, 39, 21, 50, 78, 130, 67, 130, 49, 107, 59, 177, 49, 246, 238, 178, 47, 243, 118, 207, 121, 250, 97, 214, 195, 226, 181, 103, 231, 206, 206, 236, 206, 172, 255, 63, 25, 1, 222, 179, 51, 247, 206, 204, 253, 223, 231, 156, 123, 238, 25, 233, 237, 237, 5, 17, 209, 92, 148, 47, 1, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 68, 12, 11, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 196, 176, 32, 34, 134, 5, 17, 49, 44, 136, 136, 24, 22, 68, 196, 176, 32, 34, 134, 5, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 98, 88, 16, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 196, 176, 32, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 196, 176, 32, 34, 134, 5, 17, 49, 44, 136, 136, 97, 65, 68, 196, 176, 32, 34, 134, 5, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 106, 105, 33, 95, 130, 43, 141, 152, 8, 224, 5, 106, 226, 212, 96, 102, 64, 249, 15, 48, 253, 191, 2, 64, 68, 1, 53, 83, 136, 192, 12, 0, 4, 16, 129, 1, 102, 16, 190, 152, 12, 11, 90, 178, 76, 96, 226, 225, 145, 85, 192, 155, 24, 66, 211, 78, 104, 7, 36, 18, 164, 13, 33, 68, 0, 24, 28, 144, 19, 201, 139, 207, 121, 63, 1, 203, 171, 24, 44, 128, 69, 176, 16, 98, 208, 233,108, 33, 134, 5, 45, 61, 5, 49, 103, 48, 96, 25, 228, 253, 113, 122, 181, 133, 239, 134, 220, 224, 195, 53, 62, 213, 3,77, 121, 19, 49, 5, 196, 224, 212, 96, 234, 33, 69, 96, 68, 253, 137, 160, 248, 154, 203, 157, 1, 78, 194, 142, 73, 254, 188, 186, 88, 145, 242, 18, 149, 146, 133, 174, 144, 154, 180, 183, 183, 151, 175, 194, 82, 172, 32, 76, 189, 120, 81,136, 247, 134, 2, 44, 132, 245, 90, 112, 107, 49, 125, 179, 166, 222, 107, 169, 235, 93, 148, 186, 208, 54, 6, 28, 224,197, 102, 214, 10, 58, 221, 21, 129, 66, 2, 32, 52, 245, 130, 60, 236, 120, 80, 120, 5, 197, 151, 37, 255, 162, 198, 199, 130, 98, 209, 164, 13, 162, 98, 6, 85, 51, 22, 27, 12, 11, 106, 181, 247, 21, 240, 16, 131, 207, 194, 86, 90, 112, 167, 79, 127, 216, 181, 127, 0, 153, 21, 206, 155, 160, 104, 40, 74, 45, 7, 182, 2, 1, 144, 241, 234, 20, 35, 129, 59, 98,241, 243, 225, 212, 143, 144, 125, 67, 37, 2, 66, 168, 137, 87, 243, 198, 129, 115, 134, 5, 181, 10, 7, 159, 19, 185, 198, 233, 199, 173, 227, 19, 113, 251, 123, 76, 97, 200, 195, 98, 41, 117, 28, 106, 175, 0, 196, 196, 139, 9, 44, 128, 180, 121, 45, 6, 242, 186, 20, 158, 211, 252, 126, 157, 56, 21, 250, 14, 47, 90, 30, 31, 37, 134, 5, 53, 95, 167, 67, 74, 93, 0, 19, 19, 195, 20, 176, 204, 244, 147, 174, 99, 179, 203, 92, 107, 81, 108, 62, 47, 165, 195, 220, 100, 222, 253, 4, 131, 168, 25, 100, 250, 106, 136, 154, 132, 130, 20, 240, 186, 218, 119, 116, 252, 219, 209, 212, 152, 73, 59, 236, 194, 115, 49, 52, 24, 22, 212, 100, 157, 14, 131, 1, 82, 0, 196, 228, 110, 31, 253, 177, 235, 122, 175, 143, 242, 64, 60, 191, 58, 162, 122, 41, 32, 20, 125, 21, 241, 55, 162, 177, 239, 74, 214, 75, 148, 130, 231, 91, 179, 148, 4, 221, 221, 221, 124, 21, 150, 64, 109, 225, 69, 242, 112, 215, 90, 244, 23, 174, 235, 79, 227, 238, 171, 124, 152, 43, 205, 140, 144, 5, 26, 115, 244, 38, 177, 97, 57, 228, 35, 174, 235, 55, 45, 250, 69, 144, 59, 11, 11, 121, 185, 132, 97, 65, 77, 82, 80, 64, 12, 130, 24, 90, 16, 251, 61, 223, 246, 69, 119, 213, 111, 199, 233, 73, 245, 14, 14, 2, 200, 2, 14, 31, 136, 137, 88, 17, 234, 36, 94, 103, 225, 221, 113, 215, 8, 236, 167, 65, 62, 4, 132, 157, 17, 134, 5, 45, 122, 65, 161, 144, 60, 52, 130, 255, 66, 220, 243, 249, 184, 171, 195, 35, 43, 38, 211, 73, 34, 11, 59, 102, 80, 154, 220, 9, 64, 138, 134, 54, 181, 223, 181, 244, 50, 175, 63, 86, 159, 215, 56, 100, 94, 48, 44, 104, 113, 43, 139, 28, 244, 42, 248, 191, 46, 46,251, 100, 156, 201, 193, 156, 233, 130, 245, 59, 42, 108, 149, 137, 137, 137, 135, 125, 8, 153, 27, 77, 127, 36, 133, 9, 181, 136, 121, 193, 176, 160, 133, 46, 39, 74, 39, 112, 177, 172, 96, 37, 228, 203, 133, 149, 119, 248, 244, 68, 233, 218, 131, 52, 205, 172, 40, 81, 47, 226, 204, 214, 249, 244, 6, 223, 118, 72, 243, 231, 212, 34, 190, 121, 12, 11, 90, 72, 10, 8, 52, 7, 172, 177, 224, 203, 197, 21, 31, 240, 193, 4, 76, 154, 233, 78, 13, 153, 209, 3, 202, 139, 173, 70, 240, 91, 22, 254, 159, 20, 71, 224, 34, 142, 120, 182, 242, 7, 143, 90, 175, 180, 200, 138, 93, 235, 109, 160, 184, 226, 22, 11, 38, 155, 254, 10, 229, 132, 248, 91, 124, 244, 229, 226, 178, 107, 160, 57, 222, 126, 198, 176, 160, 5, 57, 101, 27, 96, 121, 69, 143, 217, 23, 227, 149, 183, 120, 153, 50, 0, 170, 205, 125, 4, 170, 97, 18, 184, 17, 246, 183, 133, 101, 87, 153, 22, 132, 115, 181, 216, 13, 161, 70, 87, 20, 16, 143, 64, 224, 190, 152, 95, 118, 7, 82, 83, 45, 181, 245, 69, 72, 47, 162, 171, 17, 190, 32, 5, 47, 94, 25, 24, 172, 44, 168, 97, 231, 103, 1, 52, 143, 226, 103, 93, 247, 71, 45, 147, 247, 241, 244, 69, 210, 214, 49, 137, 120, 147, 75, 127, 198, 117, 228, 204, 179, 55, 194, 176, 160, 70, 241, 42, 19, 90, 248, 29, 159, 249, 108, 220, 53, 5, 111, 18, 56, 109, 177, 249, 212, 6, 153, 128, 125, 54, 238, 252, 152, 235, 200, 155, 55, 225, 124, 112, 134, 5, 53, 64, 108, 254, 221, 46, 245, 133, 184, 59, 242, 222, 3, 54, 93, 107, 180, 88, 88, 24, 44, 48, 255, 231, 197, 158, 171, 17, 196, 62, 226, 114, 91, 12, 11, 170, 255, 112, 69, 17, 254, 79, 226, 206, 27, 125, 152, 109, 217, 206, 190, 0, 64, 144, 19, 187, 26, 248, 76, 220, 21, 139, 243, 188, 146, 202, 176, 160, 58, 30, 98, 2, 228, 68, 110, 245, 233, 251, 92, 199, 84, 107, 223, 202, 89, 154, 15, 162, 57, 179, 223, 119, 29, 119, 184, 40, 199, 59,83, 25, 22, 84, 199, 179, 113, 81, 144, 242, 241, 131, 197, 158, 16, 230, 90, 190, 68, 50, 192, 156, 72, 10, 126, 139, 235, 110, 243, 202, 180, 96, 88, 80, 221, 142, 175, 2, 252, 71, 172, 227, 131, 22, 21, 205, 79, 47, 94, 209, 250, 59, 149, 51, 185, 221, 69, 119, 91, 58, 47, 28, 182, 96, 88, 80, 61, 56, 216, 187, 188, 126, 58, 238, 18, 241, 78, 166, 191, 179, 99, 41, 68, 160, 192, 137, 253, 81, 220, 217, 110, 234, 196, 183, 220, 96, 45, 195, 130, 154, 78, 14, 114, 135, 165,223, 239, 131, 188, 149, 251, 37, 75, 227, 184, 178, 2, 108, 157, 143, 62, 226, 50, 69, 31, 56, 214, 23, 12, 11, 154, 95, 15, 31, 105, 160, 223, 181, 47, 64, 57, 177, 234, 241, 29, 209, 218, 213, 23, 253, 229, 141, 63, 127, 190, 235, 222, 123, 26, 183, 119, 106, 248, 152, 207, 132, 226, 185, 64, 14, 195, 130, 106, 84, 90, 169, 191, 32, 238, 6, 11, 62, 232, 219, 11, 141, 188, 106, 144, 217, 112, 211, 123, 14, 237, 235, 217, 178, 121, 246, 143, 130, 158, 174, 213, 187, 7, 86, 239, 30, 8, 122, 186, 26, 241, 212, 89, 177, 91, 227, 212, 77, 136, 114, 204, 10, 134, 5, 213, 218, 165, 23, 53, 137, 37, 248, 176, 107, 235, 244, 206, 3, 13, 250, 110, 209, 229, 15, 109, 189, 238, 217, 39, 103, 215, 20, 51, 117, 221, 123, 207, 117, 207, 62, 217, 113, 215, 109, 117, 127, 118, 15, 180, 139, 222, 233, 210, 49, 28, 223, 116, 134, 5, 213, 152, 22, 177, 184, 30, 39, 119, 90, 186, 40, 6, 168, 214, 187, 31, 146, 217, 112, 211, 117, 207, 62, 185, 242, 209, 237, 213, 52, 142, 214, 174, 94, 243, 244, 206, 85, 143, 239, 168, 251, 142, 230, 97, 247, 196, 237, 43, 124, 200, 180, 96, 88, 80, 109, 89, 129, 24, 114, 157, 69, 189, 62, 116, 38, 0, 172, 174, 67, 128, 165, 130, 34, 179, 225, 166, 68, 191, 213, 179, 101, 243, 123, 14, 237, 171, 99, 137, 33, 128, 55, 244, 122, 237, 181, 208, 243, 203, 15, 25, 22, 84, 211, 81, 100, 49, 112, 3, 194, 78, 175, 78, 234, 57, 190, 153, 168, 160, 184, 92, 137, 81, 243, 175, 95, 34, 44, 128, 8, 122, 171, 143, 138, 226, 75, 41, 73, 12, 11, 74, 82, 89, 192, 20, 242, 62, 31, 214, 122, 107, 166, 213, 177, 160, 104, 220, 227, 148, 98, 209, 11, 62, 100, 169, 80, 225, 197, 132, 105, 193, 176, 160, 164, 199, 250, 85, 208, 13, 46, 19, 215, 122, 198, 150,186, 22, 20, 151, 171, 80, 150, 63, 180, 117, 158, 187, 105, 2, 7, 91, 229, 131, 119, 185, 192, 76, 120, 31, 42, 195, 130, 146, 137, 129, 101, 166, 61, 16, 87, 211, 69, 16, 123, 231, 55, 2, 84, 83, 8, 156, 125, 108, 103, 241, 245, 83, 23, 253, 229, 169, 7, 119, 184, 209, 241, 10, 191, 181, 242, 209, 237, 115, 94, 76, 153, 147, 131, 45, 67, 248, 27, 18, 21, 184, 126, 22, 195, 130, 146, 242, 144, 101, 38, 157, 222, 108, 126, 195, 126, 153, 13, 235, 230, 44, 40, 114, 135, 143, 30, 223, 180, 245, 220, 19, 79, 206, 254, 209, 248, 254, 231, 143, 221, 126, 223, 228, 11, 135, 42, 151, 24, 151, 155, 166, 81, 125, 125, 209, 97, 88, 227, 66, 241, 102, 172, 44, 154, 21, 215, 224, 108, 82, 5, 200, 109, 62, 184, 203, 183, 23, 231, 113, 170, 93, 254, 208, 214, 213, 187, 7, 195, 85, 43, 42, 180, 25, 221, 179, 239, 228, 150, 191, 140, 207, 188,121, 217, 35, 57, 87, 120, 235, 233, 255, 136, 207, 188, 217, 185, 169, 175, 194, 227, 116, 110, 234, 107, 187, 125, 67, 246, 208, 97, 63, 54, 94, 195, 166, 166, 160, 47, 106, 254, 39, 90, 140, 166, 123, 81, 196, 202, 130, 170, 61, 219, 218, 213, 136, 106, 62, 104, 170, 25, 161, 112, 163, 227, 39, 238, 223, 126, 250, 225, 129, 106, 30, 112, 116, 207, 190, 227, 155, 182, 230, 14, 31, 173, 208, 166, 227, 174, 219, 106, 46, 49, 4, 214, 83, 26, 176, 96, 80, 176, 178, 160, 100, 221, 120, 177, 63, 112, 237, 239, 245, 81, 13, 149, 197, 242, 135, 182, 174, 222, 61, 80, 185, 160, 24, 223, 255, 252, 137, 79, 125, 62, 255, 243, 215, 18, 12, 163, 156, 121, 115, 116, 207, 62, 201, 164, 219, 111, 223, 80, 185, 196, 72, 175,187, 126, 234, 224, 33, 203, 21, 170, 127, 240, 8, 242, 154, 184, 31, 4, 185, 144, 39, 48, 134, 5, 37, 18, 43, 238, 115, 109, 107, 124, 42, 209, 237, 152, 209, 218, 213, 171, 191, 54, 48, 231, 185, 253, 244, 195, 3, 103, 31, 219, 153, 232,96, 46, 155, 122, 225, 80, 246, 208, 225, 246, 219, 55, 4, 61, 239, 186, 92, 155, 244, 186, 235, 123, 182, 252, 97, 113, 248, 84, 161, 234, 48, 138, 32, 191, 210, 248, 123, 90, 8, 88, 89, 176, 27, 66, 9, 186, 32, 64, 232, 17, 25, 188, 88, 162, 89, 22, 203, 31, 218, 90, 121, 122, 229, 228, 11, 135, 94, 189, 109, 243, 232, 158, 125, 243, 217, 188, 210, 131, 140, 239, 127, 190, 210, 89, 168, 167, 107, 245, 238, 129, 4, 187, 108, 72, 67, 33, 224, 0, 39, 195, 130, 146, 246, 225, 37, 128, 136, 161, 142, 183, 132, 156, 125, 108, 231, 137, 251, 183, 207, 190, 62, 90, 155, 83, 15, 238, 152, 243, 194, 106, 34, 161, 189, 253, 13, 169, 212, 132, 66, 190, 4, 77, 90, 92, 72, 157, 199, 250, 78, 63, 60, 48, 207, 130, 226, 146, 3, 31, 126, 116, 124, 205, 211, 59, 235, 146, 142, 23, 170, 42, 46, 248, 205, 202, 130, 18, 133, 133, 161, 40, 144, 250, 221, 43, 177, 234, 241, 29, 243, 156, 109, 57, 91, 215, 189, 247, 92, 147, 164, 175, 81, 41, 43, 12, 89, 245, 198, 202, 130, 97, 65, 73, 207, 178, 30, 150, 181, 88, 80, 207, 91, 77, 87, 62, 186, 125, 205, 211, 59, 231, 57, 219, 178, 172,190, 139, 226, 136, 200, 148, 197, 28, 176, 96, 88, 80, 98, 30, 56, 39, 72, 122, 91, 213, 185, 39, 158, 108, 220, 84, 136, 139, 30, 164, 242, 114, 123, 110, 116, 252, 212, 131, 137, 22, 191, 176, 17, 131, 193, 120, 31, 89, 211, 226, 165, 211, 38, 21, 195, 214, 34, 186, 211, 167, 18, 221, 72, 230, 199, 198, 71, 247, 236, 179, 124, 190, 242, 53, 145, 218, 166, 66, 148, 203, 147, 85, 143, 239, 168, 112, 221, 20, 23, 38, 113, 84, 142, 173, 139, 68, 144, 239, 6, 217, 151, 52, 78,177, 35, 194, 202, 130, 146, 142, 90, 12, 107, 236, 107, 42, 203, 207, 61, 241, 228, 156, 179, 45, 187, 238, 189, 231, 250, 31, 254, 91, 162, 101, 108, 170, 188, 205, 244, 244, 195, 3, 53, 92, 37, 241, 192, 121, 245, 44, 43, 88, 89, 80, 242, 110, 136, 72, 151, 151, 79, 196, 109, 34, 181, 12, 91, 84, 51, 219, 82, 51, 233, 238, 79, 125, 34, 92, 181, 98, 226, 217, 161, 57, 31, 176, 103, 203, 230, 107, 247, 124, 165, 242, 172, 208, 201, 23, 14, 157, 184, 127, 251, 84, 197, 187, 206, 46, 61, 96, 1, 56, 145, 111, 135, 217, 51, 226, 56, 131, 147, 97, 65, 201, 75, 11, 209, 143, 187, 206, 118, 212, 190, 176, 119, 53, 179, 45, 51, 27, 110, 238, 220, 212, 151, 123, 233, 229, 203, 221, 75, 22, 244, 116, 93, 187, 231, 43, 203, 30, 252, 244, 156, 5, 197, 27, 143, 126, 165, 182, 187, 200, 66, 96, 68, 252, 158, 112, 170, 32, 158, 81, 193, 176,160, 196, 103, 219, 188, 199, 7, 17, 93, 103, 97, 60, 143, 135, 41, 190, 126, 106, 100, 247, 63, 135, 171, 86, 100, 54,220, 124, 217, 99, 117, 213, 138, 158, 45, 155, 45, 159, 207, 30, 58, 60, 187, 183, 178, 230, 91, 95, 77, 175, 187, 190, 194, 83, 228, 14, 31, 125, 253, 222, 7, 107, 40, 40, 222, 30, 176, 48, 57, 33, 241, 191, 6, 121, 136, 151, 233, 82, 131, 56, 102, 65, 85, 102, 133, 105, 78, 252, 75, 146, 11, 235, 113, 49, 241, 244, 195, 3, 39, 238, 223, 62, 231, 50, 54, 179, 175, 170, 206, 121, 113, 244, 236, 99, 59, 143, 111, 218, 58, 191, 89, 161, 166, 106, 47, 7, 46, 43, 177, 152, 48, 41, 24, 22, 148, 180, 15, 98, 34, 248, 165, 250, 98, 157, 102, 52, 78, 190, 112, 232, 216, 237, 247, 85, 190, 161, 35, 145, 10, 75, 230, 36, 216, 77, 192, 11, 204, 235, 15, 52, 203, 197, 122, 25, 22, 84, 139, 208, 35, 2, 94, 65, 241, 180, 186, 176, 78, 39, 219, 210, 220, 135, 186, 220, 208, 81, 205, 5, 151, 234, 58, 91, 146, 242, 24, 17, 123, 85, 124, 196, 154, 130, 97, 65, 181, 85, 22, 1, 244, 141, 32, 62, 18, 228, 35, 148, 38, 114, 214, 231, 88, 170, 102, 165, 188, 202, 131, 32, 39, 238, 223, 126, 246, 177, 157, 245, 218, 211, 20, 228, 127, 131, 220, 175, 165, 24, 48, 44, 24, 22, 84, 3, 47, 128, 64, 44, 120, 86, 166, 226, 233, 123, 202, 234, 54, 21, 58, 209, 26, 89, 51, 141, 238, 217, 247, 234, 109, 155, 39, 231, 49, 150, 121, 137, 84, 68, 56, 20, 100, 61, 199, 42, 24, 22, 84, 123, 105, 1, 75, 153, 189, 164, 241, 113, 181, 16,90, 247, 53, 242, 19, 29, 249, 165, 130, 162, 134, 124, 185, 76, 239, 99, 90, 26, 120, 57, 42, 252, 88, 115, 25, 142, 87, 48, 44, 168, 230, 195, 73, 12, 34, 56, 47, 254, 191, 100, 42, 37, 190, 17, 111, 86, 149, 125, 138, 241, 253, 207, 31,223, 180, 181, 142, 5, 197, 244, 13, 99, 134, 64, 236, 251, 150, 29, 129, 169, 240, 22, 50, 134, 5, 205, 79, 26, 242, 159, 225, 212, 25, 179, 160, 97, 119, 100, 86, 24, 173, 172, 227, 152, 232, 172, 15, 158, 132, 130, 55, 13, 251, 195, 137, 80, 248, 57, 108, 133, 19, 88, 111, 111, 47, 95, 133, 166, 126, 135, 12, 227, 234, 182, 197, 221, 127, 86, 236, 154, 128, 9, 150, 206, 215, 7, 183, 91, 240, 245, 212, 232, 174, 96, 170, 221, 0, 49, 46, 236, 205, 202, 130, 230, 57, 118, 33, 105, 200, 51, 50, 117, 82, 92, 100, 48, 248, 37, 112, 72, 25, 16, 25, 206, 104, 252, 239, 58, 21, 54, 96, 89, 48, 98, 88, 92, 161, 113, 17, 89, 112, 50, 240, 123, 131, 201, 72, 161, 166, 78, 150, 194, 199, 46, 37, 193, 55, 131, 183, 78, 138, 69, 124, 135, 25, 22, 84, 191, 211, 176, 181, 25, 190, 19, 78, 189, 36, 197, 72, 90, 122, 40, 208, 74, 255, 164, 161, 135, 181, 248, 47, 81, 174, 157, 23, 65, 24, 22, 84, 63, 82, 122, 159, 38, 196, 63, 17, 190, 149, 19, 31, 182, 114, 197, 110, 128, 138, 119, 102, 95, 11, 199, 179, 112, 92, 156, 151, 97, 65, 245, 215, 225, 131, 23, 165, 240, 79, 225, 100,71, 11, 87, 22, 162, 38, 237, 22, 126, 51, 156, 248, 190, 78, 101, 44, 80, 46, 186, 201, 176, 160, 250, 159, 147, 197, 82, 138, 111, 233, 196, 80, 80, 108, 175, 231, 215, 137, 44, 72, 223, 3, 211, 183, 147, 102, 4, 63, 150, 226, 238, 212, 120, 26, 34, 243, 88, 170, 131, 24, 22, 84, 233, 160, 11, 76, 178, 98, 127, 23, 157, 63, 165, 190, 45, 241, 106, 190, 139, 216, 143, 18, 64, 196, 124, 26, 56, 45, 126, 32, 53, 146, 55, 187, 112, 39, 8, 251, 33, 12, 11, 106, 140, 52, 228, 184, 248, 129, 240, 205, 73, 132, 97, 139, 28, 104, 6, 24, 92, 36, 152, 146, 224, 75, 225, 200, 49, 245, 109, 22, 240, 173, 108, 57, 92, 41, 171, 245, 68, 144, 99, 234, 78, 107, 161, 207, 181, 167, 128, 88, 74, 167, 238, 102, 173, 42, 32, 2, 75, 1, 14, 225, 64, 244, 230, 119, 131, 98, 135, 112, 189, 127, 134, 5, 45, 212, 169, 58, 133, 240, 168, 228, 126, 45, 110, 163, 181, 135, 102, 30, 205, 249, 85, 94, 2, 19, 129, 143, 4, 30, 250, 165, 232, 252, 51, 97, 174, 19, 34, 236, 122,48, 44, 104, 1, 79, 215, 136, 16, 30, 9, 139, 191, 146, 184, 207, 101, 82, 8, 92, 243, 93, 86, 240, 34, 106, 62, 18, 192, 162, 129, 244, 200, 254, 32, 223, 129, 64, 120, 249, 131, 97, 65, 11, 57, 4, 32, 0, 224, 51, 62, 248, 153, 230, 79, 72, 225, 78, 223, 214, 14, 45, 194, 116, 70, 154, 52, 67, 164, 181, 65, 223, 82, 249, 82, 116, 238, 153, 32, 219, 101, 106, 234, 89, 86, 48, 44, 104, 97, 235, 138, 210, 191, 5, 41, 200, 209, 32, 254, 137, 20, 223, 143, 212, 213, 134, 172, 72, 96, 16, 136, 201, 162, 77, 119, 18, 148, 86, 16, 69, 23, 244, 181, 192, 253, 85, 120, 238, 160, 186, 118, 41, 141, 172, 48, 41, 24, 22, 180, 56, 37, 134, 41, 36, 37, 58, 172, 238, 7, 146, 239, 70, 120, 139, 79, 137, 72, 81, 44, 88, 188, 65, 12, 19, 164, 128, 20, 194, 103, 195, 220, 223, 132, 231, 95, 81, 235, 16, 174, 131, 197, 176, 160, 69, 165, 128, 23, 136, 73, 10, 50, 38, 238, 123, 65, 246, 13, 245, 235, 93, 186, 7, 40, 168, 169, 45, 80, 125, 97, 23, 102, 82, 148, 170, 157, 14, 211, 49, 193, 223, 167, 70, 255, 49, 24, 203, 138, 180, 129, 203, 218, 48, 44, 168, 9, 122, 36, 229, 194, 62, 128, 4, 144, 151, 36, 254, 161, 78, 46, 71, 112, 131, 107, 11, 196, 199, 88, 136, 202, 95, 46, 68, 70, 10, 8, 36, 248, 239, 48, 247, 88, 116, 126, 72, 138, 145, 106, 200, 183, 136, 97, 65, 205, 57, 150, 17, 137, 157, 21, 249, 31, 205, 255, 66, 167, 86, 73, 122, 141, 15, 84, 26, 62, 165, 90, 12, 41, 69, 218, 194, 163, 97, 225, 31, 130, 145, 175, 7, 83, 231, 197, 103, 132, 171, 95, 49, 44, 168, 169, 59, 38, 26, 193, 76, 241, 75, 113, 207, 105, 246, 164, 186, 101, 22, 92, 35, 97,52, 125, 80, 151, 50, 197, 172, 166, 177, 70, 187, 144, 13, 229, 223, 12, 129, 52, 2, 21, 125, 69, 220, 215, 162, 209, 175, 234, 91, 63, 9, 45, 3, 139, 166, 191, 47, 136, 23, 74, 151, 214, 217, 136, 203, 234, 45, 205, 247, 213, 224, 4, 5, 243, 25, 209, 187, 92, 230, 163, 113, 230, 125, 136, 86, 90, 4, 88, 209, 44, 150, 210, 242, 124, 146, 244, 49, 75, 161, 161, 34, 41, 40, 128, 115, 112, 63, 67, 254, 185, 40, 55, 20, 20, 198, 196, 101, 160, 1, 195, 129, 97, 65, 173, 152, 23,38, 48, 184, 41, 209, 200, 236, 221, 208, 187, 227, 142, 15, 249, 240, 6, 73, 175, 114, 97, 104, 136, 197, 98, 120, 63,125, 239, 70, 165, 222, 77, 233, 79, 202, 164, 52, 70, 242, 134, 218, 207, 144, 123, 81, 11, 223, 11, 179, 103, 204, 156, 32, 109, 10, 245, 194, 89, 220, 12, 11, 106, 57, 38, 211, 133, 128, 152, 120, 53, 245, 112, 144, 172, 186, 0, 88, 227, 194, 155, 45, 189, 6, 225, 45, 146, 90, 87, 8, 59, 13, 161, 74, 84, 186, 164, 97, 106, 128, 9, 212, 188, 64, 188, 64, 204, 23, 129, 60, 108, 10, 242, 203, 208, 253, 84, 242, 39, 205, 29, 213, 252, 177, 160, 232, 68, 50, 94, 130, 210, 69, 25, 52, 224, 123, 77, 168, 201, 112, 184, 122, 201, 150, 21, 23, 82, 195, 74, 37, 134, 194, 58, 76, 13, 248, 149, 250, 227, 50, 169, 30, 237, 22, 116, 102, 180, 199, 164, 19, 88, 233, 131, 149, 22, 116, 67, 82, 166, 145, 104, 1, 62, 47, 118, 94, 227, 17, 195, 40, 220, 91, 98, 163, 176, 113, 139, 39, 213, 155, 104, 100, 210, 102, 111, 47, 91, 83, 154, 210, 193, 164, 96, 88, 208, 210, 10, 17, 32, 2, 82, 94, 189, 192, 169, 157, 131, 59, 43, 38, 38, 62, 40, 74, 105, 125, 204, 210, 108, 9, 19, 148, 190, 66, 81, 125, 96, 162, 16, 17, 31, 64, 219, 45, 52, 99, 44, 48, 44, 232, 138, 41, 58, 188, 66, 12, 129, 47, 207, 217, 50, 0, 42, 242, 246, 144, 167, 148, 50, 3, 165, 219, 77, 12, 128, 41, 7, 36, 24, 22, 116, 133, 14, 103, 204, 24, 144, 156, 253, 181, 203, 54, 235, 111, 46, 124, 227, 32, 93, 169, 56, 113, 134, 136, 24, 22, 68, 196, 176,32, 34, 134, 5, 17, 53, 35, 14, 112, 94, 161, 46, 119, 5, 244, 146, 55, 181, 155, 153, 247, 126, 102, 3, 85, 158, 102, 24, 22, 116, 101, 168, 126, 165, 11, 231, 156, 170, 70, 81, 84, 14, 14, 78, 181, 96, 88, 16, 93, 66, 16, 4, 51, 43, 17, 38, 5, 195, 130, 18, 123, 228, 145, 71, 182, 109, 219, 118, 185, 159, 14, 14, 14, 238, 218, 181, 171, 202, 198, 67, 67, 67, 159, 251, 220, 231, 198, 198, 198, 0, 12, 12, 12, 60, 240, 192, 3, 0, 134, 135, 135, 251, 250, 250, 102, 54, 123, 234, 169, 167, 54, 110, 220, 120, 209, 143, 18, 181, 223, 182, 109, 219, 35, 143, 60, 82, 205, 54, 87, 185, 119, 229, 103,175, 160, 175, 175, 175, 191, 191, 191, 252, 188, 125, 125, 125, 195, 195, 195, 53, 236, 105, 229, 77, 218, 181, 107, 215, 224, 224, 32, 63, 150, 141, 195, 158, 103, 141, 250, 251, 251, 43, 124, 112, 75, 159, 236, 210, 199, 189, 154, 198, 27, 55, 110, 156, 221, 160, 183, 183, 183, 191, 191, 191, 250, 77, 74, 218, 190, 94, 123, 55, 127, 213, 108, 249, 156, 155, 180, 109, 219, 182, 58, 110, 18, 49, 44, 234, 102, 253, 250, 245, 213, 183, 169, 166, 241, 37, 63, 232, 73, 15, 254,122, 133, 69, 162, 189, 171, 87, 60, 205, 255, 233, 24, 22, 236, 134, 52, 163, 153, 43, 140, 149, 235, 234, 210, 73, 242, 224, 193, 131, 229, 255, 174, 220, 24, 192, 193, 131, 7, 75, 205, 46, 185, 100, 89, 127, 127, 127, 119, 119, 119, 169, 123, 82, 229, 33, 87, 125, 251, 139, 182, 164, 182, 189, 219, 177, 99, 199, 142, 29, 59, 46, 234, 16, 85, 126, 240, 218, 182, 188, 154, 77, 226, 178, 111, 172, 44, 174, 104, 115, 142, 8, 204, 179, 125, 235, 238, 41, 49, 44, 136, 97, 65, 12, 11, 74, 174, 183, 183, 55, 81, 87, 60, 105, 251, 214, 221, 83, 226, 152, 5, 93, 162, 63, 63, 52, 52, 212, 184, 246, 173, 187, 167, 0, 134, 135, 135, 215, 174, 93, 203, 15, 9, 195, 162, 245, 52, 226, 179, 219, 223, 223, 63, 56, 56, 152, 104, 152, 51, 81, 251, 230, 57, 50, 27, 183, 229, 196, 110, 200, 82, 54, 54, 54, 86, 58, 108, 186, 187, 187, 171, 233, 207, 39, 109, 223, 186, 123, 74, 12, 11, 122, 135, 238, 238, 238, 3, 7, 14, 148, 79, 185, 117, 111, 127, 240, 224, 193, 215, 103, 24, 24, 24, 104, 149, 61, 37, 134, 5, 93, 172, 220, 129, 95, 191, 126, 125, 53, 179, 146, 146, 182, 111, 221, 61, 157, 29, 118, 139, 155, 119, 12, 11, 90, 100, 71, 142, 28, 57, 114, 228, 72, 245, 167, 220, 164, 237, 91, 119, 79, 105, 225, 113, 128, 179, 217, 29, 56, 112, 160, 116, 166, 125, 224, 129, 7, 170, 153, 19, 89, 125, 251, 164, 147, 44, 155, 109, 79, 137, 149, 5, 189, 195, 222, 189, 123, 203, 131, 127, 213, 124, 125, 92, 210, 246, 173, 187, 167, 125, 125, 125,107, 215, 174, 189, 232, 118, 85, 98, 88, 92, 185, 198, 198, 198, 202, 131, 127, 213, 220, 251, 144, 180, 125, 235, 238, 41, 49, 44, 90, 91, 111, 111, 111, 221, 199, 219, 202, 135, 80, 131, 218, 47, 238, 222, 45, 204, 150, 19, 195, 226, 138, 48, 52, 52, 148, 168, 15, 159, 180, 125, 235, 238, 41, 49, 44, 232, 18, 253, 249, 134, 182, 111, 221, 61, 37, 134, 5,53, 105, 79, 164, 217, 246, 148, 24, 22, 244, 14, 195, 195, 195, 137, 238, 176, 74, 218, 190, 117, 247, 244, 146, 202, 243, 181, 158, 122, 234, 169, 234, 255, 134, 42, 227, 60, 139, 26, 205, 188, 217, 169, 188, 82, 211, 236, 207, 125, 245,141, 231, 188, 123, 234, 192, 129, 3, 137, 238, 224, 158, 179, 253, 236, 45, 217, 187, 119, 111, 105, 217, 171, 68, 123, 215, 136, 226, 98, 246, 150, 215, 229, 53, 36, 86, 22, 139, 160, 60, 221, 176, 154, 54, 213, 52, 158, 243, 116, 90, 158, 134, 80, 125, 231, 191, 230, 131, 39, 209, 222, 53, 98, 216, 98, 246, 150, 215, 229, 53, 36, 134, 197, 226, 116, 173,103, 174, 244, 63, 219, 224, 224, 96, 249, 179, 59, 103, 227, 161, 161, 161, 202, 13, 202, 71, 81, 210, 163, 110, 1, 246, 174, 65, 121, 145, 116, 147, 118, 237, 218, 197, 176, 104, 40, 105, 173, 73, 126, 68, 196, 202, 130, 136, 24, 22, 68,196, 176, 32, 34, 134, 5, 17, 17, 195, 130, 136, 24, 22, 68, 196, 176, 32, 34, 134, 5, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 34, 134, 5, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 68, 12, 11, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 196, 176, 32, 34, 134, 5, 17, 49, 44, 136, 136, 24, 22, 68, 196, 176, 32, 34, 134, 5, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 98, 88, 16, 17, 49, 44, 136, 136, 97, 65, 68, 12, 11, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 196, 176, 32, 34, 98, 88, 16, 17, 195, 130, 136, 24, 22, 68, 180, 184, 254, 127, 0, 201, 199, 93, 104, 149, 27, 252, 74, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)
    [byte[]]$SyncHash.screenCapErrorImage = @(71, 73, 70, 56, 57, 97, 100, 1, 200, 0, 247, 0, 0, 255, 255, 255, 255, 255, 204, 255, 255, 153, 255, 255, 102, 255, 255, 51, 255, 255, 0, 255, 204, 255, 255, 204, 204, 255, 204, 153, 255, 204, 102, 255, 204, 51, 255, 204, 0, 255, 153, 255, 255, 153, 204, 255, 153, 153, 255, 153, 102, 255, 153, 51, 255, 153, 0, 255, 102, 255, 255, 102, 204, 255, 102, 153, 255, 102, 102, 255, 102, 51, 255, 102, 0, 255, 51, 255, 255, 51, 204, 255, 51, 153, 255, 51, 102, 255, 51, 51, 255, 51, 0, 255, 0, 255, 255, 0, 204, 255, 0, 153, 255, 0, 102, 255, 0, 51, 255, 0, 0, 204, 255, 255, 204, 255, 204, 204, 255, 153, 204, 255, 102, 204, 255, 51, 204, 255, 0, 204, 204, 255, 204, 204, 204, 204, 204, 153, 204, 204, 102, 204, 204, 51, 204, 204, 0, 204, 153, 255, 204, 153, 204, 204, 153, 153, 204, 153, 102, 204, 153, 51, 204, 153, 0, 204, 102, 255, 204, 102, 204, 204, 102, 153, 204, 102, 102, 204, 102, 51, 204, 102, 0, 204, 51, 255, 204, 51, 204, 204, 51, 153, 204, 51, 102, 204, 51, 51, 204, 51, 0, 204, 0, 255, 204, 0, 204, 204, 0, 153, 204, 0, 102, 204, 0, 51, 204, 0, 0, 153, 255, 255, 153, 255, 204, 153, 255, 153, 153, 255, 102, 153, 255, 51, 153, 255, 0, 153, 204, 255, 153, 204, 204, 153, 204, 153, 153, 204, 102, 153, 204, 51, 153, 204, 0, 153, 153, 255, 153, 153, 204, 153, 153, 153, 153, 153, 102, 153, 153, 51, 153, 153, 0, 153, 102, 255, 153, 102, 204, 153, 102, 153, 153, 102, 102, 153, 102, 51, 153, 102, 0, 153, 51, 255, 153, 51, 204, 153, 51, 153, 153, 51, 102, 153, 51, 51, 153, 51, 0, 153, 0, 255, 153, 0, 204, 153, 0, 153, 153, 0, 102, 153, 0, 51, 153, 0, 0, 102, 255, 255, 102, 255, 204, 102, 255, 153, 102, 255, 102, 102, 255, 51, 102, 255, 0, 102, 204, 255, 102, 204, 204, 102, 204, 153, 102, 204, 102, 102, 204, 51, 102, 204, 0, 102, 153, 255, 102, 153, 204, 102, 153, 153, 102, 153, 102, 102, 153, 51, 102, 153, 0, 102, 102, 255, 102, 102, 204, 102, 102, 153, 102, 102, 102, 102, 102, 51, 102, 102, 0, 102, 51, 255, 102, 51, 204, 102, 51, 153, 102, 51, 102, 102, 51, 51, 102, 51, 0, 102, 0, 255, 102, 0, 204, 102, 0, 153, 102, 0, 102, 102, 0, 51, 102, 0, 0, 51, 255, 255, 51, 255, 204, 51, 255, 153, 51, 255, 102, 51, 255, 51, 51, 255, 0, 51, 204, 255, 51, 204, 204, 51, 204, 153, 51, 204, 102, 51, 204, 51, 51, 204, 0, 51, 153, 255, 51, 153, 204, 51, 153, 153, 51, 153, 102, 51, 153, 51, 51, 153, 0, 51, 102, 255, 51, 102, 204, 51, 102, 153, 51, 102, 102, 51, 102, 51, 51, 102, 0, 51, 51, 255, 51, 51, 204, 51, 51, 153, 51, 51, 102, 51, 51, 51, 51, 51, 0, 51, 0, 255, 51, 0, 204, 51, 0, 153, 51, 0, 102, 51, 0, 51, 51, 0, 0, 0, 255, 255, 0, 255, 204, 0, 255, 153, 0, 255, 102, 0, 255, 51, 0, 255, 0, 0, 204, 255, 0, 204, 204, 0, 204, 153, 0, 204, 102, 0, 204, 51, 0, 204, 0, 0, 153, 255, 0, 153, 204, 0, 153, 153, 0, 153, 102, 0, 153, 51, 0, 153, 0, 0, 102, 255, 0, 102, 204, 0, 102, 153, 0, 102, 102, 0, 102, 51, 0, 102, 0, 0, 51, 255, 0, 51, 204, 0, 51, 153, 0, 51, 102, 0, 51, 51, 0, 51, 0, 0, 0, 255, 0, 0, 204, 0, 0, 153, 0, 0, 102, 0, 0, 51, 0, 0, 0, 30, 30, 30, 215, 22, 53, 225, 22, 54, 222, 22, 54, 219, 22, 53, 216, 22, 52, 214, 22, 53, 209, 23, 53, 201, 23, 52, 185, 24, 50, 164, 25, 47, 142, 25, 44, 119, 26, 41, 219, 49, 76, 93, 27, 37, 224, 76, 99, 231, 118, 136, 49, 29, 32, 215, 22, 54, 68, 28, 35, 36, 28, 31, 31, 29, 30, 30, 29, 33, 28, 29, 31, 26, 32, 33, 21, 30, 29, 26, 31, 30, 29, 31, 30, 25, 33, 28, 27, 31, 28, 29, 31, 29, 30, 31, 26, 32, 29, 28, 237, 236, 236, 196, 196, 196, 140, 140, 140, 83, 83, 83, 44, 44, 44, 29, 29, 29, 255, 255, 255, 33, 249, 4, 1, 0, 0, 255, 0, 44, 0, 0, 0, 0, 100, 1, 200, 0, 0, 8, 255, 0, 177, 9, 28, 72, 176, 160, 193, 131, 8, 19, 42, 92, 200, 176, 161, 195, 135, 16, 35, 74, 156, 72, 177, 162, 197, 139, 24, 51, 106, 220, 200, 177, 163, 199, 143, 32, 67, 138, 28, 73, 178, 164, 201, 147, 40, 83, 170, 92, 201, 178, 165, 203, 151, 48, 99, 202, 156, 73, 179, 166, 205, 155, 56, 115, 234, 220, 201, 179, 167, 207, 159, 64, 131, 10, 29, 74, 180, 168, 209, 163, 72, 147, 42, 93, 202, 180, 169, 211, 167, 80, 163, 74, 157, 74, 181, 106, 204, 118, 236, 178, 102, 109, 55, 79, 158, 188, 121, 243, 8, 210, 27, 59, 214, 158, 89, 176, 94, 225, 193, 139, 167, 214, 157, 59, 173, 236, 220, 170, 109, 235, 22, 31, 62, 179, 245, 242, 214, 243, 234, 149, 44, 61, 171, 128, 3, 131, 196, 170, 181, 235, 216, 121, 132, 219, 113, 181, 39, 80, 177, 98, 187, 144, 205, 218, 243, 138, 24, 27, 220, 184, 237, 220, 214, 133, 124, 239, 94, 222, 177, 242, 176, 189, 205, 42, 184, 180, 233, 139, 132, 73, 203, 163, 23, 15, 49, 59, 197, 236, 192, 54, 134, 13, 57, 242, 228, 175, 176, 115, 99, 213, 236, 174, 118, 231, 122, 247, 64, 139, 214, 218, 238, 180, 241, 227, 12, 199, 58, 198, 6, 122, 30, 92, 129, 110, 103, 43, 134, 206, 155, 176, 91, 176, 126, 179, 211, 147, 231, 78, 96, 109, 187, 2, 231, 194, 255, 67, 78, 190, 60, 65, 120, 244, 166, 99, 67, 255, 245, 185, 232, 238, 216, 28, 23, 127, 207, 251, 237, 245, 121, 218, 131, 7, 135, 7, 255, 59, 190, 240, 115, 153, 39, 32, 114, 124, 21, 40, 143, 63, 248, 104, 85, 15, 91, 192, 33, 88, 27, 88, 116, 185, 245, 206, 59, 106, 241, 133, 77, 109, 88, 77, 200, 155, 90, 174, 17, 135, 141, 87, 3, 134, 24, 162, 122, 34, 150, 104, 162, 77, 211, 113, 133, 205, 59, 6, 198, 195, 23, 99, 39, 198, 40, 227, 68, 243, 216, 227, 79, 60, 56, 202, 195, 78, 58, 60, 174, 227, 227, 58, 60, 178, 243, 14, 142, 241, 212, 51, 227, 145, 72, 22, 36, 15, 142, 236, 172, 99, 14, 57, 226, 132, 3, 206, 55, 222, 120, 243, 205, 149, 223, 128, 19, 142, 56, 228, 152, 179, 14, 59, 57, 38, 41, 166, 128, 246, 100, 214, 85, 145, 233, 152, 51, 78, 56, 219, 104, 227, 230, 54, 220, 100, 35, 103, 55, 221, 112, 99, 39, 55, 109, 106, 179, 77, 56, 227, 144, 147, 14, 107, 239, 216, 19, 214, 152, 132, 154, 102, 79, 60, 236, 152, 35, 206, 55, 111, 202, 233, 232, 163, 144, 62, 218, 77, 158, 223, 136, 99, 78, 58, 46, 186, 51, 207, 127, 133, 118, 42, 213, 130, 233, 144, 19, 142, 155, 220, 168, 163, 78, 164, 168, 162, 170, 142, 55, 217, 112, 163, 103, 56, 126, 198, 255, 243, 142, 167, 180, 42, 53, 40, 99, 136, 146, 3, 142, 158, 217, 172, 154, 234, 175, 144, 178, 218, 141, 156, 234, 180, 9, 14, 57, 96, 98, 3, 99, 173, 204, 18, 229, 149, 57, 163, 250, 10, 236, 180, 212, 226, 25, 142, 57, 245, 140, 215, 236, 182, 63, 205, 19, 79, 58, 227, 232, 105, 42, 181, 228, 2, 107, 234, 54, 219, 136, 131, 41, 183, 236, 226, 100, 214, 146, 230, 236, 234, 205, 176, 217, 176, 90, 238, 189, 144, 118, 83, 229, 54, 223, 152, 19, 207, 178, 237, 6, 252, 82, 59, 242, 216, 51, 14, 186, 248, 38, 92, 45, 55, 227, 184, 19, 143, 192, 16, 183, 132, 168, 56, 218, 244, 170, 240, 197, 168, 206, 219, 141, 54, 226, 176, 19, 90, 196, 32, 151, 116, 104, 58, 209, 98, 108, 114, 176, 190, 106, 19, 206, 186, 33, 183, 252, 145, 195, 36, 111, 99, 239, 201, 52, 67, 170, 50, 203, 46, 231, 140, 81, 59, 223, 178, 89, 101, 205, 64, 59, 234, 205, 205, 15, 235, 108, 180, 68, 140, 233, 24, 237, 169, 65, 55, 157, 141, 202, 30, 31, 45, 245, 67, 239, 212, 35, 206, 54, 78, 103, 93, 47, 199, 85, 79, 237, 53, 66, 153, 197, 67, 142, 54, 221, 48, 173, 117, 208, 27, 147, 83, 244, 215, 108, 15, 20, 207, 58, 220, 12, 59, 243, 217, 65, 111, 227, 47, 192, 109, 75, 173, 227, 174, 116, 103, 255, 205, 234, 54, 224, 164, 163, 109, 222, 83, 199, 19, 174, 217, 125, 3, 61, 174, 54, 227, 180, 70, 184, 212, 111, 199, 141, 120, 226, 53, 155, 106, 231, 58, 107, 63, 238, 242, 129, 87, 123, 51, 57, 229, 149, 115, 188, 162, 230, 57, 199, 99, 142, 54, 220, 204, 13, 122, 208, 234, 104, 227, 47, 233, 45, 219, 195, 14, 155, 171, 159, 93, 108, 56, 216, 212, 51, 31, 236, 2, 155, 142, 117, 237, 116, 219, 157, 57, 239, 237, 202, 115, 181, 214, 234, 124, 227, 64, 57, 143, 114, 147, 15, 58, 90, 115, 252, 49, 241, 220, 22, 247, 182, 58, 244, 58, 125, 78, 62, 0, 148, 131, 56, 0, 0, 52, 0, 68, 156, 78, 99, 78, 61, 187, 60, 143, 93, 175, 211, 232, 128, 223, 253, 247, 224, 231, 115, 206, 231, 24, 15, 173, 246, 249, 220, 214, 51, 251, 54, 227, 2, 125, 206, 1, 238, 235, 30, 164, 2, 8, 0, 7, 4, 205, 27, 123, 138, 26, 254, 152, 37, 143, 117, 120, 163, 84, 138, 107, 31, 1, 153, 247, 40, 2, 2, 64, 126, 138, 227, 198, 58, 166, 183, 64, 79, 153, 174, 98, 254, 3, 160, 5, 189, 87, 65, 11, 22, 240, 27, 52, 107, 221, 253, 6, 213, 65, 66, 29, 42, 92, 64, 147, 160, 9, 73, 232, 40, 19, 130, 239, 0, 231, 160, 89, 186, 232, 129, 183, 22, 38, 73, 118, 224, 248, 221, 189, 255, 178, 39, 167, 255, 217, 16, 124, 20, 172, 225, 17, 1, 0, 61, 147, 113, 3, 28, 10, 244, 225, 152, 228, 145, 142, 111, 208, 175, 92, 234, 144, 161, 13, 209, 129, 184, 110, 160, 131, 123, 71, 60, 64, 18, 19, 214, 141, 111, 152, 79, 138, 99, 122, 27, 217, 48, 102, 196, 48, 206, 111, 114, 147, 18, 225, 17, 155, 168, 48, 225, 161, 49, 141, 167, 195, 152, 22, 77, 232, 0, 43, 166, 170, 74, 123, 180, 160, 24, 235, 248, 186, 59, 38, 73, 108, 32, 196, 87, 27, 143, 120, 14, 63, 254, 138, 85, 139, 220, 98, 194, 180, 161, 182, 30, 26, 210, 68, 242, 128, 225, 189, 178, 184, 68, 0, 28, 192, 84, 87, 12, 150, 242, 58, 217, 128, 49, 78, 139, 113, 195, 187, 228, 137, 226, 65, 177, 123, 149, 67, 142, 91, 212, 87, 194, 190, 177, 189, 37, 62, 143, 136, 191, 226, 88, 42, 85, 89, 34, 227, 105, 67, 117, 191, 114, 192, 18, 197, 248, 179, 132, 89, 174, 1, 157, 196, 101, 170, 210, 85, 48, 94, 202, 72, 30, 180, 35, 23, 56, 144, 185, 197, 98, 94, 140, 78, 223, 248, 226, 17, 203, 37, 61, 103, 62, 243, 120, 228, 26, 165, 9, 185, 24, 202, 114, 209, 169, 27, 231, 216, 38, 185, 186, 233, 205, 19, 249, 242, 94, 194, 220, 98, 57, 239, 165, 77, 27, 114, 83, 28, 187, 108, 167, 121, 88, 249, 255, 203, 112, 82, 211, 134, 131, 60, 217, 63, 237, 185, 206, 198, 233, 211, 68, 134, 75, 228, 180, 190, 241, 202, 78, 210, 17, 95, 234, 168, 229, 17, 159, 199, 205, 198, 177, 240, 160, 2, 66, 228, 189, 172, 20, 72, 2, 150, 18, 95, 226, 60, 98, 41, 233, 68, 174, 109, 220, 15, 163, 33, 122, 155, 16, 177, 24, 73, 11, 202, 111, 158, 69, 132, 229, 56, 191, 113, 206, 146, 250, 107, 86, 40, 21, 80, 3, 73, 138, 47, 207, 197, 243, 136, 125, 44, 103, 71, 3, 40, 198, 115, 242, 116, 90, 234, 56, 99, 78, 247, 153, 14, 112, 144, 15, 164, 180, 4, 35, 64, 115, 24, 169, 110, 52, 116, 137, 232, 40, 166, 53, 129, 245, 196, 40, 46, 149, 60, 246, 120, 7, 56, 21, 102, 170, 159, 74, 82, 82, 245, 4, 40, 243, 128, 73, 173, 61, 185, 195, 146, 95, 61, 141, 70, 77, 22, 209, 78, 210, 80, 78, 14, 5, 229, 197, 80, 25, 87, 243, 120, 203, 28, 43, 37, 171, 169, 100, 26, 192, 187, 102, 195, 141, 253, 75, 216, 190, 10, 217, 87, 228, 16, 140, 29, 78, 165, 89, 55, 140, 144, 214, 194, 14, 144, 143, 108, 221, 228, 19, 211, 193, 193, 198, 30, 135, 30, 48, 132, 41, 176, 232, 180, 13, 194, 154, 210, 165, 141, 68, 33, 93, 249, 234, 89, 228, 224, 10, 176, 172, 243, 198, 30, 13, 75, 64, 7, 255, 232, 149, 102, 174, 203, 103, 107, 3, 51, 15, 127, 236, 239, 128, 217, 184, 234, 251, 74, 120, 193, 55, 2, 45, 129, 254, 216, 109, 121, 16, 41, 218, 114, 1, 18, 137, 151, 45, 101, 98, 113, 123, 82, 229, 18, 168, 169, 79, 5, 154, 231, 254, 55, 70, 231, 161, 131, 166, 138, 83, 199, 102, 59, 107, 93, 211, 164, 79, 27, 205, 237, 233, 116, 227, 86, 83, 160, 81, 146, 188, 229, 53, 13, 61, 176, 171, 76, 154, 177, 213, 168, 53, 123, 96, 224, 224, 27, 95, 193, 12, 105, 108, 178, 4, 158, 123, 171, 219, 223, 227, 120, 197, 103, 2, 182, 239, 158, 228, 129, 211, 2, 35, 231, 109, 15, 76, 176, 201, 230, 165, 65, 221, 58, 56, 48, 14, 83, 159, 132, 47, 214, 58, 131, 114, 234, 194, 6, 102, 7, 197, 50, 187, 97, 148, 157, 138, 99, 121, 1, 49, 83, 131, 152, 94, 1, 155, 106, 82, 251, 85, 113, 70, 29, 152, 221, 18, 103, 12, 129, 73, 141, 199, 238, 100, 76, 30, 211, 21, 203, 115, 54, 134, 212, 184, 74, 117, 55, 30, 15, 200, 199, 53, 182, 241, 139, 237, 196, 88, 35, 155, 199, 97, 230, 200, 70, 96, 75, 60, 47, 116, 249, 11, 62, 78, 22, 16, 148, 191, 33, 51, 98, 217, 88, 27, 253, 210, 49, 92, 179, 108, 156, 37, 173, 99, 84, 172, 146, 22, 240, 86, 165, 50, 165, 146, 153, 255, 76, 216, 240, 22, 184, 244, 68, 98, 186, 61, 48, 93, 56, 123, 243, 128, 96, 84, 48, 115, 48, 138, 85, 117, 182, 239, 184, 90, 23, 102, 254, 234, 249, 200, 233, 184, 154, 204, 90, 172, 176, 59, 139, 3, 115, 23, 61, 180, 137, 14, 245, 14, 104, 33, 44, 120, 42, 243, 151, 133, 37, 29, 162, 37, 181, 195, 210, 168, 155, 83, 160, 35, 85, 165, 153, 185, 106, 79, 230, 192, 71, 209, 236, 129, 101, 78, 199, 168, 29, 67, 170, 180, 56, 118, 21, 234, 250, 78, 171, 78, 110, 2, 135, 165, 192, 20, 105, 87, 31, 169, 56, 247, 192, 81, 168, 102, 221, 38, 56, 217, 218, 81, 184, 206, 53, 151, 210, 177, 160, 64, 249, 122, 76, 131, 226, 10, 172, 133, 253, 164, 89, 223, 185, 216, 121, 106, 83, 234, 116, 221, 37, 76, 225, 40, 185, 207, 102, 214, 132, 88, 132, 35, 172, 248, 232, 73, 228, 24, 135, 186, 201, 209, 37, 31, 165, 67, 213, 46, 50, 75, 184, 33, 118, 38, 34, 217, 219, 222, 75, 234, 245, 188, 171, 23, 150, 249, 200, 123, 223, 0, 15, 184, 192, 7, 78, 240, 130, 27, 252, 224, 8, 79, 184, 194, 23, 206, 240, 134, 59, 252, 225, 16, 143, 184, 196, 39, 78, 241, 138, 91, 252, 226, 24, 207, 56, 84, 2, 177, 143, 142, 239, 163, 32, 30, 223, 71, 32, 90, 221, 95, 86, 116, 156, 32, 29, 255, 103, 197, 81, 252, 193, 15, 145, 7, 101, 5, 1, 44, 72, 0, 87, 208, 18, 86, 4, 194, 10, 109, 227, 7, 248, 8, 2, 62, 126, 32, 69, 31, 0, 192, 249, 79, 88, 222, 242, 157, 19, 132, 31, 252, 176, 2, 0, 244, 209, 18, 157, 3, 128, 228, 71, 115, 58, 207, 1, 224, 115, 129, 244, 3, 233, 85, 47, 8, 210, 251, 129, 16, 164, 63, 228, 234, 2, 225, 135, 202, 29, 130, 117, 174, 19, 4, 232, 31, 135, 136, 216, 177, 1, 246, 163, 111, 189, 235, 252, 0, 55, 67, 174, 238, 117, 130, 248, 131, 229, 70, 39, 136, 59, 148, 206, 244, 140, 208, 61, 235, 110, 31, 251, 64, 164, 206, 54, 194, 11, 164, 231, 2, 81, 186, 251, 250, 46, 144, 64, 72, 85, 232, 216, 64, 59, 204, 47, 24, 119, 133, 4, 157, 123, 250, 80, 124, 32, 176, 97, 120, 196, 99, 195, 241, 49, 231, 188, 13, 23, 178, 15, 0, 148, 30, 0, 160, 167, 249, 231, 9, 8, 249, 158, 131, 209, 10, 240, 241, 60, 218, 19, 31, 192, 124, 140, 92, 32, 201, 53, 60, 202, 151, 62, 248, 158, 131, 59, 16, 23, 100, 136, 226, 193, 199, 120, 206, 75, 85, 31, 92, 7, 186, 5, 211, 46, 144, 210, 23, 31, 98, 186, 71, 124, 233, 87, 16, 8, 126, 112, 124, 32, 192, 167, 62, 232, 211, 14, 244, 124, 228, 99, 31, 48, 127, 190, 255, 65, 192, 183, 130, 201, 243, 93, 244, 0, 24, 8, 226, 157, 94, 253, 155, 99, 131, 229, 250, 208, 7, 247, 242, 17, 127, 241, 131, 28, 124, 138, 47, 63, 213, 177, 177, 15, 43, 84, 255, 244, 85, 23, 63, 153, 7, 62, 155, 135, 13, 178, 103, 122, 239, 151, 121, 72, 215, 125, 102, 23, 118, 121, 183, 123, 125, 119, 119, 48, 7, 121, 64, 7, 121, 8, 49, 125, 237, 199, 124, 172, 224, 125, 213, 23, 126, 216, 96, 5, 250, 183, 116, 250, 64, 125, 83, 183, 127, 32, 19, 125, 251, 87, 129, 208, 113, 119, 239, 199, 61, 155, 231, 14, 192, 151, 15, 201, 213, 125, 62, 7, 124, 0, 32, 119, 7, 113, 65, 38, 135, 128, 75, 135, 119, 233, 119, 120, 251, 55, 125, 162, 49, 16, 119, 151, 92, 48, 183, 15, 56, 152, 16, 165, 183, 15, 238, 112, 65, 253, 80, 122, 149, 55, 132, 238, 112, 132, 64, 200, 116, 83, 136, 128, 6, 104, 130, 179, 119, 35, 201, 229, 15, 253, 224, 121, 14, 248, 131, 247, 199, 120, 48, 24, 124, 216, 192, 10, 224, 35, 120, 8, 161, 130, 162, 193, 130, 123, 23, 116, 111, 129, 134, 0, 48, 118, 134, 215, 106, 12, 24, 50, 40, 232, 115, 167, 167, 15, 251, 32, 120, 78, 231, 113, 138, 119, 119, 104, 247, 14, 254, 96, 114, 72, 104, 121, 76, 7, 133, 6, 200, 116, 157, 183, 127, 78, 255, 247, 125, 81, 56, 16, 179, 215, 16, 138, 200, 123, 138, 200, 118, 28, 183, 15, 220, 147, 118, 158, 71, 133, 89, 88, 117, 147, 88, 136, 30, 7, 134, 232, 119, 16, 206, 71, 16, 27, 72, 117, 254, 224, 124, 80, 119, 127, 75, 215, 135, 83, 103, 5, 86, 208, 113, 158, 167, 123, 90, 215, 128, 17, 147, 135, 108, 55, 124, 65, 247, 126, 78, 103, 65, 51, 136, 133, 173, 56, 126, 137, 184, 127, 188, 215, 136, 85, 167, 137, 139, 135, 139, 147, 200, 16, 149, 88, 140, 53, 184, 124, 64, 8, 138, 88, 120, 128, 105, 199, 139, 164, 104, 139, 205, 199, 123, 4, 161, 116, 86, 224, 15, 48, 87, 128, 10, 209, 15, 188, 40, 116, 254, 96, 67, 85, 167, 141, 81, 247, 128, 158, 231, 14, 253, 16, 8, 202, 183, 121, 234, 24, 121, 88, 232, 16, 150, 104, 140, 140, 152, 119, 96, 56, 15, 55, 135, 127, 103, 87, 143, 164, 135, 143, 252, 71, 117, 114, 200, 125, 213, 168, 133, 7, 73, 141, 76, 24, 131, 1, 104, 130, 97, 104, 138, 220, 8, 29, 58, 151, 15, 19, 233, 16, 238, 8, 143, 4, 56, 141, 93, 247, 128, 83, 35, 135, 233, 104, 116, 92, 231, 28, 87, 200, 132, 216, 176, 137, 7, 209, 140, 13, 113, 143, 62, 119, 140, 224, 195, 117, 0, 200, 118, 2, 225, 28, 74, 183, 2, 88, 198, 134, 206, 40, 144, 80, 255, 232, 116, 241, 192, 114, 38, 249, 137, 2, 49, 137, 25, 249, 135, 3, 73, 115, 101, 232, 144, 165, 104, 16, 167, 88, 16, 220, 51, 129, 13, 17, 146, 113, 65, 133, 254, 0, 116, 246, 135, 126, 184, 56, 16, 73, 25, 50, 48, 151, 15, 178, 200, 61, 66, 55, 130, 179, 168, 120, 62, 55, 15, 167, 55, 139, 251, 192, 135, 63, 9, 144, 12, 161, 146, 139, 200, 118, 196, 167, 116, 220, 163, 135, 90, 217, 127, 61, 73, 123, 113, 169, 15, 73, 120, 127, 43, 9, 141, 114, 152, 121, 96, 196, 137, 8, 153, 118, 48, 183, 2, 86, 224, 125, 8, 104, 131, 178, 232, 62, 160, 56, 130, 196, 167, 15, 35, 199, 15, 241, 55, 127, 241, 23, 133, 167, 55, 135, 195, 120, 118, 130, 217, 127, 181, 72, 124, 29, 23, 127, 224, 246, 133, 175, 232, 127, 88, 134, 152, 45, 211, 15, 202, 231, 143, 180, 231, 62, 182, 135, 101, 202, 232, 62, 183, 135, 146, 105, 9, 141, 107, 185, 122, 4, 8, 115, 209, 24, 64, 22, 200, 118, 165, 121, 131, 10, 241, 140, 3, 201, 15, 238, 48, 153, 3, 232, 151, 10, 25, 118, 175, 167, 116, 36, 89, 154, 101, 105, 130, 38, 244, 113, 191, 24, 64, 85, 231, 133, 228, 231, 16, 188, 152, 154, 216, 39, 85, 189, 88, 157, 238, 195, 124, 244, 152, 15, 85, 9, 49, 238, 192, 10, 111, 55, 16, 238, 255, 136, 117, 67, 168, 119, 88, 87, 153, 24, 193, 14, 224, 217, 15, 173, 214, 29, 228, 121, 16, 223, 25, 158, 21, 1, 158, 172, 112, 151, 8, 145, 92, 87, 199, 10, 238, 128, 131, 68, 215, 157, 243, 73, 138, 10, 49, 158, 94, 135, 101, 119, 23, 15, 228, 217, 158, 238, 240, 158, 71, 231, 159, 94, 227, 15, 130, 114, 159, 246, 169, 17, 243, 128, 158, 68, 193, 130, 26, 193, 10, 30, 40, 17, 14, 26, 105, 248, 96, 161, 5, 193, 66, 30, 170, 113, 69, 241, 139, 43, 208, 15, 17, 58, 17, 39, 42, 162, 76, 225, 152, 124, 104, 162, 42, 42, 38, 44, 24, 162, 47, 138, 36, 41, 58, 163, 54, 122, 163, 3, 199, 114, 106, 40, 34, 58, 26, 24, 224, 9, 120, 72, 130, 117, 59, 186, 16, 67, 58, 16, 69, 186, 122, 249, 112, 164, 229, 17, 131, 74, 186, 20, 60, 185, 120, 73, 130, 141, 64, 218, 117, 220, 115, 16, 252, 80, 165, 16, 169, 138, 72, 65, 64, 140, 153, 17, 0, 88, 163, 41, 81, 123, 250, 48, 165, 19, 49, 127, 30, 135, 36, 110, 249, 149, 99, 202, 16, 62, 104, 16, 109, 234, 166, 171, 24, 8, 96, 186, 18, 12, 154, 16, 228, 183, 2, 96, 68, 166, 16, 113, 119, 34, 55, 167, 22, 81, 167, 8, 113, 167, 96, 36, 142, 20, 225, 116, 77, 90, 34, 46, 136, 16, 48, 232, 149, 62, 255, 7, 131, 152, 105, 122, 29, 231, 155, 28, 167, 120, 30, 151, 140, 33, 135, 138, 34, 71, 142, 130, 217, 128, 139, 122, 153, 39, 199, 118, 101, 25, 127, 183, 41, 17, 123, 183, 2, 122, 26, 168, 251, 215, 15, 61, 105, 114, 241, 39, 152, 130, 183, 168, 94, 41, 120, 33, 167, 157, 86, 23, 170, 36, 88, 17, 165, 122, 170, 57, 168, 138, 241, 208, 125, 162, 193, 113, 54, 23, 127, 218, 201, 10, 86, 32, 172, 13, 248, 166, 5, 65, 172, 198, 42, 16, 38, 23, 8, 154, 106, 5, 128, 151, 116, 241, 87, 128, 142, 26, 172, 93, 138, 138, 197, 26, 153, 226, 9, 143, 130, 25, 173, 217, 186, 166, 97, 138, 150, 208, 225, 150, 241, 136, 13, 147, 71, 64, 31, 119, 174, 1, 228, 151, 238, 115, 116, 0, 16, 130, 239, 58, 16, 228, 26, 115, 253, 144, 149, 250, 119, 17, 24, 74, 121, 15, 209, 137, 88, 56, 125, 120, 234, 132, 162, 65, 174, 64, 151, 117, 4, 100, 119, 87, 58, 115, 22, 145, 175, 20, 185, 175, 170, 232, 131, 70, 184, 116, 235, 234, 139, 152, 183, 148, 190, 88, 116, 84, 135, 116, 42, 247, 164, 242, 23, 175, 162, 247, 175, 241, 195, 117, 101, 152, 15, 255, 42, 116, 19, 24, 64, 212, 106, 131, 217, 57, 174, 23, 84, 174, 69, 185, 2, 242, 71, 171, 37, 161, 124, 223, 135, 139, 217, 199, 167, 193, 255, 135, 116, 0, 136, 177, 156, 103, 177, 66, 26, 118, 22, 235, 174, 239, 10, 158, 190, 135, 134, 220, 41, 122, 50, 56, 148, 44, 8, 168, 22, 169, 121, 246, 104, 122, 69, 199, 157, 185, 167, 159, 108, 183, 137, 62, 216, 128, 13, 136, 179, 28, 185, 148, 42, 7, 158, 23, 241, 134, 168, 215, 180, 62, 231, 15, 49, 120, 150, 189, 88, 122, 71, 251, 150, 83, 107, 122, 81, 185, 156, 2, 129, 182, 170, 170, 182, 143, 200, 15, 111, 59, 114, 68, 171, 114, 78, 23, 119, 202, 135, 132, 82, 153, 92, 114, 104, 5, 118, 91, 121, 53, 187, 138, 102, 152, 168, 86, 151, 18, 94, 152, 155, 144, 23, 142, 239, 119, 142, 13, 91, 135, 139, 235, 184, 184, 167, 123, 119, 219, 29, 235, 23, 145, 224, 67, 136, 102, 123, 123, 15, 129, 117, 88, 135, 131, 236, 48, 150, 41, 137, 174, 184, 135, 131, 104, 231, 131, 251, 224, 159, 200, 42, 155, 236, 9, 17, 63, 170, 160, 2, 241, 185, 166, 185, 16, 235, 55, 129, 221, 33, 149, 15, 25, 131, 93, 232, 124, 98, 251, 168, 149, 138, 164, 185, 203, 146, 84, 183, 147, 179, 231, 141, 111, 181, 182, 31, 39, 149, 59, 153, 148, 51, 201, 14, 239, 183, 147, 15, 187, 121, 119, 135, 120, 152, 119, 168, 34, 113, 119, 142, 233, 62, 56, 215, 132, 38, 84, 121, 182, 152, 123, 28, 217, 123, 98, 255, 136, 126, 48, 130, 120, 158, 169, 135, 239, 122, 119, 111, 75, 124, 186, 74, 132, 185, 89, 124, 96, 33, 184, 215, 105, 121, 65, 183, 149, 215, 249, 132, 214, 137, 132, 107, 75, 126, 132, 250, 144, 86, 25, 145, 15, 49, 153, 15, 248, 190, 160, 43, 187, 4, 180, 2, 99, 231, 154, 3, 105, 65, 76, 23, 23, 182, 8, 192, 80, 234, 116, 50, 170, 174, 41, 91, 186, 3, 217, 119, 71, 24, 22, 8, 146, 92, 218, 107, 65, 190, 57, 153, 51, 203, 18, 119, 151, 175, 63, 136, 127, 179, 74, 135, 223, 123, 148, 6, 33, 185, 250, 184, 127, 94, 27, 63, 207, 249, 132, 231, 186, 191, 8, 241, 173, 153, 103, 16, 245, 170, 175, 4, 204, 15, 239, 240, 142, 70, 151, 149, 29, 215, 147, 139, 138, 189, 90, 247, 128, 87, 105, 145, 129, 224, 178, 245, 103, 195, 89, 185, 190, 89, 136, 196, 154, 75, 143, 48, 107, 182, 179, 186, 121, 97, 209, 192, 23, 52, 197, 232, 119, 151, 82, 57, 171, 62, 55, 137, 73, 137, 192, 89, 72, 150, 30, 199, 10, 85, 60, 152, 209, 233, 18, 167, 215, 182, 168, 135, 139, 240, 161, 142, 243, 168, 194, 98, 136, 120, 104, 72, 125, 34, 87, 159, 114, 199, 183, 25, 106, 17, 7, 107, 192, 239, 151, 195, 202, 98, 131, 84, 249, 176, 204, 183, 159, 228, 200, 145, 186, 103, 131, 74, 27, 17, 123, 255, 156, 177, 57, 188, 159, 5, 129, 192, 49, 152, 57, 88, 102, 139, 145, 172, 119, 40, 220, 141, 112, 104, 16, 94, 204, 141, 51, 121, 16, 46, 200, 198, 226, 9, 187, 70, 89, 18, 43, 176, 15, 72, 103, 131, 118, 41, 184, 11, 203, 121, 226, 200, 126, 108, 231, 135, 25, 217, 15, 42, 71, 119, 57, 107, 183, 43, 236, 115, 19, 201, 10, 113, 209, 199, 159, 23, 8, 250, 201, 10, 123, 107, 17, 160, 135, 124, 77, 107, 202, 195, 236, 131, 114, 75, 169, 156, 103, 202, 201, 101, 182, 86, 135, 181, 23, 251, 203, 90, 123, 134, 76, 188, 16, 195, 156, 200, 26, 169, 201, 226, 154, 138, 126, 139, 137, 82, 123, 201, 103, 200, 149, 179, 236, 203, 9, 250, 189, 229, 172, 182, 103, 216, 154, 253, 202, 123, 231, 220, 205, 72, 103, 179, 171, 108, 125, 137, 199, 15, 53, 114, 183, 126, 170, 17, 46, 85, 121, 55, 28, 64, 17, 8, 142, 17, 187, 184, 234, 202, 156, 108, 139, 140, 162, 33, 193, 107, 234, 192, 171, 76, 17, 111, 251, 141, 12, 59, 115, 92, 231, 15, 214, 121, 132, 62, 104, 178, 97, 40, 186, 69, 233, 62, 170, 167, 208, 92, 121, 207, 0, 122, 150, 48, 123, 209, 162, 201, 191, 219, 202, 193, 224, 252, 186, 216, 248, 131, 155, 220, 119, 236, 128, 141, 135, 184, 207, 80, 154, 133, 182, 121, 207, 25, 1, 131, 223, 255, 122, 186, 59, 25, 103, 176, 202, 135, 128, 247, 132, 245, 183, 211, 161, 58, 166, 223, 57, 171, 145, 26, 212, 204, 151, 114, 245, 112, 165, 223, 247, 195, 193, 199, 170, 194, 202, 10, 55, 77, 17, 44, 247, 196, 148, 24, 114, 128, 71, 172, 221, 218, 114, 62, 247, 185, 245, 7, 173, 67, 104, 136, 92, 28, 103, 234, 153, 173, 183, 10, 213, 214, 71, 161, 32, 7, 139, 5, 225, 168, 83, 234, 28, 202, 122, 153, 13, 104, 136, 31, 26, 214, 94, 121, 186, 68, 125, 16, 19, 42, 173, 130, 249, 130, 28, 151, 142, 46, 135, 211, 55, 215, 211, 49, 153, 211, 166, 252, 171, 197, 154, 215, 102, 237, 17, 236, 96, 118, 92, 216, 161, 118, 23, 161, 49, 154, 132, 143, 13, 29, 9, 1, 117, 181, 155, 201, 89, 108, 16, 197, 33, 211, 110, 218, 17, 154, 66, 114, 243, 176, 32, 246, 89, 153, 97, 209, 158, 22, 161, 217, 226, 169, 168, 8, 49, 218, 146, 141, 131, 173, 168, 218, 67, 8, 110, 162, 109, 25, 240, 129, 101, 36, 23, 29, 184, 247, 218, 144, 157, 132, 137, 13, 29, 216, 252, 17, 224, 150, 193, 59, 230, 16, 39, 106, 218, 68, 56, 147, 237, 199, 148, 61, 161, 111, 239, 247, 97, 237, 2, 22, 202, 221, 16, 126, 122, 199, 47, 65, 220, 35, 225, 210, 23, 100, 5, 189, 141, 163, 167, 225, 133, 7, 170, 221, 222, 255, 253, 221, 224, 29, 222, 226, 61, 222, 19, 71, 119, 112, 231, 186, 106, 39, 183, 73, 242, 142, 30, 39, 195, 59, 145, 137, 228, 140, 175, 82, 109, 20, 156, 91, 118, 21, 161, 142, 249, 123, 194, 161, 91, 205, 228, 241, 164, 161, 199, 19, 254, 125, 198, 247, 173, 223, 66, 145, 223, 33, 61, 17, 234, 232, 168, 138, 71, 17, 29, 93, 21, 109, 247, 16, 152, 119, 202, 163, 138, 19, 169, 88, 151, 83, 185, 185, 4, 254, 18, 15, 238, 16, 91, 60, 198, 3, 30, 190, 3, 49, 161, 236, 48, 143, 105, 57, 202, 14, 142, 167, 243, 157, 16, 16, 172, 193, 201, 58, 124, 25, 29, 127, 192, 124, 221, 4, 113, 196, 234, 43, 119, 202, 168, 149, 99, 119, 196, 129, 112, 205, 194, 135, 195, 94, 24, 118, 165, 57, 214, 48, 158, 149, 183, 87, 216, 139, 201, 152, 9, 26, 127, 146, 56, 166, 51, 168, 15, 49, 174, 149, 40, 55, 127, 221, 92, 17, 245, 74, 157, 28, 14, 144, 240, 17, 127, 164, 121, 65, 154, 11, 126, 139, 199, 189, 174, 71, 121, 224, 6, 22, 218, 120, 227, 83, 190, 139, 243, 215, 224, 84, 65, 169, 115, 250, 135, 221, 121, 176, 244, 7, 115, 234, 119, 65, 244, 71, 128, 221, 17, 131, 101, 233, 125, 102, 199, 119, 94, 222, 119, 211, 247, 174, 152, 151, 162, 218, 203, 208, 188, 204, 127, 113, 57, 121, 99, 255, 71, 126, 34, 155, 145, 185, 153, 178, 4, 157, 133, 222, 23, 143, 221, 193, 231, 121, 76, 17, 108, 126, 229, 48, 219, 196, 139, 222, 176, 35, 168, 212, 50, 56, 209, 132, 153, 164, 64, 91, 16, 148, 206, 141, 55, 44, 178, 147, 199, 223, 77, 81, 148, 19, 94, 16, 18, 24, 63, 92, 141, 123, 64, 87, 162, 162, 209, 128, 46, 252, 134, 76, 151, 138, 118, 204, 148, 21, 25, 206, 95, 123, 122, 251, 192, 14, 128, 172, 16, 119, 123, 16, 46, 218, 130, 7, 153, 164, 43, 29, 145, 182, 248, 232, 183, 126, 126, 189, 158, 138, 238, 253, 16, 172, 126, 229, 165, 124, 166, 64, 88, 180, 84, 203, 118, 221, 81, 136, 149, 219, 131, 241, 48, 151, 151, 28, 237, 137, 106, 182, 102, 167, 230, 72, 225, 168, 237, 77, 16, 206, 177, 199, 137, 76, 172, 182, 201, 172, 13, 78, 128, 254, 0, 131, 130, 137, 164, 88, 55, 147, 184, 142, 117, 84, 56, 125, 245, 48, 15, 36, 30, 134, 167, 250, 163, 158, 72, 128, 255, 110, 131, 224, 214, 236, 183, 12, 132, 114, 106, 239, 56, 199, 119, 252, 46, 174, 41, 60, 171, 236, 62, 226, 75, 153, 200, 141, 30, 199, 95, 11, 197, 68, 136, 117, 223, 206, 14, 119, 199, 119, 114, 87, 135, 16, 143, 116, 18, 189, 237, 62, 9, 21, 234, 154, 209, 49, 201, 143, 248, 103, 214, 223, 105, 198, 8, 255, 184, 226, 227, 103, 130, 170, 105, 66, 250, 96, 15, 18, 12, 62, 31, 39, 132, 37, 61, 196, 38, 206, 121, 141, 46, 156, 34, 173, 240, 26, 223, 144, 85, 135, 101, 59, 47, 241, 174, 216, 174, 236, 238, 242, 150, 157, 16, 21, 200, 185, 115, 62, 156, 159, 103, 157, 142, 8, 62, 24, 92, 196, 186, 183, 244, 31, 231, 123, 201, 133, 238, 72, 145, 137, 29, 55, 223, 139, 108, 145, 105, 155, 143, 0, 224, 159, 29, 61, 125, 245, 141, 183, 65, 87, 223, 42, 151, 148, 1, 207, 150, 241, 59, 16, 111, 59, 166, 252, 80, 240, 38, 56, 236, 224, 236, 236, 38, 62, 245, 156, 75, 189, 45, 119, 169, 90, 55, 205, 11, 97, 147, 83, 55, 156, 127, 136, 116, 223, 46, 175, 254, 171, 123, 130, 223, 179, 96, 40, 246, 71, 65, 219, 105, 109, 152, 102, 93, 149, 30, 232, 153, 153, 222, 209, 49, 120, 172, 201, 213, 201, 167, 93, 193, 34, 157, 16, 89, 105, 181, 151, 253, 182, 68, 143, 235, 224, 11, 244, 141, 231, 121, 29, 77, 250, 146, 109, 17, 172, 126, 216, 96, 108, 141, 166, 143, 204, 71, 9, 209, 0, 169, 123, 180, 95, 158, 84, 88, 148, 170, 206, 20, 148, 202, 188, 12, 113, 165, 124, 152, 156, 168, 199, 106, 148, 106, 125, 173, 103, 226, 190, 79, 125, 208, 239, 115, 123, 41, 225, 219, 216, 119, 117, 47, 155, 22, 255, 110, 186, 52, 126, 144, 166, 124, 122, 114, 42, 239, 113, 95, 125, 103, 200, 243, 160, 167, 156, 38, 126, 253, 208, 127, 17, 199, 127, 229, 203, 159, 114, 217, 92, 186, 153, 155, 254, 184, 76, 128, 215, 155, 164, 205, 204, 187, 131, 13, 16, 172, 0, 0, 208, 199, 143, 95, 32, 43, 216, 176, 237, 3, 144, 47, 16, 195, 129, 252, 20, 78, 164, 88, 209, 226, 69, 140, 25, 53, 110, 228, 216, 177, 223, 10, 135, 216, 222, 205, 227, 200, 111, 224, 73, 0, 86, 220, 41, 100, 181, 2, 37, 128, 137, 17, 47, 242, 203, 247, 146, 159, 63, 108, 129, 106, 162, 92, 201, 80, 159, 66, 147, 48, 57, 6, 122, 169, 207, 159, 63, 125, 39, 243, 37, 221, 167, 240, 37, 128, 166, 56, 21, 90, 65, 217, 20, 27, 213, 129, 86, 92, 74, 196, 38, 211, 162, 206, 151, 43, 59, 94, 252, 24, 114, 100, 199, 164, 54, 157, 2, 224, 202, 20, 91, 191, 157, 0, 86, 108, 197, 22, 84, 233, 205, 181, 47, 173, 130, 229, 249, 214, 101, 86, 186, 99, 5, 15, 38, 92, 88, 99, 63, 126, 98, 199, 242, 219, 215, 56, 16, 43, 138, 71, 25, 59, 158, 104, 176, 159, 69, 127, 241, 252, 61, 220, 23, 8, 175, 59, 119, 253, 56, 63, 102, 105, 16, 39, 98, 174, 27, 67, 115, 190, 41, 245, 97, 160, 126, 172, 248, 65, 238, 154, 178, 49, 255, 237, 137, 238, 216, 77, 222, 7, 89, 247, 235, 221, 252, 46, 215, 21, 110, 17, 180, 104, 199, 184, 13, 191, 77, 60, 216, 224, 115, 203, 64, 139, 19, 167, 221, 143, 114, 244, 186, 163, 251, 73, 37, 14, 125, 54, 182, 227, 163, 113, 35, 15, 228, 14, 251, 114, 244, 233, 213, 83, 180, 55, 56, 179, 84, 118, 138, 21, 30, 117, 143, 79, 234, 74, 238, 10, 229, 235, 167, 111, 88, 49, 119, 208, 114, 139, 137, 173, 254, 40, 154, 167, 30, 156, 250, 35, 105, 165, 3, 243, 227, 104, 63, 245, 218, 19, 172, 64, 141, 40, 236, 175, 64, 0, 33, 172, 104, 63, 13, 193, 155, 207, 193, 245, 66, 20, 113, 196, 138, 236, 195, 102, 30, 20, 49, 35, 241, 196, 21, 9, 243, 106, 48, 146, 12, 139, 177, 197, 177, 64, 196, 200, 65, 27, 213, 155, 177, 162, 25, 115, 164, 241, 71, 32, 51, 242, 49, 72, 34, 51, 210, 167, 160, 33, 139, 84, 114, 73, 38, 155, 116, 242, 73, 40, 71, 60, 42, 201, 40, 171, 180, 242, 74, 44, 179, 212, 114, 75, 46, 187, 244, 242, 75, 48, 195, 20, 115, 76, 50, 203, 52, 243, 76, 52, 211, 84, 115, 77, 54, 219, 116, 243, 77, 56, 227, 148, 115, 78, 58, 235, 180, 243, 78, 60, 243, 212, 115, 79, 62, 251, 244, 243, 79, 64, 3, 21, 116, 80, 66, 11, 53, 244, 80, 68, 19, 85, 47, 116, 81, 70, 27, 117, 244, 81, 72, 35, 149, 116, 82, 74, 43, 181, 244, 82, 76, 51, 213, 116, 83, 78, 59, 245, 244, 83, 80, 67, 21, 117, 84, 82, 75, 53, 245, 84, 84, 83, 85, 117, 85, 86, 91, 109, 51, 32, 0, 59)

    <#
    $SyncHash.TextLabel = New-Object System.Windows.Forms.Label
    $SyncHash.TextLabel.Location = New-Object System.Drawing.Size(12,5)
    $SyncHash.TextLabel.Size = New-Object System.Drawing.Size(330,40)
    $Font = New-Object System.Drawing.Font("Arial",8,[System.Drawing.FontStyle]::Bold)
    # Font styles are: Regular, Bold, Italic, Underline, Strikeout
    $SyncHash.TextLabel.Font = $Font
    $SyncHash.TextLabel.Text = "User must manually set:`r`nSettings -> Basic -> Preferences-> Screen Capture -> Enabled"
    #>

    # Message button ============================================================
    $SyncHash.SaveImageButton = New-Object System.Windows.Forms.Button
    $SyncHash.SaveImageButton.Location = New-Object System.Drawing.Size(150,230)
    $SyncHash.SaveImageButton.Size = New-Object System.Drawing.Size(80,22)
    $SyncHash.SaveImageButton.Text = "Save Image"
    $SyncHash.SaveImageButton.Margin = 10
    #$SyncHash.SaveImageButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $SyncHash.SaveImageButton.Add_Click(
    {
        #$form.Topmost = $false
        #SAVE IMAGE
        $img = $SyncHash.PictureBox.Image
        SaveImageFile -bmp $img
        #$form.Topmost = $true
    }
    )

    $SyncHash.PictureBox = new-object Windows.Forms.PictureBox
    $SyncHash.PictureBox.Location = New-Object System.Drawing.Size(10,10)
    $SyncHash.PictureBox.width = 0
    $SyncHash.PictureBox.height = 0
    $SyncHash.PictureBox.BorderStyle = "FixedSingle"
    $SyncHash.PictureBox.sizemode = "Autosize"
    $SyncHash.PictureBox.Margin = 10
    $SyncHash.PictureBox.WaitOnLoad = $true

    $SyncHash.PictureBox.Add_SizeChanged(
    {
        $width = $SyncHash.PictureBox.Width
        $height = $SyncHash.PictureBox.Height
        #Write-Host "RESIZED! $Width $height"
        $SyncHash.SaveImageButton.Location = New-Object System.Drawing.Size((($width / 2) - 30),($height + 20))
        [System.Windows.Forms.Application]::DoEvents()
    }
    )
    $SyncHash.PictureBox.Image = $SyncHash.screenCapErrorImage  #$SyncHash.connectingImage



    # Create the form
    $SyncHash.form = New-Object System.Windows.Forms.Form
    $SyncHash.form.Text = "VVX Screen"
    $SyncHash.form.Size = New-Object System.Drawing.Size(100,100)
    $SyncHash.form.FormBorderStyle = "FixedSingle"
    $SyncHash.form.StartPosition = "CenterScreen"
    $SyncHash.form.AutoSizeMode = "GrowAndShrink"
    $SyncHash.form.AutoSize = $True
    $SyncHash.form.Topmost = $True
    $SyncHash.form.MaximizeBox = $False
    $SyncHash.form.MinimizeBox = $False
    #Myskypelab Icon
    [byte[]]$WindowIcon = @(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 32, 0, 0, 0, 32, 8, 6, 0, 0, 0, 115, 122, 122, 244, 0, 0, 0, 6, 98, 75, 71, 68, 0, 255, 0, 255, 0, 255, 160, 189, 167, 147, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 11, 19, 0, 0, 11, 19, 1, 0, 154, 156, 24, 0, 0, 0, 7, 116, 73, 77, 69, 7, 225, 7, 26, 1, 36, 51, 211, 178, 227, 235, 0, 0, 5, 235, 73, 68, 65, 84, 88, 195, 197, 151, 91, 108, 92, 213, 21, 134, 191, 189, 207, 57, 115, 159, 216, 78, 176, 27, 98, 72, 226, 88, 110, 66, 66, 34, 185, 161, 168, 193, 73, 21, 17, 2, 2, 139, 75, 164, 182, 106, 145, 170, 190, 84, 74, 104, 65, 16, 144, 218, 138, 138, 244, 173, 69, 106, 101, 42, 129, 42, 149, 170, 162, 15, 168, 168, 151, 7, 4, 22, 180, 1, 41, 92, 172, 52, 196, 68, 105, 130, 19, 138, 98, 76, 154, 27, 174, 227, 248, 58, 247, 57, 103, 175, 62, 236, 241, 177, 199, 246, 140, 67, 26, 169, 251, 237, 236, 61, 179, 215, 191, 214, 191, 214, 191, 214, 86, 188, 62, 37, 252, 31, 151, 174, 123, 42, 224, 42, 72, 56, 138, 152, 99, 191, 175, 247, 114, 107, 29, 172, 75, 106, 94, 254, 74, 156, 109, 13, 58, 180, 155, 53, 240, 216, 64, 129, 63, 156, 43, 95, 55, 0, 106, 62, 5, 158, 134, 83, 59, 147, 116, 36, 106, 7, 103, 188, 44, 228, 13, 120, 202, 126, 151, 12, 100, 3, 225, 183, 231, 203, 60, 55, 88, 66, 4, 80, 215, 0, 96, 89, 68, 113, 97, 87, 138, 180, 3, 163, 101, 120, 116, 160, 192, 161, 81, 159, 203, 69, 33, 230, 40, 58, 27, 52, 251, 215, 69, 248, 198, 74, 183, 238, 165, 175, 141, 248, 60, 114, 178, 192, 165, 188, 44, 9, 100, 22, 128, 192, 127, 238, 73, 209, 18, 81, 252, 109, 52, 224, 222, 247, 179, 179, 46, 206, 93, 102, 142, 119, 193, 76, 216, 96, 247, 13, 46, 223, 189, 201, 101, 207, 74, 143, 148, 99, 183, 159, 250, 184, 72, 207, 96, 169, 46, 136, 16, 192, 183, 91, 61, 94, 233, 140, 241, 81, 198, 176, 229, 173, 204, 226, 198, 175, 102, 5, 194, 243, 157, 113, 246, 221, 236, 225, 42, 232, 29, 9, 184, 255, 104, 174, 62, 0, 165, 192, 239, 78, 163, 129, 174, 195, 57, 14, 143, 5, 255, 115, 114, 197, 29, 197, 200, 221, 41, 82, 14, 188, 63, 30, 240, 245, 190, 220, 162, 145, 208, 0, 141, 174, 66, 1, 37, 129, 195, 163, 254, 34, 40, 1, 191, 70, 25, 250, 50, 75, 197, 156, 149, 15, 132, 27, 254, 62, 205, 229, 178, 176, 163, 201, 161, 103, 115, 172, 182, 14, 196, 181, 53, 114, 38, 107, 64, 22, 194, 92, 147, 80, 200, 67, 105, 50, 247, 165, 171, 156, 104, 141, 105, 70, 186, 211, 200, 131, 105, 214, 46, 82, 53, 69, 3, 119, 244, 217, 240, 63, 177, 214, 35, 233, 170, 250, 66, 164, 20, 11, 221, 52, 240, 171, 77, 49, 114, 6, 198, 74, 18, 158, 106, 5, 239, 110, 79, 208, 236, 41, 254, 93, 16, 206, 102, 204, 162, 30, 14, 78, 27, 158, 60, 93, 68, 1, 7, 191, 150, 176, 73, 60, 31, 64, 182, 178, 185, 49, 169, 103, 80, 132, 235, 166, 164, 38, 238, 64, 66, 67, 104, 94, 224, 229, 206, 56, 111, 93, 182, 116, 61, 246, 81, 177, 118, 166, 107, 248, 253, 121, 43, 92, 119, 52, 106, 86, 39, 245, 66, 0, 147, 101, 9, 105, 188, 171, 165, 186, 198, 127, 179, 57, 202, 233, 233, 106, 216, 9, 79, 113, 169, 96, 216, 119, 179, 135, 47, 112, 240, 114, 185, 110, 169, 77, 149, 132, 95, 159, 181, 32, 182, 54, 58, 139, 83, 112, 231, 7, 121, 0, 126, 210, 17, 129, 96, 150, 134, 213, 9, 205, 84, 185, 42, 29, 121, 103, 91, 130, 15, 38, 45, 228, 105, 95, 40, 207, 97, 173, 209, 83, 124, 179, 213, 227, 153, 13, 81, 16, 91, 205, 247, 174, 116, 113, 42, 118, 31, 89, 227, 86, 37, 109, 8, 224, 189, 97, 159, 178, 64, 71, 82, 207, 166, 129, 192, 75, 231, 203, 180, 68, 170, 235, 252, 95, 57, 195, 150, 138, 218, 156, 43, 8, 70, 102, 43, 98, 96, 103, 146, 63, 119, 198, 120, 115, 216, 210, 243, 179, 245, 81, 222, 248, 106, 156, 141, 73, 77, 201, 192, 109, 141, 14, 86, 171, 231, 39, 161, 99, 209, 158, 43, 152, 48, 156, 237, 41, 205, 123, 163, 1, 174, 99, 55, 38, 3, 225, 209, 142, 40, 7, 78, 23, 217, 182, 220, 2, 120, 247, 202, 172, 59, 27, 155, 28, 90, 163, 138, 76, 32, 28, 159, 12, 192, 23, 30, 110, 181, 148, 238, 63, 85, 64, 128, 166, 121, 149, 160, 23, 118, 96, 21, 122, 255, 226, 150, 40, 103, 178, 134, 132, 182, 123, 167, 50, 134, 95, 222, 18, 229, 108, 198, 112, 99, 212, 238, 29, 155, 156, 5, 240, 253, 53, 54, 84, 127, 25, 246, 9, 4, 214, 175, 112, 104, 139, 107, 46, 20, 132, 129, 41, 179, 196, 60, 96, 108, 228, 155, 61, 107, 60, 237, 41, 140, 82, 100, 138, 66, 186, 146, 151, 67, 89, 195, 119, 142, 231, 65, 36, 212, 251, 209, 188, 132, 212, 116, 85, 18, 236, 233, 143, 139, 0, 252, 174, 34, 62, 71, 39, 131, 80, 107, 138, 82, 11, 128, 182, 213, 176, 33, 169, 33, 128, 159, 174, 143, 176, 231, 104, 30, 20, 172, 170, 120, 187, 111, 181, 199, 171, 151, 124, 80, 48, 94, 17, 204, 111, 173, 246, 160, 44, 188, 182, 45, 73, 103, 131, 189, 110, 120, 218, 240, 192, 74, 151, 29, 77, 22, 80, 207, 80, 137, 6, 79, 227, 42, 136, 42, 112, 230, 244, 153, 16, 128, 18, 155, 193, 0, 127, 237, 74, 48, 81, 18, 50, 190, 128, 8, 55, 198, 236, 207, 186, 251, 243, 161, 10, 205, 112, 255, 189, 85, 46, 178, 103, 25, 61, 67, 37, 222, 24, 177, 168, 142, 237, 74, 209, 28, 213, 76, 248, 66, 206, 192, 67, 95, 242, 56, 240, 229, 8, 253, 21, 26, 126, 176, 54, 178, 112, 34, 18, 5, 63, 255, 180, 196, 211, 237, 17, 20, 240, 236, 39, 37, 11, 79, 89, 158, 247, 159, 242, 57, 50, 211, 164, 20, 60, 126, 178, 64, 68, 131, 163, 96, 239, 201, 2, 34, 112, 100, 220, 231, 135, 107, 35, 188, 114, 209, 103, 119, 179, 67, 163, 171, 24, 200, 24, 122, 134, 138, 124, 158, 23, 86, 197, 53, 23, 239, 74, 242, 112, 171, 199, 243, 131, 69, 112, 212, 188, 137, 40, 0, 121, 48, 109, 109, 244, 102, 174, 105, 8, 92, 151, 208, 244, 109, 79, 112, 177, 32, 220, 182, 76, 115, 123, 95, 142, 254, 137, 32, 188, 127, 172, 59, 133, 163, 160, 225, 245, 105, 112, 213, 188, 42, 112, 224, 197, 138, 108, 158, 216, 153, 248, 226, 61, 88, 224, 79, 91, 227, 180, 189, 157, 97, 115, 74, 115, 104, 44, 160, 127, 78, 153, 162, 160, 28, 64, 84, 171, 218, 101, 184, 247, 159, 5, 174, 248, 176, 37, 165, 121, 118, 83, 244, 11, 5, 161, 179, 209, 225, 76, 222, 240, 194, 230, 24, 142, 134, 61, 253, 121, 112, 170, 69, 172, 33, 162, 24, 47, 75, 157, 177, 92, 65, 87, 95, 22, 128, 31, 183, 69, 56, 176, 33, 90, 37, 205, 245, 214, 241, 241, 128, 67, 35, 1, 39, 38, 13, 94, 239, 52, 147, 229, 234, 255, 221, 211, 234, 17, 85, 208, 119, 37, 176, 237, 116, 177, 169, 120, 38, 148, 91, 151, 59, 124, 216, 149, 168, 12, 153, 1, 123, 79, 228, 25, 206, 203, 82, 47, 137, 186, 244, 100, 187, 211, 36, 52, 220, 255, 97, 158, 222, 138, 84, 235, 26, 131, 26, 199, 198, 3, 154, 14, 102, 152, 240, 133, 7, 90, 28, 62, 223, 157, 226, 165, 173, 113, 86, 120, 138, 168, 14, 29, 176, 169, 163, 150, 54, 254, 199, 219, 227, 36, 52, 156, 206, 25, 122, 47, 148, 107, 191, 11, 22, 72, 165, 130, 95, 108, 140, 241, 163, 54, 111, 230, 46, 138, 6, 2, 17, 130, 202, 212, 173, 21, 228, 12, 220, 249, 143, 28, 3, 19, 166, 170, 53, 183, 196, 20, 71, 182, 39, 105, 139, 219, 205, 230, 131, 25, 70, 75, 114, 245, 0, 102, 100, 122, 69, 76, 177, 171, 217, 229, 153, 142, 8, 183, 166, 106, 243, 112, 46, 47, 97, 146, 165, 92, 104, 175, 140, 106, 99, 62, 108, 122, 39, 195, 112, 65, 234, 191, 140, 150, 10, 37, 70, 64, 43, 54, 164, 53, 77, 17, 133, 8, 92, 42, 26, 118, 44, 119, 121, 170, 61, 66, 103, 186, 26, 220, 80, 78, 120, 238, 179, 18, 47, 12, 150, 170, 43, 226, 154, 0, 92, 197, 155, 0, 20, 237, 203, 172, 238, 127, 50, 101, 108, 239, 175, 147, 36, 238, 117, 125, 234, 86, 12, 125, 58, 51, 100, 106, 150, 124, 36, 254, 23, 153, 41, 93, 205, 81, 212, 105, 60, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)

    $ico = New-Object IO.MemoryStream($WindowIcon, 0, $WindowIcon.Length)
    $SyncHash.form.Icon = [System.Drawing.Icon]::FromHandle((new-object System.Drawing.Bitmap -argument $ico).GetHIcon())
    $SyncHash.form.ShowInTaskbar = $true

    # Add all of the controls to the form
    $SyncHash.form.Controls.Add($SyncHash.PictureBox)
    $SyncHash.form.Controls.Add($SyncHash.TextLabel)
    $SyncHash.form.Controls.Add($SyncHash.SaveImageButton)


    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($Host)
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('SyncHash',$SyncHash)
    $powershell = [System.Management.Automation.PowerShell]::Create()
    $powershell.Runspace = $runspace
    $powershell.AddScript({


    [string]$theIPAddress = $SyncHash.IPAddress
    [string]$thePort = $SyncHash.Port
    [byte[]]$errorImage = @(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 1, 100, 0, 0, 0, 200, 8, 2, 0, 0, 0, 80, 208, 12, 86, 0, 0, 0, 9, 112, 72, 89, 115, 0, 0, 11, 19, 0, 0, 11, 19, 1, 0, 154, 156, 24, 0, 0, 0, 4, 103, 65, 77, 65, 0, 0, 177,142, 124, 251, 81, 147, 0, 0, 0, 32, 99, 72, 82, 77, 0, 0, 122, 37, 0, 0, 128, 131, 0, 0, 249, 255, 0, 0, 128, 233, 0, 0, 117, 48, 0, 0, 234, 96, 0, 0, 58, 152, 0, 0, 23, 111, 146, 95, 197, 70, 0, 0, 31, 41, 73, 68, 65, 84, 120, 218, 236, 157, 123, 148, 92, 85, 189, 231, 191, 191, 189, 207, 57, 245, 234, 234, 238, 196, 116, 39, 157, 164, 59, 24, 242, 48, 15, 184, 4, 51, 185, 6, 112, 140, 220, 97, 221, 145, 113, 22, 220, 37, 163, 68, 71, 19, 174, 162, 132, 0, 81, 64, 188, 147, 160, 209, 89, 87, 24, 7, 103, 6, 116, 28, 81, 209, 81, 194, 194, 21, 16, 5, 212, 75, 2, 142, 232, 232, 36, 36, 225, 33, 16, 66, 36, 209, 64, 146, 78, 66, 146, 126, 87, 157, 170, 58, 231, 236, 253, 155, 63, 78, 119, 81, 233, 71, 210, 175, 36, 221, 240, 251, 172, 16, 186, 170, 79, 159, 170, 212, 233, 253, 57, 191, 253, 219, 123, 255, 54, 53, 53, 53, 65, 16, 4, 225, 84, 40, 249, 8, 4, 65, 16, 89, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 34,11, 65, 16, 4, 145, 133, 32, 8, 34, 11, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 89, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 34, 11, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 89, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 34, 11, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 89, 8, 130, 32, 178, 16, 4, 65, 16, 89, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 227, 26, 71, 62, 130, 119, 26, 196, 68, 128, 37, 40, 38, 163, 24, 204, 12, 148, 255, 0, 221, 15, 9, 0, 145, 2, 20, 179, 2, 17, 152, 1,128, 0, 34, 48, 192, 12, 146, 15, 83, 100, 33, 188, 109, 97, 2, 147, 133, 69, 65, 1, 150, 137, 225, 176, 170, 130, 202,128, 92, 66, 130, 225, 128, 8, 0, 195, 0, 69, 162, 18, 217, 162, 181, 57, 112, 73, 17, 131, 53, 216, 5, 59, 32, 134, 234, 118, 139, 32, 178, 16, 222, 126, 4, 196, 134, 193, 192, 68, 208, 194, 40, 49, 141, 157, 201, 160, 89, 214, 105, 180, 94, 45, 148, 103, 153, 136, 21, 64, 12, 163, 24, 172, 44, 40, 4, 218, 148, 61, 160, 195, 125, 166, 248, 38, 112, 16, 252, 87, 42, 181, 42, 19, 41, 120, 150, 220, 216, 44, 194, 59, 36, 38, 109, 106, 106, 146, 79, 225, 237, 24, 65, 176, 178, 100, 73, 129, 172, 101, 4, 96, 7, 220, 196, 250, 189, 97, 98, 158, 242, 230, 176, 55, 211, 184, 94, 207, 177, 17, 96, 0,75, 92, 25, 43, 168, 238, 174, 8, 20, 72, 3, 14, 43, 75, 40, 129, 95, 215, 193, 107, 8, 95, 165, 210, 11, 42, 250, 171,14, 67, 166, 20, 72, 17, 51, 148, 98, 150, 96, 67, 100, 33, 140, 183, 235, 10, 88, 16, 195, 22, 192, 117, 172, 151, 218, 196, 50, 147, 62, 31, 201, 73, 198, 50, 33, 100, 132, 52, 156, 134, 173, 0, 13, 36, 173, 50, 10, 109, 218, 188, 204, 209, 255, 113, 252, 29, 40, 28, 85, 228, 2, 14, 20, 147, 85, 108, 89, 18, 231, 34, 11, 97, 188, 96, 96, 139, 68, 83, 141,250, 123, 206, 92, 30, 165, 207, 101, 5, 70, 9, 28, 81, 220, 113, 24, 126, 4, 64, 76, 150, 152, 192, 26, 148, 178, 42, 212, 244, 6, 5, 79, 169, 210, 227, 42, 215, 236, 216, 140, 37, 85, 206, 143, 10, 34, 11, 97, 236, 117, 58, 40, 238, 2, 48, 49, 49, 124, 96, 34, 171, 43, 76, 230, 31, 76, 114, 58, 187, 17, 219, 18, 197, 205, 156, 105, 196, 253, 4, 6, 41, 102, 80, 247, 104, 136, 98, 114, 8, 30, 240, 134, 226, 95, 170, 174, 159, 185, 126, 7, 83, 26, 220, 243, 90, 34, 13, 145, 133, 48, 198, 58, 29, 12, 6, 40, 0, 136, 233, 82, 235, 94, 99, 178, 115, 172, 91, 2, 162, 145, 197, 17, 131, 199, 3, 28, 82, 127, 65, 244, 35, 183, 227, 183, 84, 176, 228, 122, 176, 114, 105, 68, 22, 194, 152, 139, 45, 44, 81, 192, 166, 145,189, 107, 77, 213, 223, 71, 105, 102, 10, 96, 1, 140, 66, 44, 49, 232, 238, 9, 0, 143, 24, 112, 158, 86, 254, 189, 94, 251, 62, 216, 148, 12, 151, 188, 141, 208, 53, 53, 53, 242, 41, 140, 223, 128, 2, 196, 32, 68, 80, 1, 241, 135, 108, 106, 189, 153, 240, 175, 162, 68, 94, 89, 3, 3, 2, 232, 12, 166, 15, 136, 137, 56, 132, 50, 20, 205, 101, 231, 210, 40, 219, 6, 126, 69, 151, 28, 128, 164, 51, 34, 178, 16, 206, 122, 64, 161, 64, 37, 40, 23, 246, 166, 168, 118, 117, 148, 205, 88, 20, 226, 91, 124, 172, 138, 51, 154, 51, 136, 39, 119, 2, 160, 144, 145, 82, 252, 1, 78, 76, 180, 234, 89, 101, 75, 42, 114, 196, 23, 34, 11, 225, 236, 70, 22, 69, 168, 9, 176, 95, 13, 39, 94, 17, 37, 139, 96, 195, 10, 196, 103, 253, 93, 49, 49, 49, 89, 240, 133, 72, 206, 102, 181, 131, 130, 156, 98, 87, 124, 33, 178, 16, 206, 116, 56, 17, 223, 192, 137,11, 132, 58, 208, 55, 130, 186, 247, 217, 68, 46, 30, 123, 160, 49, 51, 43, 138, 148, 37, 50, 204, 115, 109, 226, 111, 108, 106, 187, 42, 181, 40, 118, 229, 226, 137, 44, 132, 51, 137, 2, 8, 170, 8, 52, 178, 254, 70, 56, 233, 124, 171, 115, 96, 26, 75, 43, 53, 168, 162, 7, 84, 34, 158, 6, 125, 1, 59, 207, 81, 216, 6, 227, 74, 198, 83, 100, 33, 156, 185, 166, 200, 40, 40, 76, 183, 124, 103, 84, 63, 143, 181, 15, 139, 177, 61, 232, 80, 34, 158, 206, 250, 66, 155, 122, 70, 23, 218, 136, 37, 127, 33, 178, 16, 206, 136, 39, 128, 64, 81, 13, 227, 235, 97, 221, 249, 86, 229, 65, 0, 169, 177, 189, 0,148, 128, 16, 152, 66, 188, 192, 36, 255, 160, 139, 121, 5, 45, 186, 16, 89, 8, 167, 55, 89, 1, 178, 208, 4, 179, 190, 52, 241, 125, 240, 252, 113, 245, 238, 67, 80, 19, 220, 6, 56, 255, 151, 2, 75, 86, 73, 124, 33, 178, 16, 78, 87, 170, 130, 137, 73, 21, 17, 126, 218, 212, 126, 212, 164, 139, 28, 1, 122, 124, 181, 184, 16, 118, 30, 187, 17, 225, 25, 85, 112, 161, 196, 22, 34, 11, 225, 244, 196, 21, 138, 114, 42, 124, 191, 73, 221, 22, 77, 8, 96, 153, 148, 81, 60, 222, 230, 59, 81, 8, 92, 104, 19, 111, 144, 217, 75, 129, 30, 127, 239, 255, 157, 125, 187, 146, 143, 96, 188, 16, 177, 157, 108, 188, 155, 162, 26, 215, 90, 11, 48, 160, 120, 156, 181, 52, 6, 49, 88, 179, 253, 66, 88, 219, 0, 29, 89, 87, 202, 109, 137, 44, 132, 209, 79, 87, 132, 176, 255, 24, 85, 205, 182, 78, 97, 220, 222, 140, 9, 0, 116, 145, 184, 1, 88, 17, 101, 35, 50, 86, 70, 82, 69, 22, 194, 40, 54, 49, 2, 138, 68, 239, 181, 137, 43, 77, 198, 31, 236, 82, 78, 238, 254, 175, 123,222, 55, 245, 250, 22, 96, 135, 85, 254, 38, 174, 103, 1, 238, 46, 216, 75, 12, 210, 67, 88, 250, 30, 207, 7, 81, 69, 230, 15, 155, 204, 251, 140, 91, 148, 149, 169, 227, 7, 169, 193, 57, 14, 238, 198, 33, 193, 179, 209, 181, 225, 187, 28,112, 97, 176, 203, 61, 136, 201, 170, 200, 218, 66, 80, 217, 89, 33, 38, 74, 56, 228, 122, 22, 195, 25, 142, 96, 128, 21, 107, 107, 217, 15, 12, 108, 124, 130, 128, 88, 91, 5, 237, 32, 237, 158, 178, 87, 17, 151, 238, 51, 68, 41, 216, 79, 154, 154, 63, 169, 227, 150, 228, 150, 37, 178, 16, 70, 169, 11, 18, 192, 254, 91, 206, 44, 98, 55, 100, 3, 162, 193, 244, 243, 25, 80, 17, 71, 117, 245, 118, 209, 108, 182, 21, 119, 111, 215, 209, 127, 218, 67, 251, 15, 169, 164, 55, 60, 115, 81, 196, 17, 91, 254, 187, 37, 54, 147, 130, 181, 113, 38, 34, 210, 154, 142, 181, 186, 47, 236, 166, 193, 14, 113, 112, 145, 233, 111, 141, 123, 169, 147, 248, 23, 85, 76, 177, 116, 70, 68, 22, 194, 136, 49, 224, 106, 171, 174, 142, 178, 68, 214, 116, 239, 217, 129, 83, 134, 23, 138, 97, 10, 37, 103, 241, 252, 57, 27, 254, 123, 175, 214, 222, 185, 107, 207, 193, 43, 87, 209, 225, 163, 72, 39, 57, 238, 143, 196, 11, 221, 79, 101, 31, 2, 145, 49, 145, 239, 103, 214, 173, 158, 190, 110, 181, 62, 241, 180, 237, 127, 120, 238, 224, 191, 255, 180, 227, 13, 182, 226, 55, 19, 12, 120, 121, 84, 245, 59, 21, 68, 100, 92, 171, 45, 73, 178, 83, 114, 22, 194, 8, 40, 130, 222, 199, 137, 133, 86, 151, 248, 173, 187, 251,32, 34, 11, 98, 2, 51, 83, 69, 210, 34, 254, 177, 234, 249, 179, 167, 111, 188, 219, 54, 212, 69, 197, 130, 2, 1, 106, 80, 219, 5, 17, 148, 9, 162, 66, 161, 106, 221, 245, 141, 235, 86, 83, 188, 3, 73, 197, 91, 33, 107, 134, 56, 178, 193, 1, 120, 174, 117, 63, 104, 146, 161, 213, 70, 76, 33, 178, 16, 70, 212, 3, 1, 18, 192, 191, 51, 105, 30, 250, 24, 227, 64, 133, 121, 45, 56, 187, 104, 97, 195, 198, 111, 217, 41, 83, 194, 66, 97, 144, 39, 35, 99, 131, 66, 41, 179, 118, 213,244, 117, 55, 0, 80, 92, 81, 85, 135, 135, 255, 175, 83, 140, 203, 108, 210, 33, 43, 19, 46, 68, 22, 194, 48, 137, 135,42, 2, 50, 179, 88, 47, 178, 233, 96, 168, 163, 6, 113, 141, 44, 30, 72, 34, 168, 93, 180, 160, 241, 167, 119, 211, 148, 58, 202, 23, 123, 154, 169, 237, 187, 116, 149, 187, 77, 97, 76, 206, 175, 90, 123, 125, 227, 186, 27, 20, 160, 193, 68, 163, 243, 155, 83, 32, 126, 111, 228, 189, 7, 110, 81, 92, 33, 178, 16, 134, 121, 215, 37, 82, 76, 17, 233, 101, 38, 85, 101, 141, 5, 134, 179, 183, 104, 127, 233, 3, 234, 121, 182, 246, 194, 5, 141, 27, 239, 193, 140, 169, 81, 161, 160,64, 220, 111, 127, 132, 136, 76, 96, 130, 160, 250, 107, 55, 53, 174, 187, 161, 103, 236, 115, 212, 90, 182, 5, 210, 164, 150, 154, 68, 4, 35, 23, 93, 100, 33, 12, 211, 22, 17, 153, 90, 67, 75, 57, 17, 18, 3, 74, 13, 49, 218, 63, 101, 131,54, 204, 217, 69, 11, 27, 30, 249, 14, 157, 51, 35, 244, 125, 234, 167, 36, 6, 145, 49, 129, 95, 204, 254, 231, 53, 211, 110, 187, 142, 153, 79, 232, 125, 244, 121, 195, 195, 251, 135, 150, 192, 127, 23, 165, 39, 89, 71, 108, 33, 178, 16, 134, 231, 10, 68, 160, 115, 216, 109, 178, 142, 97, 194, 16, 235, 116, 51, 24, 73, 55, 218, 246, 114, 235, 214, 63, 1, 176, 204, 220, 71, 5, 138, 192, 64, 245, 123, 206, 157, 118, 255, 127, 85, 147, 235, 85, 174, 168, 187, 51, 163, 61, 27, 166, 27, 99, 243, 133, 154, 181, 215, 79, 253, 252, 167, 21, 224, 16, 83, 101, 168, 194, 241, 102, 234, 204, 132, 168, 84, 108, 189, 239, 65, 141, 33, 23, 214, 32, 192, 50, 154, 172, 106, 98, 199, 202, 230, 135, 34, 11, 97, 56, 57, 11, 112,4, 204, 130, 83, 101, 149, 161, 33, 231, 55, 9, 164, 181, 71, 199, 143, 55, 127, 226, 166, 206, 231, 94, 86, 212, 207, 24, 74, 185, 63, 82, 115, 193, 252, 105, 15, 223, 19, 53, 76, 10, 139, 5, 205, 0, 19, 1, 202, 4, 145, 95, 200, 220, 190,106, 250, 237, 55, 198, 179, 177, 186, 107, 116, 85, 70, 18, 12, 16, 113, 24, 28, 88, 253, 213, 252, 207, 54, 211, 208,231, 110, 16, 96, 1, 23, 234, 189, 214, 13, 201, 142, 32, 64, 17, 68, 22, 239, 216, 200, 2, 172, 64, 11, 172, 195, 52, 188, 9, 209, 198, 130, 149, 231, 185, 199, 219, 15, 93, 189, 166, 227, 133, 87, 232, 164, 253, 145, 234, 69, 11, 167, 62, 244, 45, 212, 79, 142, 10, 5, 34, 192, 216, 146, 95, 204, 174, 187, 126, 218, 218, 27, 108, 175, 177, 143, 202, 110, 14, 33, 140, 162, 125, 171, 191, 154, 127, 224, 81, 183, 58, 51, 108, 45, 90, 194, 133, 236, 57, 10, 150, 152, 196, 22, 34, 11, 97, 136, 178, 192, 4, 168, 191, 49, 201, 104, 152, 45, 176, 103, 184, 34, 157, 140, 142, 30, 59, 112, 245, 231, 59, 182, 191, 4, 192, 98, 192, 254, 72, 237, 162, 133, 83, 31, 186, 91, 205, 152, 70, 29, 93, 38, 8, 107, 190, 186, 38, 158, 121, 229, 176, 165, 19, 59, 23, 140, 238, 179, 24, 223, 63, 248, 217, 47, 23, 239, 127, 212, 169, 206, 242, 176, 198, 71, 184, 103, 118, 214, 20, 171, 171, 141, 102, 38, 89, 135, 42, 178, 16, 134, 70, 4, 76, 100, 85, 11, 50, 195, 26, 122, 224, 242, 176, 41, 147, 151, 76, 211, 145, 163, 205, 31, 189, 161, 107, 235, 243, 10, 39, 235, 143, 76, 88, 180, 112,250, 195, 223, 10, 230, 206, 172, 249, 218, 141, 141, 183, 93, 199, 204, 4, 6, 189, 213, 251, 224, 242, 2, 53, 130, 45,248, 7, 62, 179, 214, 127, 240, 23, 78, 77, 102, 144, 147, 208, 7, 12, 109, 192, 19, 225, 212, 147, 27, 72, 253, 44, 145, 133, 48, 84, 44, 104, 34, 83, 149, 101, 30, 105, 218, 207, 88, 176, 147, 74, 232, 214, 246, 230, 229, 107, 58, 183, 190, 64, 61, 205, 190, 159, 23, 181, 156, 153, 55, 123, 198, 230, 255, 61, 121, 245, 10, 3, 214, 125, 70, 73, 169, 103, 43, 161, 176, 80, 220, 247, 153, 117, 254, 207, 55, 187, 213, 217, 145, 143, 164, 50, 144, 97, 52, 26, 135, 108, 63, 129,143, 32, 178, 16, 78, 33, 139, 169, 76, 138, 148, 29, 89, 75, 140, 103, 70, 50, 3, 169, 164, 105, 239, 56, 240, 241, 155, 219, 183, 190, 0, 128, 97, 251, 54, 203, 120, 25, 88, 245, 228, 122, 199, 117, 29, 224, 132, 153, 87, 229, 177, 15, 32, 10, 131, 131, 215, 174, 45, 61, 178, 89, 215, 100, 121, 52, 10, 82, 48, 160, 64, 19, 135, 155, 158, 17, 68, 22, 239, 240, 164, 5, 55, 192, 165, 81, 104, 135, 229, 30, 4, 185, 137, 20, 90, 91, 15, 127, 226, 11, 157, 207, 191, 172, 78, 28,218, 168, 12, 28, 208, 61, 0, 74, 189, 50, 11, 196, 0, 145, 13, 131, 131, 171, 190, 226, 63, 178, 73, 215, 100, 70, 241, 159, 75, 224, 218, 56, 97, 33, 253, 16, 145, 133, 48, 180, 11, 67, 220, 96, 157, 81, 92, 93, 197, 100, 13, 216, 73, 38, 212, 177, 214, 67, 31, 187, 169, 99, 251, 139, 52, 132, 150, 28, 111, 74, 136, 192, 47, 236, 91, 245, 229, 252, 3, 143, 121, 217, 204, 168, 239, 163, 58, 145, 181, 130, 140, 157, 138, 44, 132, 161, 95, 153, 26, 16, 143, 94, 9, 108, 226, 158, 36, 100, 58, 105, 142, 30, 63, 244, 31, 214, 116, 60, 243, 39, 0, 102, 208, 115, 161, 34, 191, 216, 252, 153, 127, 42, 110, 120, 76, 215, 100, 79, 71, 57, 188, 90, 34, 197, 242, 11, 41, 178, 16, 134, 216, 135, 119, 44, 92, 134, 37, 182,167, 225, 228, 110, 34, 205, 237, 109, 7, 151, 175, 105, 223, 246, 156, 86, 131, 218, 32, 53, 40, 228, 222, 184, 246, 182, 226, 207, 159, 114, 106, 179, 167, 167, 215, 133, 4, 20, 8, 146, 224, 20, 89, 8, 67, 237, 195, 147, 6, 197, 171, 187, 70, 27, 107, 136, 85, 50, 225, 30, 61, 126, 224, 99, 55, 119, 54, 31, 30, 76, 127, 162, 249, 214, 111, 250, 15, 254, 82, 213, 100, 227, 132, 198, 233, 216, 90, 213, 225, 19, 51, 37, 130, 200, 66, 24, 92, 138, 225, 116, 229, 250, 24, 138, 64, 100, 108, 100, 145, 189, 230, 31, 146, 13, 117, 131, 105, 247, 181, 159, 186, 210, 153, 253, 110, 228, 11, 232, 158,145, 53, 218, 169, 133, 183, 138, 99, 136, 46, 68, 22, 194, 16, 195, 242, 144, 186, 211, 138, 163, 29, 180, 144, 138, 74, 97, 80, 202, 126, 237, 198, 166, 245, 159, 87, 74, 15, 166, 175, 51, 225, 111, 47, 104, 220, 248, 109, 156, 51, 213, 248, 5, 162, 184, 190, 214, 168, 190, 41, 70, 65, 89, 150, 200, 66, 100, 33, 12, 245, 46, 107, 193, 5, 142, 8, 163, 95, 109, 142, 162, 40, 8, 205, 132, 59, 110, 157, 118, 219, 117, 150, 89, 3, 24, 196, 76, 109, 203, 156, 93, 180, 96, 218, 207, 190, 67, 231, 204, 136, 124, 31, 163, 91, 214, 2, 32, 34, 159, 35, 73, 88, 136, 44, 132, 161, 231, 21, 128, 22, 194,40, 46, 171, 234, 169, 121, 101, 109, 49, 168, 253, 250, 173, 13, 55, 172, 32, 192, 33, 12, 178, 158, 157, 34, 2, 144, 125, 207, 185, 141, 15, 221, 173, 223, 221, 72, 93, 197, 120, 193, 40, 143, 218, 198, 31, 220, 198, 96, 176, 140, 156, 138, 44, 132, 33, 55, 158, 3, 202, 140, 234, 170, 42, 82, 38, 8, 125, 191, 106, 237, 117, 211, 110, 92, 97, 193, 196, 118, 24, 193, 65, 118, 222, 172, 233, 27, 239, 49, 77, 147, 77, 177, 160, 65, 163, 181, 233, 7, 3, 199, 149, 97, 144, 20, 238, 21, 89, 8, 67, 110, 62, 251, 85, 100, 71, 77, 22, 68, 198, 148, 252, 82, 213, 237, 215, 79, 91, 187, 250, 228, 189, 143, 242, 106, 20, 30, 160, 63, 82, 53, 111, 246, 212, 7, 239, 182, 147, 27, 66, 223, 239, 46, 106, 49, 26, 145, 84, 171, 178, 18, 86, 136, 44, 132, 161, 95, 24, 82, 237, 108, 66, 30, 233, 44, 165, 184, 249, 81, 20, 217, 82, 80, 187, 254, 166, 198, 181, 55, 40, 64, 159, 216, 251, 96, 112, 121, 213, 121, 254, 88, 203, 158, 85, 183, 183, 254, 97, 59, 0, 238, 47, 241, 25, 247, 71, 106, 23, 45, 152, 177, 241, 127, 56, 77, 211, 144, 47, 18, 129, 57, 110, 239, 195, 53, 25, 80, 34, 188, 73, 172, 187, 31, 9, 34, 11, 97, 208, 104, 198, 49, 197, 237, 164, 70, 120, 133, 136, 137, 162, 32, 10, 130, 154, 255, 114, 243, 244, 47, 93, 199, 28, 155, 161, 87, 125, 10, 138, 199, 33, 138, 109, 29, 205, 215, 220, 86, 250, 222, 79, 15, 175, 184, 181, 243, 153, 231, 212, 73, 19, 159, 213, 139, 22, 76, 123, 228, 127, 154, 119, 79, 139, 252, 130, 34, 226, 17, 252, 46, 105, 160, 29, 230, 0, 25, 103, 192, 128, 70, 16, 89, 8, 3, 70, 22, 232, 176, 118, 143, 46, 57, 35, 188, 211, 26, 19, 6, 166, 246, 206, 91, 27, 86, 175, 180, 204, 186, 87, 29, 77, 116, 239, 24, 160, 8, 126, 71, 215, 129, 79, 222, 106, 127, 179, 213, 173, 159, 228, 28, 239, 56, 184, 252, 11, 173, 91, 95, 56, 217, 137, 153, 171, 222, 51, 107, 250, 67, 223, 214, 51, 206, 137, 252, 188, 26, 65, 35, 215, 76, 173, 48, 185, 110, 223, 136, 44, 68, 22, 194, 208, 34, 2, 85, 36, 251, 18, 21, 157, 97, 182, 29, 38, 88, 101, 108, 84, 40, 76, 248, 250, 45, 241, 216, 135, 38, 84, 230, 35, 227, 126, 71, 60, 107, 50, 242, 253, 67, 215, 221, 30, 254, 230, 143, 168, 201, 0, 224, 84, 130, 91, 219, 155, 63, 113, 75, 219, 51, 47, 0, 232, 55, 117, 18, 247, 71, 170, 231, 205, 154, 250, 208, 127, 211, 231, 52, 193, 47, 14, 87, 107, 172, 20, 191, 170, 77, 129, 34, 98, 146, 110, 136, 200, 66, 24, 106, 91, 103, 34, 236, 85, 54, 196, 112, 214, 108, 17, 147, 5, 2, 27, 101, 215, 174, 158, 114, 211, 74, 27, 187, 161, 87, 59, 164, 238, 42, 21, 166, 80, 56, 240, 153, 181, 193, 163, 79, 234, 154, 183, 42, 217, 184, 137, 164, 106, 109, 57, 188, 124, 77, 199, 51, 207, 245, 91, 191, 170, 92, 68, 167, 102,222, 156, 105, 27, 239, 177, 211, 27, 16, 12, 185, 6, 32, 199, 91, 27, 89, 181, 69, 21, 100, 193, 169, 200, 66, 24, 14,142, 133, 11, 188, 134, 240, 136, 50, 195, 232, 137, 88, 130, 202, 135, 250, 226, 197, 13, 235, 174, 39, 64, 159, 88, 71, 147, 123, 134, 48, 136, 16, 249, 197, 3, 215, 127, 213, 127, 100, 179, 147, 173, 170, 56, 192, 26, 130, 78, 36, 116, 75, 199, 161, 229, 95, 104, 223, 242, 124, 79, 247, 128, 251, 42, 195, 2, 85, 243, 103, 79, 250, 231, 91, 76, 100, 192, 67, 174, 66, 238, 89, 180, 17, 255, 133, 172, 43, 49, 133, 200, 66, 24, 94, 100, 161, 161, 142, 234, 232, 101, 93, 114, 187, 55, 34, 164, 33, 53, 194, 8, 134, 38, 84, 123, 113, 1, 255, 138, 84, 37, 87, 124, 17, 21, 252, 253, 215, 254, 83, 225, 193, 199, 157, 218, 19, 106, 94, 17, 148, 138, 157, 146, 74, 216, 182, 142, 131, 31, 191, 165, 99, 235, 243, 4, 152,254, 92, 16, 207, 140, 240, 234, 39, 241, 176, 214, 211, 123, 160, 173, 186, 120, 152, 66, 45, 178, 16, 89, 8, 195, 192, 18, 64, 32, 214, 79, 146, 31, 117, 175, 174, 26, 202, 77, 59, 254, 9, 107, 7, 250, 110, 119, 239, 227, 211, 107, 139, 143, 108, 82, 181, 85, 253, 118, 16, 226, 57, 20, 174, 151, 84, 109, 45, 135, 150, 127, 190, 235, 153, 231, 244, 73, 198, 71, 134, 188, 139, 122, 57, 183, 226, 252, 81, 23, 172, 228, 42, 68, 22, 194, 240, 67, 11, 176, 199, 252, 146, 138, 94, 87, 236, 64, 13, 73, 22, 221, 21, 234, 6, 216, 24, 153, 8, 38, 95, 120, 253, 51, 235, 242, 63, 223, 236, 156, 162, 226, 174, 53, 196, 58, 153, 84, 173, 237, 7, 175, 254, 66, 199, 214, 231, 49, 26, 195, 21, 229, 215, 75, 0, 175, 186, 193, 179, 170, 152, 148, 124, 133, 200, 66, 24, 118, 115, 34, 6, 17, 90, 201, 254, 134, 124, 143, 236, 144, 46, 150, 102, 156, 80, 244, 63, 158, 94, 209, 83, 58, 59, 242, 253, 253, 159, 253, 79, 193, 35, 155, 156, 83, 85, 220, 141, 251, 35, 22, 224, 84, 210, 182, 119, 52, 47, 191, 165, 99, 235, 11, 113, 158, 226, 173, 115, 118, 103, 51, 134, 184, 187, 34, 0, 134,38, 254, 127, 92, 104, 3, 43, 153, 230, 45, 178, 16, 70, 72, 2, 180, 201, 241, 223, 228, 184, 48, 255, 96, 49, 202, 40,70, 92, 212, 18, 0, 136, 122, 254, 32, 200, 229, 246, 255, 227, 63, 21, 31, 217, 172, 6, 87, 113, 183, 178, 63, 130, 182, 150, 230, 143, 175, 105, 255, 195, 14, 85, 113, 206, 238, 212, 169, 51, 164, 4, 165, 2, 200, 33, 28, 103, 60, 238, 228, 28, 146, 223, 195, 113, 128, 35, 31, 193, 24, 199, 101, 188, 161, 194, 71, 93, 255, 186, 48, 155, 3, 211, 224, 238, 224, 202, 42, 118, 29, 123, 224, 208, 155, 63, 251, 23, 68, 209, 91, 158, 73, 184, 185, 159, 61, 81, 120, 244, 55, 110, 117, 213, 208, 202, 204, 144, 53, 208, 58, 153, 68, 75, 251, 155, 255, 241, 22, 255, 246, 85, 186, 166, 26, 198, 116, 251, 36, 225, 21, 95, 218, 173, 148, 26, 244, 56, 47, 3, 240, 88, 63, 230, 181, 55, 19, 210, 146, 177, 24, 23, 209, 110, 83, 83, 147, 124, 10, 99, 252, 26, 133, 100, 234, 141, 115, 111, 56, 169, 206, 170, 144, 12, 13, 178, 240, 12, 1, 145, 49,133, 210, 137, 141, 148, 149, 235, 80, 50, 49, 162, 119, 100, 250, 156, 22, 32, 173, 85, 106, 176, 167, 101, 192, 99, 180, 42, 190, 214, 59, 122, 148, 224, 202, 69, 150, 200, 66, 24, 13, 216, 101, 125, 80, 219, 7, 109, 254, 86, 100, 141, 85, 145, 26, 156, 45, 24, 208, 90, 87, 165, 71, 255, 29, 141, 248, 180, 10, 240, 72, 255, 84, 183, 30, 36, 206, 72, 80, 33, 57, 11, 97, 180, 100, 1, 112, 138, 241, 75, 199, 127, 137, 66, 151, 198, 117, 42, 176, 123, 167, 212, 4, 212, 139, 42, 124, 196, 45, 166, 101, 16, 68, 100, 33, 140, 98, 55, 36, 190, 78, 57, 178, 223, 118, 58, 139, 100, 157, 241, 124, 43,102, 64, 145, 53, 204, 247, 57, 93, 5, 24, 18, 87, 140, 31, 116, 77, 77, 141, 124, 10, 227, 2, 143, 245, 1, 138, 136, 232, 253, 198, 43, 141, 215, 54, 70, 138, 41, 13, 253, 128, 147, 123, 216, 201, 165, 160, 53, 88, 202, 121, 75, 100, 33, 140, 246, 61, 153, 216, 83, 120, 72, 229, 254, 168, 195, 244, 233, 216, 78, 228, 180, 246, 61, 122, 102, 125, 36, 9, 207, 82, 248, 3, 175, 43, 1, 34, 64, 118, 66, 22, 89, 8, 167, 165, 209, 105, 166, 2, 241, 93, 110, 107, 179, 178, 169, 209,172, 230, 123, 186, 251, 81, 4, 16, 177, 77, 0, 71, 200, 222, 233, 181, 149, 152, 123, 86, 130, 72, 88, 33, 178, 16, 78, 15, 9, 208, 235, 100, 239, 116, 142, 231, 225, 56, 227, 164, 161, 49, 192, 48, 46, 193, 39, 125, 135, 211, 246, 87, 101, 83, 113, 1, 61, 65, 114, 22, 194, 105, 197, 5, 253, 85, 153, 35, 42, 120, 191, 73, 123, 64, 52, 232, 114, 254, 103, 39, 170, 0, 17, 216, 3, 12, 156, 59, 221, 227, 191, 213, 97, 134, 164, 222, 191, 200, 66, 56, 83, 183, 106, 15, 206, 110,42, 30, 38, 115, 9, 167, 29, 102, 139, 177, 185, 149, 23, 129, 137, 96, 93, 130, 133, 186, 195, 109, 253, 149, 83, 172,138, 231, 156, 11, 34, 11, 225, 76, 221, 174, 225, 194, 121, 217, 9, 15, 81, 244, 126, 147, 244, 160, 205, 216, 43, 93,105, 137, 20, 91, 151, 0, 118, 239, 76, 180, 61, 174, 75, 25, 104, 146, 18, 155, 34, 11, 225, 76, 166, 0, 8, 0, 108, 210, 234, 93, 170, 116, 128, 130, 165, 54, 149, 134, 10, 81, 222, 55, 96, 76, 220, 186, 9, 72, 65, 117, 42, 186, 195, 109,249, 149, 46, 100, 89, 177, 178, 18, 86, 136, 44, 132, 51, 27, 87, 196, 255, 39, 120, 160, 221, 58, 218, 73, 225, 66, 120, 13, 140, 2, 145, 102, 16, 250, 212, 240, 62, 195, 111, 143, 137, 9, 89, 168, 125, 218, 124, 197, 105, 249, 131, 50, 105, 138, 51, 43, 98, 10, 145, 133, 112, 118, 66, 12, 86, 32, 143, 212, 126, 101, 182, 80, 169, 6, 206, 124, 235, 17, 81, 72, 172, 207, 94, 18, 131, 9, 30, 224, 193, 121, 210, 41, 126, 205, 105, 125, 77, 113, 134, 100, 85, 169, 200, 66, 56,171, 40, 192, 18, 136, 201, 3, 117, 144, 121, 90, 23, 142, 42, 123, 158, 73, 212, 2, 129, 98, 197, 103, 40, 190, 224, 158, 153, 20, 113, 180, 147, 97, 213, 65, 184, 219, 107, 255, 95, 186, 163, 64, 148, 130, 148, 181, 17, 89, 8, 99, 160, 71, 82, 14, 236, 53, 72, 131, 94, 162, 104, 155, 202, 191, 11, 122, 150, 73, 105, 178, 17, 206, 68, 228, 95, 222, 19, 192, 3, 52, 233, 223, 57, 197, 127, 118, 91, 255, 72, 161, 171, 148, 44, 106, 22, 89, 8, 99, 52, 151, 225, 18, 31, 35, 250,189, 42, 237, 81, 254, 20, 74, 52, 90, 173, 232, 180, 79, 169, 38, 134, 167, 144, 96, 103, 183, 19, 220, 163, 219, 126,168, 253, 86, 178, 73, 146, 234, 87, 34, 11, 97, 76, 119, 76, 148, 11, 102, 133, 189, 100, 158, 82, 133, 131, 202, 76, 100, 61, 149, 28, 183, 187, 81, 199, 78, 97, 30, 86, 174, 145, 123, 220, 80, 254, 73, 7, 72, 64, 43, 82, 175, 145, 185, 207, 109, 255, 142, 234, 220, 233, 112, 18, 236, 118, 239, 23, 36, 3, 165, 111, 175, 187, 145, 84, 202, 122, 123, 94, 87, 134, 33, 4, 108, 147, 164, 254, 181, 73, 254, 155, 40, 185, 0, 110, 29, 187, 0, 135, 204, 17, 197, 229, 249, 104, 168,231, 140, 165, 161, 136, 60, 40, 0, 45, 48, 187, 80, 122, 202, 45, 254, 81, 7, 29, 100, 146, 80, 90, 228, 32, 178, 16, 198, 163, 47, 152, 192, 48, 62, 41, 151, 121, 50, 212, 165, 81, 230, 66, 235, 204, 162, 196, 20, 227, 56, 140, 136, 56, 130, 181, 61, 27, 148, 157, 164, 119, 19, 255, 241, 152, 226, 28, 201, 81, 197, 187, 80, 124, 65, 5, 79, 59, 133, 55, 153, 13, 33, 193, 10, 202, 146, 204, 226, 22, 89, 8, 227, 14, 166, 238, 64, 128, 152, 172, 98, 101, 97, 64, 5, 101, 52, 208, 104, 156, 121, 156, 104, 132, 51, 159, 188, 185, 129, 83, 197, 112, 20, 185, 241, 144, 6, 43, 6, 152, 160, 216, 18, 200, 18, 136, 109, 8, 148, 192, 62, 104, 175, 99, 94, 161, 210, 65, 54, 187, 85, 233, 175, 58, 52, 68, 73, 75, 58, 30, 148, 193, 16, 247, 53, 17, 198, 33, 146, 174, 126, 219, 134, 21, 61, 214, 224, 56, 196, 80, 224, 12, 43, 6, 14, 41, 251, 58, 229, 149, 69, 154, 117, 85, 82, 213, 50, 85, 1, 117, 86, 215, 177, 174, 1, 121, 172, 92, 82, 1, 108, 137, 184, 85, 69, 109, 140, 118, 152, 78, 226, 118, 112, 23, 71, 121, 101, 153, 148, 203, 148, 98, 85, 118, 67, 121, 175, 0, 65, 100, 33, 188, 141, 36, 2, 184, 128, 103, 149, 37, 24, 197, 45, 48, 199, 136, 137, 201, 234, 144, 226, 250, 152, 241, 108, 9, 38, 196, 91, 40, 42, 171, 153, 20, 136, 200, 106, 168, 52, 59, 204, 162, 5, 145, 133, 240, 142, 9, 58, 172, 2, 49, 244, 91, 59, 171, 51, 0, 69, 244, 86, 202, 147, 98, 103, 32, 94, 110, 194, 0, 134, 183, 235, 177, 32, 178, 16, 222, 6, 233, 140, 138, 132, 100, 223, 109, 151, 185, 207, 51, 61, 59, 14, 10, 239, 84, 100, 226, 140, 32, 8, 34, 11, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 24, 139, 72, 130, 115, 156, 193, 204, 214, 246, 191, 52, 76, 107, 13, 192, 116, 239, 108, 126, 2, 68, 164, 148, 58, 229, 73, 122, 29, 118, 146, 227, 149, 82, 149, 203, 223, 7, 58, 97, 175, 195, 4, 145, 133, 112, 230, 112, 93, 55, 150, 66, 95, 130, 32, 0, 144, 78, 247, 179, 101, 113, 24, 134, 185, 92, 206, 117, 93, 207, 243, 152, 89, 41,149, 76, 38, 251, 61, 172, 171, 171, 203, 243, 188, 248, 48, 0, 214, 218, 66, 161, 144, 74, 165, 82, 169, 212, 91, 3, 173, 204, 249, 124, 62, 12, 195, 242, 147, 142, 227, 56, 78, 63, 191, 75, 197, 98, 49, 151, 203, 165, 82, 169, 129, 222, 179, 32, 178, 16, 78, 11, 249, 124, 254, 75, 95, 250, 210, 202, 149, 43, 243, 249, 124, 175, 152, 34, 159, 207, 127, 236, 99, 31, 203, 100, 50, 247, 223, 127, 191, 231, 121, 189, 238, 243, 97, 24, 110, 223, 190, 253, 174, 187, 238, 122, 243, 205, 55, 153, 249, 130, 11, 46, 248, 222, 247, 190, 23, 55, 251, 202, 232, 32, 138, 162, 45, 91, 182, 124, 243, 155, 223, 108, 105, 105, 113, 93, 215, 24, 67, 68, 171, 87, 175, 190, 234, 170, 171, 170, 170, 170, 202, 178, 176, 214, 30, 63, 126, 252, 190, 251, 238, 123, 236, 177, 199, 18, 137, 132, 239, 251, 203, 151, 47, 255, 242, 151, 191, 236, 251, 126, 175, 120, 36, 159, 207, 63, 254, 248, 227, 223, 255, 254, 247, 163, 40, 18, 95, 136, 44, 132, 51, 135, 181, 246, 93, 239, 122, 87, 93, 93, 93, 93, 93, 93, 175, 111, 249, 190, 239, 56, 142, 235, 186, 231, 156, 115, 78, 191, 55, 249, 217, 179, 103, 159, 127, 254, 249, 87, 93, 117, 213, 177, 99, 199, 18, 137, 196, 140, 25, 51, 250, 125, 137, 217, 179, 103, 207,153, 51, 231, 163, 31, 253, 168, 181, 54, 138, 162, 59, 239, 188, 243, 154, 107, 174, 233, 123, 216, 204, 153, 51, 151,44, 89, 82, 87, 87, 119, 239, 189, 247, 50, 115, 117, 117, 117, 125, 125, 125, 191, 39, 92, 184, 112, 97, 99, 99, 227, 205, 55, 223, 220, 111, 200, 35, 140, 35, 36, 193, 57, 254, 114, 22, 39, 249, 214, 201, 231, 98, 159, 119, 222, 121, 151, 95, 126, 121, 177, 88, 60, 249, 75, 44, 93, 186, 244, 242, 203, 47, 111, 111, 111, 95, 176, 96, 193, 39, 63, 249, 201,147, 28, 249, 185, 207, 125, 110, 202, 148, 41, 81, 20, 157, 252, 132, 203, 151, 47, 95, 188, 120, 241, 41, 95, 87, 144, 200, 66, 56, 45, 28, 59, 118, 236, 139, 95, 252, 98, 161, 80, 136, 147, 136, 198, 152, 150, 150, 150, 218, 218, 218, 242, 1, 247, 222, 123, 239, 19, 79, 60, 145, 72, 36, 62, 252, 225, 15, 127, 234, 83, 159, 138, 159, 92, 182, 108, 217, 15, 126, 240, 131, 74, 167, 124, 247, 187, 223, 221, 180, 105, 83, 42, 149, 186, 242, 202, 43, 175, 190, 250, 234, 248, 201, 37, 75, 150, 252, 248, 199, 63, 158, 51, 103, 78, 57, 72, 249, 245, 175, 127, 189, 97, 195, 6, 107, 109, 38, 147, 89,181, 106, 213, 146, 37, 75, 0, 52, 53, 53, 157, 119, 222, 121, 127, 249, 203, 95, 42, 243, 38, 183, 221, 118, 219, 254,253, 251, 179, 217, 236, 117, 215, 93, 183, 116, 233, 210, 56, 163, 49, 119, 238, 220, 237, 219, 183, 203, 85, 19, 89, 8, 103, 129, 82, 169, 244, 244, 211, 79, 119, 117, 117, 149, 115, 1, 74, 169, 202, 177, 140, 87, 94, 121, 101, 243, 230,205, 169, 84, 106, 219, 182, 109, 151, 94, 122, 233, 244, 233, 211, 1, 212, 213, 213, 245, 26, 239, 216, 181, 107, 215,230, 205, 155, 147, 201, 228, 142, 29, 59, 150, 45, 91, 54, 101, 202, 20, 0, 201, 100, 146, 153, 39, 79, 158, 28, 31, 19, 69, 209, 29, 119, 220, 241, 226, 139, 47, 166, 82, 169, 92, 46, 215, 222, 222, 254, 139, 95, 252, 34, 254, 86, 85, 85, 85, 165, 122, 172, 181, 91, 182, 108, 217, 189, 123, 119, 24, 134, 197, 98, 49, 150, 5, 128, 116, 58, 45, 43, 208, 68,22, 194, 217, 129, 136, 210, 233, 180, 49, 166, 44, 139, 82, 169, 84, 121, 64, 34, 145, 200, 100, 50, 233, 116, 58, 78,127, 14, 116, 158, 248, 176, 84, 42, 165, 148, 42, 20, 10, 149, 61, 154, 202, 51, 27, 99, 170, 171, 171, 93, 215, 37, 162, 202, 126, 71, 175, 180, 37, 17, 165, 82, 169, 116, 58, 109, 173, 173, 204, 119, 202, 0, 170, 228, 44, 132, 241, 161,149, 126, 103, 79, 244, 61, 172, 87, 147, 46, 199, 2, 241, 183, 202, 15, 123, 77, 217, 24, 240, 119, 75, 201, 111, 151,200, 66, 16, 4, 145, 133, 32, 8, 66, 191, 72, 206, 98, 28, 99, 140, 41, 79, 238, 30, 131, 73, 1, 201, 104, 138, 44, 132, 49, 1, 17, 101, 179, 89, 244, 164, 24, 163, 40, 138, 167, 123, 247, 219, 104, 203, 19, 58, 79, 210, 128, 173, 181, 163, 219, 188, 43, 207, 38, 9, 78, 145, 133, 112, 214, 168, 175, 175, 255, 213, 175, 126, 21, 55, 200, 76, 38, 243, 195, 31, 254, 240, 43, 95, 249, 74, 229, 1, 197, 98, 177, 179, 179, 51, 8, 130, 41, 83, 166, 148, 183, 146, 234, 187, 204, 172,124, 88, 85, 85, 85, 108, 159, 145, 4, 5, 204, 156, 203, 229, 186, 186, 186, 194, 48, 172, 156, 244, 17, 69, 145, 248, 66, 100, 33, 156, 165, 43, 231, 56, 13, 13, 13, 229, 135, 181, 181, 181, 189, 90, 248, 101, 151, 93, 86, 83, 83, 163, 181, 190, 248, 226, 139, 227, 217, 19, 0, 246, 236, 217, 211, 107, 194, 229, 101, 151, 93, 86, 93, 93, 237, 121, 222, 37, 151, 92, 50, 105, 210, 164, 248, 201, 227, 199, 143, 15, 207, 23, 142, 227, 172, 92, 185, 242, 232, 209, 163, 158, 231, 93, 121, 229, 149, 229, 231, 91, 91, 91, 69, 22, 34, 11, 225, 172, 101, 4, 78, 222, 252, 174, 184, 226, 138, 43, 174, 184, 162, 215, 147, 79, 60, 241, 132, 214, 186, 242, 7, 251, 30, 22, 4, 193, 166, 77, 155, 60, 207, 27, 158, 44, 110, 188,241, 198, 94, 79, 30, 62, 124, 120, 199, 142, 29, 195, 59, 161, 32, 178, 16, 70, 74, 91, 91, 219, 250, 245, 235, 227, 233, 222, 174, 235, 238, 221, 187, 55, 149, 74, 157, 252, 71, 30, 120, 224, 129, 103, 158, 121, 166, 223, 197, 233, 149, 252, 228, 39, 63, 121, 254, 249, 231, 19, 137, 196, 168, 188, 79, 99, 204, 55, 190, 241, 141, 3, 7, 14, 100, 50, 25, 185, 106, 34, 11, 225, 44, 224, 251, 254, 227, 143, 63, 222, 209, 209, 225, 56, 14, 51, 123, 158, 215, 107, 177, 233, 142, 29, 59, 118, 237, 218, 181, 100, 201, 146, 121, 243, 230, 1, 120, 250, 233, 167, 111, 190, 249, 102, 207, 243, 122, 197,35, 219, 183, 111, 127, 245, 213, 87, 151, 46, 93, 58, 103, 206, 28, 0, 79, 61, 245, 212, 237, 183, 223, 158, 76, 38, 79, 50, 233, 243, 228, 106, 216, 180, 105, 83, 87, 87, 215, 135, 62, 244, 161, 56, 81, 114, 215, 93, 119, 253, 232, 71, 63, 154, 48, 97, 130, 92, 178, 241, 142, 204, 179, 24, 175, 196, 211, 189, 171, 170, 170, 50, 153, 76, 85, 85, 85, 223, 32, 255, 254, 251, 239, 95, 185, 114, 229, 61, 247, 220, 19, 63, 156, 52, 105, 82, 34, 145, 232, 219, 115, 217, 176, 97, 195, 202, 149, 43, 55, 108, 216, 16, 63, 156, 56, 113, 98, 220, 79, 25, 94, 206, 34, 138, 162, 245, 235, 215, 175, 88, 177, 226, 197, 23, 95, 140, 159, 153, 57, 115, 166, 235, 186, 114, 189, 68, 22, 194, 216, 37, 145, 72, 164, 211, 233, 189, 123, 247, 198, 35, 32, 11, 22, 44, 152, 63, 127, 126, 223, 225, 213, 68, 34, 145, 72, 36, 246, 239, 223, 31, 63, 60, 255, 252, 243, 231, 206, 157, 59, 208, 40, 236, 96, 200, 100, 50, 142, 227, 108, 217, 178, 37, 126, 184, 112, 225, 194, 108, 54, 59, 80, 41, 64, 65, 100, 33, 140, 141, 78, 166, 227, 28, 57, 114, 228, 216, 177, 99, 0, 148, 82, 115, 231, 206, 237, 183, 246, 132, 231, 121, 59, 119, 238, 108, 107, 107, 3, 224, 186, 238, 252, 249, 243, 195, 48, 28, 225, 235, 110, 219, 182, 45, 254, 122, 250, 244, 233, 147, 38, 77, 234, 183, 50, 168, 32, 178, 16, 198, 10, 90, 235, 99, 199, 142, 237,222, 189, 59, 126, 56, 103, 206, 156, 126, 239, 240, 142, 227, 52, 55, 55, 239, 220, 185, 51, 126, 56, 107, 214, 172, 17, 6, 2, 90, 235, 35, 71, 142, 196, 171, 78, 171, 171, 171, 23, 47, 94, 220, 107, 69, 172, 32, 178, 16, 198, 28, 97, 24,238, 219, 183, 47, 254, 250, 146, 75, 46, 201, 102, 179, 125, 147, 17, 68, 20, 4, 193, 235, 175, 191, 30, 63, 92, 188, 120, 113, 175, 161, 144, 94, 53, 184, 78, 57, 53, 211, 113, 156, 195, 135, 15, 87, 158, 48, 158, 69, 26, 207, 215, 234, 236, 236, 236, 85, 173, 83, 24, 31, 129, 170, 124, 4, 227, 151, 82, 169, 84, 42, 149, 202, 21, 37, 250, 181, 0, 128, 151, 94, 122, 41, 126, 56, 123, 246, 236, 134, 134, 134, 215, 94, 123, 173, 223, 179, 189, 242, 202, 43, 241, 23, 141, 141,141, 85, 85, 85, 229, 218, 22, 113, 223, 132, 153, 11, 133, 66, 252, 119, 101, 95, 102, 160, 29, 0, 58, 59, 59, 183, 108, 217, 50, 127, 254, 124, 0, 51, 102, 204, 32, 162, 76, 38, 243, 145, 143, 124, 36, 174, 78, 126, 232, 208, 161, 223, 254, 246, 183, 82, 194, 87, 100, 33, 156, 161, 124, 196, 252, 249, 243, 243, 249, 124, 60, 120, 97, 173, 253, 243, 159, 255, 220, 215, 23, 158, 231, 109, 219, 182, 205, 247, 253, 116, 58, 157, 201, 100, 166, 78, 157, 90, 150, 66, 175, 195, 182, 110, 221, 26, 4, 129, 231, 121, 211, 167, 79, 159, 49, 99, 198, 145, 35, 71, 90, 90, 90, 202, 223, 93, 185, 114, 229, 198, 141, 27, 149, 82, 204, 188, 98, 197, 138, 242, 15, 250, 190, 63, 208, 220, 176, 114, 247, 231, 188, 243, 206, 171, 171, 171, 171, 174, 174, 190, 227, 142, 59, 226, 178, 189, 91, 182, 108, 217, 188, 121, 179, 236, 42, 34, 178, 16, 206, 4, 245, 245, 245, 143, 62, 250, 104, 57, 71, 208, 213, 213, 245, 129, 15, 124, 160, 111, 98, 50, 206, 113, 54, 55, 55,207, 158, 61, 27, 192, 210, 165, 75, 55, 109, 218, 212, 247, 108, 174, 235, 54, 55, 55, 31, 60, 120, 112, 230, 204, 153, 142, 227, 92, 124, 241, 197, 91, 183, 110, 125, 237, 181, 215, 202, 243, 68, 87, 173, 90, 245, 217, 207, 126, 54, 222,115, 36, 86, 6, 17, 29, 63, 126, 124, 247, 238, 221, 253, 142, 140, 58, 142, 179, 119, 239, 222, 248, 235, 41, 83, 166,44, 92, 184, 112, 207, 158, 61, 114, 213, 36, 103, 33, 156, 5, 136, 200, 233, 33, 254, 186, 223, 187, 52, 17, 229, 114,185, 55, 222, 120, 35, 126, 120, 209, 69, 23, 37, 18, 137, 126, 59, 44, 185, 92, 238, 224, 193, 131, 241, 195, 5, 11, 22, 36, 147, 201, 157, 59, 119, 62, 249, 228, 147, 229, 99, 180, 214, 142, 227, 196, 245, 175, 226, 215, 218, 184, 113, 227, 190, 125, 251, 250, 149, 133, 231, 121, 187, 118, 237, 42, 191, 238, 172, 89, 179, 100, 64, 68, 34, 11, 225, 140, 10, 194, 247, 253, 40, 138, 114, 185, 92, 229, 243, 90, 235, 92, 46, 23, 39, 17, 219, 219, 219, 227, 169, 19, 241, 92, 137, 184, 240, 247, 239, 126, 247, 187, 101, 203, 150, 5, 65, 80, 83, 83, 147, 205, 102, 131, 32, 232, 232, 232, 0, 144, 74, 165, 202, 135, 133, 97, 248, 251, 223, 255, 254, 162, 139, 46, 50, 198, 212, 215, 215, 167, 211, 233, 40, 138, 214, 172, 89, 179, 126, 253, 250, 15, 126, 240, 131, 169, 84, 170, 82, 49, 93, 93, 93, 15, 63, 252, 240, 221, 119, 223, 157, 201, 100, 124, 223, 47, 149, 74, 65, 16, 148, 74, 37, 223, 247, 227, 173, 137, 180, 214, 109, 109, 109, 207, 62, 251, 108,67, 67, 3, 17, 157, 123, 238, 185, 68, 212, 222, 222, 110, 140, 73, 36, 18, 185, 92, 78, 58, 32, 227, 239, 215, 175, 169, 169, 73, 62, 133, 241, 2, 51, 167, 211, 233, 184, 244, 118, 223, 111, 117, 118, 118, 198, 69, 46, 226, 118, 24, 183, 225, 120, 46, 166, 227, 56, 213, 213, 213, 241, 79, 117, 116, 116, 40, 165, 226, 213, 232, 68, 148, 207, 231, 251, 30, 22, 159, 45, 222, 163, 44, 12, 195, 137, 19, 39, 246, 26, 31, 241, 125, 191, 189, 189, 61, 153, 76, 198, 93, 146, 184, 234, 111, 252, 131, 93, 93, 93, 113, 214, 147, 153, 227, 125, 15, 153, 217, 24, 147, 207, 231, 227, 247, 22, 139, 169, 171, 171, 75, 124, 33, 178, 16, 78, 35, 214, 218, 129, 38, 65, 196, 139, 68, 202, 209, 126, 229, 206, 0, 149, 207, 159, 228, 176, 242, 201, 227, 208, 160, 124, 102, 99, 76, 47, 61, 245, 218, 118, 160, 242, 93, 85, 46, 81, 233, 117, 194, 242, 48, 74, 175, 243, 11, 210, 13, 17, 78, 67, 146, 233, 196, 86, 218, 111, 34, 227, 148, 207, 15, 116, 216, 64, 39, 63, 101,195, 30, 232, 7, 123, 61, 223, 239, 139, 10, 227, 230, 119, 79, 62, 2, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 89,8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 34, 11, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 89, 8, 130, 32, 136, 44, 4, 65, 16, 89, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 34, 11, 65, 16, 4, 145, 133, 32, 8, 34, 11, 65, 16, 68, 22, 130, 32, 136,44, 4, 65, 16, 89, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 32, 178, 16, 4, 65, 100, 33, 8, 130, 200, 66, 16, 4, 145, 133, 32, 8, 34, 11, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 68, 22, 130, 32, 136, 44, 4, 65, 16, 89, 8, 130, 32,178, 16, 4, 97, 172, 242, 255, 7, 0, 130, 175, 153, 6, 240, 149, 254, 96, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)

    $RetryTimer = 3

    While($SyncHash.boolWhile) {
        try {
            $PhoneUrl = "$($Script:Proto)://${theIPAddress}:${thePort}/captureScreen/mainScreen"
        } catch {
            Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
            Write-Host "Exception:" $_.Exception.Message -foreground "red"
            if($_.Exception.Response.StatusCode.value__ -eq "")
            {
                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
            }
        }

        $WebClient = $null
        #$Image = $connectingImage

        $WebClient = New-Object System.Net.WebClient
        $WebClient.Timeout = 800
        $WebClient.Credentials = New-Object System.Net.NetworkCredential($SyncHash.VVXHTTPUsername,$SyncHash.VVXHTTPPassword)

        Try {
            $Image = $WebClient.DownloadData($PhoneUrl)
        }
        Catch [Exception] {
            $theError = $_.Exception.Message
            $WebResponse = [net.HttpWebResponse]$_.Exception.Response
            $resst = $WebResponse.getResponseStream()
            $sr = new-object IO.StreamReader($resst)
            [string]$result = $sr.ReadToEnd()
            $WebResponse.close()

            if($result -imatch "(404) Not Found")
            {
                Write-Host "INFO: The user must manually configure Settings -> Basic -> Preferences -> Screen Capture -> Enabled" -foreground "yellow"
                $RetryTimer = 10
            }
            else
            {
                Write-Host "INFO: " $_.Exception.Message -foreground "yellow"
            }

        }
        if($Image -ne $null)
        {

            Try {
                #Display Image
                $SyncHash.PictureBox.Image = $Image
                $SyncHash.PictureBox.Visible = $true
                $RetryTimer = 3
            }
            Catch [Exception] {
                Write-Host "INFO: Cannot display image." -foreground "yellow"
                #If display fails show error image.
                $SyncHash.PictureBox.Image = $errorImage
                $SyncHash.PictureBox.Visible = $true

                $RetryTimer = 10
            }
        }
        else
        {
            #Write-Host "Don't report error"
        }

        for($i=0; $i -lt $RetryTimer; $i++)
        {
            if(!$SyncHash.boolWhile)
            {
                break
            }
            Start-Sleep -milliseconds 500
        }

    }

    }) | Out-Null

    $handle = $powershell.BeginInvoke()


    # Initialize and show the form.
    $SyncHash.form.Add_Shown({$SyncHash.form.Activate()})
    $SyncHash.form.ShowDialog() > $null   # Trash the text of the button that was clicked.

    $SyncHash.boolWhile = $false
    While (-Not $handle.IsCompleted) {
        Start-Sleep -Milliseconds 50
    }


    #$powershell.EndInvoke($handle)
    $runspace.Close()
    $powershell.Dispose()
}

function SaveImageFile([System.Drawing.Image] $bmp)
{

    Write-Host "Saving Image..." -foreground "yellow"
    #File Dialog
    $objFileForm = New-Object System.Windows.Forms.SaveFileDialog
    $objFileForm.FileName = "VVXScreenShot.jpg"
    $objFileForm.Title = "Save Image"
    $objFileForm.CheckFileExists = $false
    $Show = $objFileForm.ShowDialog()
    if ($Show -eq "OK")
    {
        [string]$imageTarget = $objFileForm.FileName

        Write-Host "Output File: $imageTarget" -foreground "green"
        [int]$quality = 95

        #Encoder parameter for image quality
        $myEncoder = [System.Drawing.Imaging.Encoder]::Quality
        $encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
        $encoderParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter($myEncoder, $quality)
        # get codec
        $myImageCodecInfo = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|where {$_.MimeType -eq 'image/jpeg'}

        #save to file
        $bmp.Save($imageTarget,$myImageCodecInfo, $($encoderParams))
        $bmp.Dispose()

    }
    else
    {
        Write-Host "INFO: Cancelled save image dialog..." -foreground "Yellow"
        return
    }

}

Function SetScreenCapture([string]$IPAddress, [string]$Value)
{
    $user = $AdminUsername
    $pass = $AdminPassword
    $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

    [string]$ParamText = "up.screenCapture.enabled"
    [string]$ValueText = $Value


$body = @"
{
`"data`":
{
`"$ParamText`": `"$ValueText`"
}
}

"@

    try {
        #REPLACED - 2.10
        #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${IPAddress}:${WebServicePort}/api/v1/mgmt/config/set" -Credential $cred -body $body -Method Post -ContentType "application/json" -TimeoutSec 2 #-DisableKeepAlive

        $uri = "$(Script:Proto)://${IPAddress}:${WebServicePort}/api/v1/mgmt/config/set"

        # Create a request object using the URI
        $request = [System.Net.HttpWebRequest]::Create($uri)

        $request.Credentials = $cred
        $request.KeepAlive = $true
        $request.Pipelined = $true
        $request.AllowAutoRedirect = $false
        $request.Method = "POST"
        $request.ContentType = "application/json"
        #$request.Accept = "text/xml"

        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
        $json = $output | ConvertFrom-Json

        $reader.Close()
        $response.Close()
        Write-Output $output


    } catch {
        $RetryOK = $true
        if($_.Exception.Message -imatch "The underlying connection was closed")
        {
            Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
            try {
                #REPLACED - 2.10
                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${IPAddress}:${WebServicePort}/api/v1/mgmt/config/set" -Credential $cred -body $body -Method Post -ContentType "application/json" -TimeoutSec 2 #-DisableKeepAlive

                $uri = "$(Script:Proto)://${IPAddress}:${WebServicePort}/api/v1/mgmt/config/set"

                # Create a request object using the URI
                $request = [System.Net.HttpWebRequest]::Create($uri)

                $request.Credentials = $cred
                $request.KeepAlive = $true
                $request.Pipelined = $true
                $request.AllowAutoRedirect = $false
                $request.Method = "POST"
                $request.ContentType = "application/json"
                #$request.Accept = "text/xml"

                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                $json = $output | ConvertFrom-Json

                $reader.Close()
                $response.Close()
                Write-Output $output

                $RetryOK = $false
            } catch {
                Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                try {
                    #REPLACED - 2.10
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${IPAddress}:${WebServicePort}/api/v1/mgmt/config/set" -Credential $cred -body $body -Method Post -ContentType "application/json" -TimeoutSec 2 #-DisableKeepAlive

                    $uri = "$(Script:Proto)://${IPAddress}:${WebServicePort}/api/v1/mgmt/config/set"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "POST"
                    $request.ContentType = "application/json"
                    #$request.Accept = "text/xml"

                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                    $json = $output | ConvertFrom-Json

                    $reader.Close()
                    $response.Close()
                    Write-Output $output

                    $RetryOK = $false
                } catch {
                    $RetryOK = $true
                }
            }
        }
        if($RetryOK)
        {
            Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
            Write-Host "Exception:" $_.Exception.Message -foreground "red"
            if($_.Exception.Response.StatusCode.value__ -eq "")
            {
                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
            }
            Return $false
        }

    }


    if($json -ne $null)
    {
        Write-Host "Status: " $json.Status
        if($json.Status -eq "2000")
        {
            Write-Host "Successfully set data..." -foreground "green"

            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Setting: " +$ParamText+ "`r`n"
            $DeviceInfoText += "Made Setting: " +$ValueText+ "`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"

        }
        elseif($json.Status -eq "4000")
        {
            Write-Host "Failed to set data. Invalid input parameters." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Invalid input parameters.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4001")
        {
            Write-Host "Failed to set data. Device busy." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Device busy.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4002")
        {
            Write-Host "Failed to set data. Line not registered." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Line not registered.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4004")
        {
            Write-Host "Failed to set data. Operation Not Supported." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Operation Not Supported.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4005")
        {
            Write-Host "Failed to set data. Line does not exist." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Line does not exist.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4006")
        {
            Write-Host "Failed to set data. URLs not configured." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. URLs not configured.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4007")
        {
            Write-Host "Failed to set data. Call Does Not Exist." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Call Does Not Exist.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4009")
        {
            Write-Host "Failed to set data. Input Size Limit Exceeded." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Input Size Limit Exceeded.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "4010")
        {
            Write-Host "Failed to set data. Default Password Not Allowed." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Default Password Not Allowed.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
        elseif($json.Status -eq "5000")
        {
            Write-Host "Failed to set data. Failed to process request." -foreground "red"
            $DeviceInfoText += "--------Setting Config--------`r`n"
            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
            $DeviceInfoText += "Error: Failed to set data. Failed to process request.`r`n"
            $DeviceInfoText += "------------------------------`r`n"
            $DeviceInfoText += "`r`n"
            Return $false
        }
    }
    else
    {
        Write-Host "No json response received..."
        $DeviceInfoText += "--------Setting Config--------`r`n"
        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
        $DeviceInfoText += "Error: Failed to get data. No response received.`r`n"
        $DeviceInfoText += "------------------------------`r`n"
        $DeviceInfoText += "`r`n"
        Return $false
    }

    #$DeviceInfoText += "`r`n"
    #$objInformationTextBox.Text += $DeviceInfoText
    Return $true
}

#Check if a user has a VVX and then set then enable/disable buttons as necessary  ============================================================
function UpdateButtons
{
    $HasVVX = $false
    $ClientAppBelow54 = $false
    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $LyncServer = $vvxphone.LyncServer
            $ClientIP = $vvxphone.ClientIP
            $ClientApp = $vvxphone.ClientApp

            if($user -eq $SipUser)
            {
                if($ClientIP -ne "IP NOT IN LYNC DATABASE")
                {
                    $HasVVX = $true
                    if(($ClientApp -match "/1\.") -or ($ClientApp -match "/2\.") -or ($ClientApp -match "/3\.") -or ($ClientApp -match "/4\.") -or ($ClientApp -match "/5\.0\.") -or ($ClientApp -match "/5\.1\.") -or ($ClientApp -match "/5\.2\.") -or ($ClientApp -match "/5\.3\."))
                    {
                        $ClientAppBelow54 = $true
                    }
                    break
                }
            }
        }
    }
    if($HasVVX -and $ClientAppBelow54) #Only certain buttons can be enabled for phones under version 5.4
    {
        Write-Host "WARNING: This phone does not have version 5.4 or higher software. Most features of this software are only supported on 5.4 or higher software." -foreground "red"
        $ConnectButton.enabled = $true
        $MessageButton.Enabled = $true
        $GetInfoButton.Enabled = $false
        $SendButton.Enabled = $false
        $GetConfigButton.Enabled = $false
        $SetConfigButton.Enabled = $false
        $DialButton.Enabled = $false
        $EndCallButton.Enabled = $false
        $ScreenButton.Enabled = $false
    }
    elseif($HasVVX) #User has a legit software version above 5.4
    {
        Write-Host "INFO: This phone has version 5.4 or higher software. All features supported." -foreground "Yellow"
        $ConnectButton.enabled = $true
        $MessageButton.Enabled = $true
        $GetInfoButton.Enabled = $true
        $SendButton.Enabled = $true
        $GetConfigButton.Enabled = $true
        $SetConfigButton.Enabled = $true
        $DialButton.Enabled = $true
        $EndCallButton.Enabled = $true
        $ScreenButton.Enabled = $true
    }
    else #User does not have phone
    {
        $ConnectButton.enabled = $false
        $MessageButton.Enabled = $false
        $GetInfoButton.Enabled = $false
        $SendButton.Enabled = $false
        $GetConfigButton.Enabled = $false
        $SetConfigButton.Enabled = $false
        $DialButton.Enabled = $false
        $EndCallButton.Enabled = $false
        $ScreenButton.Enabled = $false
    }
}

#Put useful information about the phone in the Information box  ============================================================
function UpdatePhoneInfoText
{

    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
    $user = $item.Text
    $vvx = $item.SubItems
    [string]$vvxAvailable = $vvx[1].Text
    if($vvxAvailable -eq "Yes")
    {
    foreach($vvxphone in $DiscoverSyncHash.VVXphones)
    {
        $SipUser = $vvxphone.SipUser
        $LyncServer = $vvxphone.LyncServer
        $ClientIP = $vvxphone.ClientIP
        $ClientApp = $vvxphone.ClientApp

        if($SipUser -match "VVXNot@LoggedIn" -and $SipUser -eq $user)
        {
            $objInformationTextBox.Text += "---User Information---`n"
            $objInformationTextBox.Text += "`n"
            $objInformationTextBox.Text += "User:          ${SipUser} `n"
            $objInformationTextBox.Text += "Line Uri:      NOT AVAILABLE `n"
            $objInformationTextBox.Text += "VVX Version:   $ClientApp `n"
            $objInformationTextBox.Text += "Lync Pool:     NOT AVAILABLE `n"
            $objInformationTextBox.Text += "VVX IP:        $ClientIP `n"

            $objInformationTextBox.Text += "`n---PIN Information---`n"
            $objInformationTextBox.Text += "`n"
            $objInformationTextBox.Text += "Pin Policy:    NOT AVAILABLE `n"
            $objInformationTextBox.Text += "Is PIN Set:    NOT AVAILABLE `n"
            $objInformationTextBox.Text += "Is Locked Out: NOT AVAILABLE `n"

            $objInformationTextBox.Text += "`n---Policy Information---`n"
            $objInformationTextBox.Text += "`n"
            $objInformationTextBox.Text += "Dial Plan:     NOT AVAILABLE `n"
            $objInformationTextBox.Text += "Voice Policy:  NOT AVAILABLE `n"

            $objInformationTextBox.Text += "`n`n"
        }
        elseif($user -eq $SipUser)
        {
            $userArray = $user.Split(" ")
            $user = $userArray[0]

            $objInformationTextBox.Text += "---User Information---`n"
            $objInformationTextBox.Text += "`n"
            $objInformationTextBox.Text += "User:          $SipUser `n"

            $UserSettings = Invoke-Expression "Get-CsUser -Identity sip:${user} -ErrorAction SilentlyContinue"
            if($UserSettings -eq $null)
            {
                $UserSettings = Invoke-Expression "Get-CsCommonAreaPhone -Identity sip:${user} -ErrorAction SilentlyContinue"
                $DisplayName = $UserSettings.DisplayName
                $objInformationTextBox.Text += "Display Name:  ${DisplayName} `n"
            }
            $UserPINSettings = Invoke-Expression "Get-CsClientPinInfo -Identity sip:${user} -ErrorAction SilentlyContinue"

            $command = "Get-CsEffectivePolicy"
            if(Get-Command $command -errorAction SilentlyContinue)
            {
                $UserEffective = Invoke-Expression "Get-CsEffectivePolicy -Identity sip:${user}"
                [string]$VoicePolicy = $UserEffective.VoicePolicy
                [string]$PinPolicy = $UserEffective.UserPinPolicy
            }
            else
            {
                [string]$VoicePolicy = $UserSettings.VoicePolicy
                if($VoicePolicy -eq "")
                {$VoicePolicy="Automatic"}

                [string]$PinPolicy = $UserSettings.$PinPolicy
                if($PinPolicy -eq "")
                {$PinPolicy="Automatic"}
            }


            [string]$LineUri = $UserSettings.LineUri
            if($LineUri -eq "")
            {$LineUri="Not Assigned"}
            $objInformationTextBox.Text += "Line Uri:      $LineUri `n"

            $objInformationTextBox.Text += "VVX Version:   $ClientApp `n"
            $objInformationTextBox.Text += "Lync Server:   $LyncServer `n"
            $objInformationTextBox.Text += "VVX IP:        $ClientIP `n"

            $objInformationTextBox.Text += "`n---PIN Information---`n"
            $objInformationTextBox.Text += "`n"
            $objInformationTextBox.Text += "Pin Policy:    $PinPolicy `n"

            if($UserPINSettings -ne $null)
            {
                $IsPinSet = $UserPINSettings.IsPinSet
                $objInformationTextBox.Text += "Is PIN Set:    $IsPinSet `n"
                $IsLockedOut = $UserPINSettings.IsLockedOut
                $objInformationTextBox.Text += "Is Locked Out: $IsLockedOut `n"
            }
            else
            {
                $IsPinSet = $UserPINSettings.IsPinSet
                $objInformationTextBox.Text += "Is PIN Set:    ERROR GETTING PIN INFO `n"
                $IsLockedOut = $UserPINSettings.IsLockedOut
                $objInformationTextBox.Text += "Is Locked Out: ERROR GETTING PIN INFO `n"
            }

            $objInformationTextBox.Text += "`n---Policy Information---`n"
            $objInformationTextBox.Text += "`n"
            [string]$DialPlan = $UserSettings.DialPlan
            if($DialPlan -eq $null)
            {$DialPlan="Automatic"}
            $objInformationTextBox.Text += "Dial Plan:     $DialPlan `n"

            $VoicePolicy = $VoicePolicy.Replace("Tag:","")
            $objInformationTextBox.Text += "Voice Policy:  $VoicePolicy `n"

            $objInformationTextBox.Text += "`n`n"

        }
    }
    }
    else
    {
            $objInformationTextBox.Text += "---User Information---`n"
            $objInformationTextBox.Text += "`n"
            $objInformationTextBox.Text += "User:          ${user} `n"

            $UserSettings = Invoke-Expression "Get-CsUser -Identity sip:${user} -ErrorAction SilentlyContinue"
            if($UserSettings -eq $null)
            {
                $UserSettings = Invoke-Expression "Get-CsCommonAreaPhone -Identity sip:${user} -ErrorAction SilentlyContinue"
                $DisplayName = $UserSettings.DisplayName
                $objInformationTextBox.Text += "Display Name:  ${DisplayName} `n"
            }
            $UserPINSettings = Invoke-Expression "Get-CsClientPinInfo -Identity sip:${user} -ErrorAction SilentlyContinue"

            $command = "Get-CsEffectivePolicy"
            if(Get-Command $command -errorAction SilentlyContinue)
            {
                $UserEffective = Invoke-Expression "Get-CsEffectivePolicy -Identity sip:${user}"
                [string]$VoicePolicy = $UserEffective.VoicePolicy
                [string]$PinPolicy = $UserEffective.UserPinPolicy
            }
            else
            {
                [string]$VoicePolicy = $UserSettings.VoicePolicy
                if($VoicePolicy -eq "")
                {$VoicePolicy="Automatic"}

                [string]$PinPolicy = $UserSettings.$PinPolicy
                if($PinPolicy -eq "")
                {$PinPolicy="Automatic"}
            }


            [string]$LineUri = $UserSettings.LineUri
            if($LineUri -eq "")
            {$LineUri="Not Assigned"}
            $objInformationTextBox.Text += "Line Uri:      $LineUri `n"

            $objInformationTextBox.Text += "VVX Version:   NOT AVAILABLE `n"
            $objInformationTextBox.Text += "Lync Server:   NOT AVAILABLE `n"
            $objInformationTextBox.Text += "VVX IP:        NOT AVAILABLE `n"

            $objInformationTextBox.Text += "`n---PIN Information---`n"
            $objInformationTextBox.Text += "`n"
            $objInformationTextBox.Text += "Pin Policy:    $PinPolicy `n"

            if($UserPINSettings -ne $null)
            {
                $IsPinSet = $UserPINSettings.IsPinSet
                $objInformationTextBox.Text += "Is PIN Set:    $IsPinSet `n"
                $IsLockedOut = $UserPINSettings.IsLockedOut
                $objInformationTextBox.Text += "Is Locked Out: $IsLockedOut `n"
            }
            else
            {
                $IsPinSet = $UserPINSettings.IsPinSet
                $objInformationTextBox.Text += "Is PIN Set:    ERROR GETTING PIN INFO `n"
                $IsLockedOut = $UserPINSettings.IsLockedOut
                $objInformationTextBox.Text += "Is Locked Out: ERROR GETTING PIN INFO `n"
            }
            $objInformationTextBox.Text += "`n---Policy Information---`n"
            $objInformationTextBox.Text += "`n"
            [string]$DialPlan = $UserSettings.DialPlan
            if($DialPlan -eq $null)
            {$DialPlan="Automatic"}
            $objInformationTextBox.Text += "Dial Plan:     $DialPlan `n"

            $VoicePolicy = $VoicePolicy.Replace("Tag:","")
            $objInformationTextBox.Text += "Voice Policy:  $VoicePolicy `n"

            $objInformationTextBox.Text += "`n`n"

    }
    }
}


# Get All VVX Users From Database ============================================================
function GetUsersFromDatabase
{
    $DiscoverSyncHash.VVXphones = @()

    foreach($computer in $computers)
    {

    Write-Host "Connecting to Server: $computer" -Foreground "green"

    [string]$Server = $computer

    #Define SQL Connection String
    [string]$connstring = "server=$server\rtclocal;database=RTCDYN;trusted_connection=true;"

    #Define SQL Command
    [object]$command = New-Object System.Data.SqlClient.SqlCommand

    # SQL query for Lync Server
    $command.CommandText = "select distinct * from RegistrarEndpoint"

    [object]$connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connstring
    try {
    $connection.Open()
    } catch [Exception] {
        write-host ""
        write-host "Lync Polycom VVX Manager was unable to connect to database $server\rtclocal. Please check that the server is online. Also check that UDP 1434 and the Dynamic SQL TCP Port for the RTCLOCAL Named Instance are open in the Windows Firewall on $server." -foreground "red"
        write-host ""
        $StatusLabel.Text = "Error connecting to $server. Refer to Powershell window."
    }

    $command.Connection = $connection


    [object]$sqladapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $sqladapter.SelectCommand = $command

    [object]$results = New-Object System.Data.Dataset
    try {
    $recordcount = $sqladapter.Fill($results)
    } catch [Exception] {
        write-host ""
        write-host "Error running SQL on $server : $_" -foreground "red"
        write-host ""
    }
    $connection.Close()
    $tempstore = $results.Tables[0].rows

    foreach ($t in $tempstore)
    {
    if ($t.isserversource -ne "False")
    {
        $bytearray0 = $t.clientapp
        $bytearray1 = $t.SipCallId
        $bytearray2 = $t.sipheaderfrom
        $EncodingType = "System.Text.ASCIIEncoding"
        $Encode = new-object $EncodingType
        [string]$clientapp = $Encode.GetString($ByteArray0)
        $SipCallId = $encode.getstring($bytearray1)
        $sipheaderfrom = $encode.getstring($bytearray2)

        #write-host "SIP CALL ID: $SipCallId"
        if($SipCallId.contains("@"))
        {
            $c = $SipCallId.split('@')
            $clientip = $c[1]
        }
        else
        {
            $clientip = "IP NOT IN LYNC DATABASE"
        }
        if($sipheaderfrom.contains(";"))
        {
            $noTag = $sipheaderfrom.split(';')
            [string]$sipheaderfrom = $noTag[0]
        }

        $sipheaderfrom = $sipheaderfrom.Replace("sip:", "").Replace("SIP:", "").Replace("<", "").Replace(">", "")
        #Debugging for database check
        #write-host "SIP USER   : `t`t" $sipheaderfrom
        #write-host "Client IP  : `t`t" $clientip
        #write-host "Client App : `t`t" $clientapp

        [string]$polycomName = "PolycomVVX"
        [string]$clientLower = $clientapp.ToLower()
        [string]$polycomLower = $polycomName.ToLower()
        if($clientLower -eq $polycomLower)
        {
            #Confirm how many phones this user is logged into Lync
            $numberofphones = 1
            foreach($vvxphone2 in $DiscoverSyncHash.VVXphones)
            {
                [string]$SipUser2 = $vvxphone2.SipUser
                [string]$SipUserLower = $SipUser2.ToLower()
                [string]$sipheaderfromLower = $sipheaderfrom.ToLower()
                if($SipUserLower -eq $sipheaderfromLower)
                {
                    if($numberofphones -gt 1)
                    {
                        $SipUser = "$SipUser $loop"
                    }
                    $numberofphones++
                }
            }
            #Check if the user has multiple phones
            if($numberofphones -gt 1)
            {
                $sipheaderfrom = "$sipheaderfrom $numberofphones"
            }

            $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$sipheaderfrom";"ClientIP" = "$clientip";"ClientApp" = "$clientapp";"LyncServer"="$computer"})

        }

    }
    }
    }

}

#Update the users list from the vvxphone array  ============================================================
function UpdateUsersList
{

    $lv.Items.Clear()
    Write-Output "VVX Devices found = $(($DiscoverSyncHash.VVXphones).Count)"

    foreach($vvxphone in $DiscoverSyncHash.VVXphones)
    {
        [string]$SipUser = $vvxphone.SipUser
        #Check for Logged out phones
        if($SipUser -match "VVXNot@LoggedIn")
        {
            $lvItem = new-object System.Windows.Forms.ListViewItem($SipUser)
            [void]$lvItem.SubItems.Add("Yes")
            $lvItem.ForeColor = "Green"
            [void]$lv.Items.Add($lvItem)
        }
        #Check for multiple phones per user
        $SipUserSplit = $SipUser.Split(" ")
        if($SipUserSplit.count -gt 1)
        {
            $lvItem = new-object System.Windows.Forms.ListViewItem($SipUser)
            [void]$lvItem.SubItems.Add("Yes")
            $lvItem.ForeColor = "Green"
            [void]$lv.Items.Add($lvItem)
        }
    }

    if (-not $Script:RESTOnlyMode) {
        $Users = Invoke-Expression "Get-CsUser"
        $Users += Invoke-Expression "Get-CsCommonAreaPhone"
        foreach($User in $Users)
        {
            $HasVVX = $false
            [string]$UserSipAddress = $User.SipAddress
            [string]$UserSipAddress = $UserSipAddress.Replace("sip:", "").Replace("SIP:", "")

            foreach($vvxphone in $DiscoverSyncHash.VVXphones)
            {
                [string]$SipUser = $vvxphone.SipUser
                [string]$SipUserLower = $SipUser.ToLower()
                [string]$UserSipAddressLower = $UserSipAddress.ToLower()
                if($SipUserLower -eq $UserSipAddressLower)
                {
                    $HasVVX = $true
                }
            }

            $lvItem = new-object System.Windows.Forms.ListViewItem($UserSipAddress)

            if($HasVVX)
            {
            [void]$lvItem.SubItems.Add("Yes")
            $lvItem.ForeColor = "Green"
            }
            else
            {[void]$lvItem.SubItems.Add("No")}

            #Check if HasVVX and Show VVX ####################################################
            if($HasVVX -and $ShowOnlyVVXUsersCheckBox.Checked)
            {
                [void]$lv.Items.Add($lvItem)
            }
            elseif(!$ShowOnlyVVXUsersCheckBox.Checked)
            {
                [void]$lv.Items.Add($lvItem)
            }
            else
            {
                #Don't Add Item
            }
        }
    }
    else {
        # $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$sipheaderfrom";"ClientIP" = "$clientip";"ClientApp" = "$clientapp";"LyncServer"="$computer"})
        foreach($User in $DiscoverSyncHash.VVXphones)
        {
            $HasVVX = $true
            [string]$UserSipAddress = $User.SipUser
            [string]$UserSipAddress = $UserSipAddress.Replace("sip:", "").Replace("SIP:", "")

            foreach($vvxphone in $DiscoverSyncHash.VVXphones)
            {
                [string]$SipUser = $vvxphone.SipUser
                [string]$SipUserLower = $SipUser.ToLower()
                [string]$UserSipAddressLower = $UserSipAddress.ToLower()
                if($SipUserLower -eq $UserSipAddressLower)
                {
                    $HasVVX = $true
                }
            }

            $lvItem = new-object System.Windows.Forms.ListViewItem($UserSipAddress)

            if($HasVVX)
            {
                [void]$lvItem.SubItems.Add("Yes")
                $lvItem.ForeColor = "Green"
            }
            else
            {[void]$lvItem.SubItems.Add("No")}

            #Check if HasVVX and Show VVX ####################################################
            if($HasVVX -and $ShowOnlyVVXUsersCheckBox.Checked)
            {
                [void]$lv.Items.Add($lvItem)
            }
            elseif(!$ShowOnlyVVXUsersCheckBox.Checked)
            {
                [void]$lv.Items.Add($lvItem)
            }
            else
            {
                #Don't Add Item
            }
        }
    }

    if($lv.Items.count -ne 0)
    {
        $lv.Items[0].Selected = $true
    }
}

#Open the Web Interface of the phone  ============================================================
function ConnectToVVX
{

    foreach ($item in $lv.SelectedItems)
    {

        $user = $item.Text

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP
            $ClientApp = $vvxphone.ClientApp

            if($user -eq $SipUser)
            {
                $ie = New-Object -ComObject InternetExplorer.Application
                $ie.Navigate("$(Script:Proto)://${ClientIP}:${WebPort}")
                $ie.Visible = $true
            }
        }
    }
}


#Reboot selected VVX phones  ============================================================
function RebootVVX2
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP

            if($user -eq $SipUser)
            {
                $ClientIP

                ##REBOOT REST CALL
                $user = $script:AdminUsername
                $pass= $script:AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                try {
                    #REPLACED - 2.10
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "POST"
                    $request.ContentType = "application/json"
                    #$request.Accept = "text/xml"

                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                    $json = $output | ConvertFrom-Json

                    $reader.Close()
                    $response.Close()
                    Write-Output $output


                } catch {
                    Write-Host "Exception:" $_.Exception.Message -foreground "red"
                    if($_.Exception.Response.StatusCode.value__ -eq "")
                    {
                        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                    }
                }

                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully rebooted" -foreground "green"
                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed reboot. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed reboot. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed reboot. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed reboot. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed reboot. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed reboot. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed reboot. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed reboot. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed reboot. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed reboot. Failed to process request." -foreground "red"
                    }
                    #Success 2000 API executed successfully.
                    #Failed 4000 Invalid input parameters.
                    #4001 Device busy.
                    #4002 Line not registered.
                    #4003 Operation not allowed.
                    #4004 Operation Not Supported
                    #4005 Line does not exist.
                    #4006 URLs not configured.
                    #4007 Call Does Not Exist
                    #2000, 4008, 5000 Configuration Export Failed
                    #4009 Input Size Limit Exceeded
                    #4010 Default Password Not Allowed
                    #5000 Failed to process request.
                }
                else
                {
                    Write-Host "No json response received..."
                }

            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }
        }
    }
}

#Send Command selected VVX phones  ============================================================
function SendCommand
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        #$DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP

            if($user -eq $SipUser)
            {
                $ClientIP

                ##REBOOT REST CALL
                $user = $script:AdminUsername
                $pass= $script:AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                $CommandSelected = $CommandDropDownBox.SelectedItem.ToString()
                Write-Host "COMMAND: $CommandSelected"
                if($CommandSelected -eq "Restart")
                {
                    Write-Host "Sending Restart..."

                    $DeviceInfoText += "--------Restart Phone--------`r`n"
                    $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                    try {

                        #REPLACED - 2.10
                        #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                        $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart"

                        # Create a request object using the URI
                        $request = [System.Net.HttpWebRequest]::Create($uri)

                        $request.Credentials = $cred
                        $request.KeepAlive = $true
                        $request.Pipelined = $true
                        $request.AllowAutoRedirect = $false
                        $request.Method = "POST"
                        $request.ContentType = "application/json"
                        #$request.Accept = "text/xml"

                        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                        $json = $output | ConvertFrom-Json

                        $reader.Close()
                        $response.Close()
                        Write-Output $output

                    } catch {
                        $RetryOK = $true
                        if($_.Exception.Message -imatch "The underlying connection was closed")
                        {
                            Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "POST"
                                $request.ContentType = "application/json"
                                #$request.Accept = "text/xml"

                                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                $json = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output

                                $RetryOK = $false
                            } catch {
                                Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                                try {
                                    #REPLACED - 2.10
                                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart"

                                    # Create a request object using the URI
                                    $request = [System.Net.HttpWebRequest]::Create($uri)

                                    $request.Credentials = $cred
                                    $request.KeepAlive = $true
                                    $request.Pipelined = $true
                                    $request.AllowAutoRedirect = $false
                                    $request.Method = "POST"
                                    $request.ContentType = "application/json"
                                    #$request.Accept = "text/xml"

                                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                    $json = $output | ConvertFrom-Json

                                    $reader.Close()
                                    $response.Close()
                                    Write-Output $output


                                    $RetryOK = $false
                                } catch {
                                    $RetryOK = $true
                                }
                            }
                        }
                        if($RetryOK)
                        {
                            Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                            Write-Host "Exception:" $_.Exception.Message -foreground "red"
                            if($_.Exception.Response.StatusCode.value__ -eq "")
                            {
                                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                                $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                                $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                $DeviceInfoText += "-------------------------------`r`n"
                                $DeviceInfoText += "`r`n"
                            }
                            else
                            {
                                $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                $DeviceInfoText += "-------------------------------`r`n"
                                $DeviceInfoText += "`r`n"
                            }

                        }
                    }
                }
                elseif($CommandSelected    -eq "Reboot")
                {
                    Write-Host "Sending Reboot..."
                    $DeviceInfoText += "--------Reboot Phone--------`r`n"
                    $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                    try {
                        #REPLACED - 2.10
                        #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeReboot" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                        $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeReboot"

                        # Create a request object using the URI
                        $request = [System.Net.HttpWebRequest]::Create($uri)

                        $request.Credentials = $cred
                        $request.KeepAlive = $true
                        $request.Pipelined = $true
                        $request.AllowAutoRedirect = $false
                        $request.Method = "POST"
                        $request.ContentType = "application/json"
                        #$request.Accept = "text/xml"

                        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                        $json = $output | ConvertFrom-Json

                        $reader.Close()
                        $response.Close()
                        Write-Output $output


                    } catch {
                        $RetryOK = $true
                        if($_.Exception.Message -imatch "The underlying connection was closed")
                        {
                            Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeReboot" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeReboot"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "POST"
                                $request.ContentType = "application/json"
                                #$request.Accept = "text/xml"

                                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                $json = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output


                                $RetryOK = $false
                            } catch {
                                Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                                try {
                                    #REPLACED - 2.10
                                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeReboot" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeReboot"

                                    # Create a request object using the URI
                                    $request = [System.Net.HttpWebRequest]::Create($uri)

                                    $request.Credentials = $cred
                                    $request.KeepAlive = $true
                                    $request.Pipelined = $true
                                    $request.AllowAutoRedirect = $false
                                    $request.Method = "POST"
                                    $request.ContentType = "application/json"
                                    #$request.Accept = "text/xml"

                                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                    $json = $output | ConvertFrom-Json

                                    $reader.Close()
                                    $response.Close()
                                    Write-Output $output


                                    $RetryOK = $false
                                } catch {
                                    $RetryOK = $true
                                }
                            }

                            if($RetryOK)
                            {
                                Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                                Write-Host "Exception:" $_.Exception.Message -foreground "red"
                                if($_.Exception.Response.StatusCode.value__ -eq "")
                                {
                                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                                    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                                    $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                                    $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                    $DeviceInfoText += "-------------------------------`r`n"
                                    $DeviceInfoText += "`r`n"
                                }
                                else
                                {
                                    $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                    $DeviceInfoText += "-------------------------------`r`n"
                                    $DeviceInfoText += "`r`n"
                                }
                            }

                        }
                    }
                }
                elseif($CommandSelected -eq "Config Reset")
                {
                    $DeviceInfoText += "--------Config Reset--------`r`n"
                    $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                    try {
                        #REPLACED - 2.10
                        #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/configReset" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                        $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/configReset"

                        # Create a request object using the URI
                        $request = [System.Net.HttpWebRequest]::Create($uri)

                        $request.Credentials = $cred
                        $request.KeepAlive = $true
                        $request.Pipelined = $true
                        $request.AllowAutoRedirect = $false
                        $request.Method = "POST"
                        $request.ContentType = "application/json"
                        #$request.Accept = "text/xml"

                        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                        $json = $output | ConvertFrom-Json

                        $reader.Close()
                        $response.Close()
                        Write-Output $output


                    } catch {
                        $RetryOK = $true
                        if($_.Exception.Message -imatch "The underlying connection was closed")
                        {
                            Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/configReset" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/configReset"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "POST"
                                $request.ContentType = "application/json"
                                #$request.Accept = "text/xml"

                                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                $json = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output

                                $RetryOK = $false
                            } catch {
                                Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                                try {
                                    #REPLACED - 2.10
                                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/configReset" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/configReset"

                                    # Create a request object using the URI
                                    $request = [System.Net.HttpWebRequest]::Create($uri)

                                    $request.Credentials = $cred
                                    $request.KeepAlive = $true
                                    $request.Pipelined = $true
                                    $request.AllowAutoRedirect = $false
                                    $request.Method = "POST"
                                    $request.ContentType = "application/json"
                                    #$request.Accept = "text/xml"

                                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                    $json = $output | ConvertFrom-Json

                                    $reader.Close()
                                    $response.Close()
                                    Write-Output $output

                                    $RetryOK = $false
                                } catch {
                                    $RetryOK = $true
                                }
                            }
                        }
                        if($RetryOK)
                        {
                            Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                            Write-Host "Exception:" $_.Exception.Message -foreground "red"
                            if($_.Exception.Response.StatusCode.value__ -eq "")
                            {
                                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                                $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                                $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                $DeviceInfoText += "-------------------------------`r`n"
                                $DeviceInfoText += "`r`n"
                            }
                            else
                            {
                                $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                $DeviceInfoText += "-------------------------------`r`n"
                                $DeviceInfoText += "`r`n"
                            }
                        }
                    }
                }

                elseif($CommandSelected -eq "Factory Reset")
                {
                    $DeviceInfoText += "--------Factory Reset--------`r`n"
                    $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                    try {
                        #REPLACED - 2.10
                        #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/factoryReset" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                        $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/factoryReset"

                        # Create a request object using the URI
                        $request = [System.Net.HttpWebRequest]::Create($uri)

                        $request.Credentials = $cred
                        $request.KeepAlive = $true
                        $request.Pipelined = $true
                        $request.AllowAutoRedirect = $false
                        $request.Method = "POST"
                        $request.ContentType = "application/json"
                        #$request.Accept = "text/xml"

                        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                        $json = $output | ConvertFrom-Json

                        $reader.Close()
                        $response.Close()
                        Write-Output $output

                    } catch {
                        $RetryOK = $true
                        if($_.Exception.Message -imatch "The underlying connection was closed")
                        {
                            Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/factoryReset" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/factoryReset"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "POST"
                                $request.ContentType = "application/json"
                                #$request.Accept = "text/xml"

                                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                $json = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output


                                $RetryOK = $false
                            } catch {
                                Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                                try {
                                    #REPLACED - 2.10
                                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/factoryReset" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/factoryReset"

                                    # Create a request object using the URI
                                    $request = [System.Net.HttpWebRequest]::Create($uri)

                                    $request.Credentials = $cred
                                    $request.KeepAlive = $true
                                    $request.Pipelined = $true
                                    $request.AllowAutoRedirect = $false
                                    $request.Method = "POST"
                                    $request.ContentType = "application/json"
                                    #$request.Accept = "text/xml"

                                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                                    $json = $output | ConvertFrom-Json

                                    $reader.Close()
                                    $response.Close()
                                    Write-Output $output

                                    $RetryOK = $false
                                } catch {
                                    $RetryOK = $true
                                }
                            }
                        }
                        if($RetryOK)
                        {
                            Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                            Write-Host "Exception:" $_.Exception.Message -foreground "red"
                            if($_.Exception.Response.StatusCode.value__ -eq "")
                            {
                                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                                $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                                $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                $DeviceInfoText += "-------------------------------`r`n"
                                $DeviceInfoText += "`r`n"
                            }
                            else
                            {
                                $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                                $DeviceInfoText += "-------------------------------`r`n"
                                $DeviceInfoText += "`r`n"
                            }
                        }

                    }
                }


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully rebooted!" -foreground "green"
                        $DeviceInfoText += "Successfully rebooted!`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed reboot. Invalid input parameters" -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Invalid input parameters`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed reboot. Device busy." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Device busy.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed reboot. Line not registered." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Line not registered.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed reboot. Operation Not Supported." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Operation Not Supported.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed reboot. Line does not exist." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Line does not exist.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed reboot. URLs not configured." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. URLs not configured.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed reboot. Call Does Not Exist." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Call Does Not Exist.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed reboot. Input Size Limit Exceeded." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Input Size Limit Exceeded.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed reboot. Default Password Not Allowed." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Default Password Not Allowed.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed reboot. Failed to process request." -foreground "red"
                        $DeviceInfoText += "ERROR: Failed reboot. Failed to process request.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    #Success 2000 API executed successfully.
                    #Failed 4000 Invalid input parameters.
                    #4001 Device busy.
                    #4002 Line not registered.
                    #4003 Operation not allowed.
                    #4004 Operation Not Supported
                    #4005 Line does not exist.
                    #4006 URLs not configured.
                    #4007 Call Does Not Exist
                    #2000, 4008, 5000 Configuration Export Failed
                    #4009 Input Size Limit Exceeded
                    #4010 Default Password Not Allowed
                    #5000 Failed to process request.
                }
                else
                {
                    Write-Host "No json response received..."
                    #$DeviceInfoText += "ERROR: No response received.`r`n"
                    #$DeviceInfoText += "------------------------------`r`n"
                    #$DeviceInfoText += "`r`n"
                }
                $objInformationTextBox.Text = $DeviceInfoText

                if($CommandSelected -eq "Reboot All Phones")
                {
                    $a = new-object -comobject wscript.shell
                    $intAnswer = $a.popup("Are you sure you want to reboot all of the VVX phones on the system?",0,"Reboot All Phones",4)
                    if ($intAnswer -eq 6) {
                        RebootAllVVX2
                    }
                }
            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }
        }
    }
}

#GetInfo selected VVX phones  ============================================================
function GetInfo
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP

            if($user -eq $SipUser)
            {
                #$ClientIP

                $DeviceInfoText = "==== $SipUser ====`r`n`r`n"


                ##REBOOT REST CALL
                Write-Host "User: $AdminUsername Pass: $AdminPassword"
                $user = $AdminUsername
                $pass = $AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                Write-Host "Getting Device Info..."
                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/device/info" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/device/info"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got info" -foreground "green"
                        Write-Host "Model Number: " $json.Data.ModelNumber
                        Write-Host "Firmware Release: " $json.Data.FirmwareRelease
                        Write-Host "Device Type: " $json.Data.DeviceType
                        Write-Host "Device Vendor: " $json.Data.DeviceVendor
                        Write-Host "Up Time Since Last Reboot: " $json.Data.UpTimeSinceLastReboot
                        Write-Host "IPV4Address: " $json.Data.IPV4Address
                        Write-Host "IPV6Address: " $json.Data.IPV6Address
                        Write-Host "MACAddress: " $json.Data.MACAddress
                        Write-Host "Camera:" $json.Data.AttachedHardware.Camera
                        Write-Host "EM.Type: " $json.Data.AttachedHardware.EM.Type
                        Write-Host "EM.Version: " $json.Data.AttachedHardware.EM.Version

                        $DeviceInfoText += "--------Device Info---------`r`n"
                        $DeviceInfoText += "Model Number: " +$json.Data.ModelNumber+ "`r`n"
                        $DeviceInfoText += "Firmware Release: " +$json.Data.FirmwareRelease+ "`r`n"
                        $DeviceInfoText += "Device Type: " +$json.Data.DeviceType+ "`r`n"
                        $DeviceInfoText += "Device Vendor: " +$json.Data.DeviceVendor+ "`r`n"
                        $DeviceInfoText += "Up Time Since Last Reboot: " +$json.Data.UpTimeSinceLastReboot+ "`r`n"
                        $DeviceInfoText += "IPV4Address: " +$json.Data.IPV4Address+ "`r`n"
                        $DeviceInfoText += "IPV6Address: " +$json.Data.IPV6Address+ "`r`n"
                        $DeviceInfoText += "MACAddress: " +$json.Data.MACAddress+ "`r`n"
                        $DeviceInfoText += "Camera:" +$json.Data.AttachedHardware.Camera+ "`r`n"
                        $DeviceInfoText += "EM.Type: " +$json.Data.AttachedHardware.EM.Type+ "`r`n"
                        $DeviceInfoText += "EM.Version: " +$json.Data.AttachedHardware.EM.Version+ "`r`n"
                        $DeviceInfoText += "`r`n"


                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get input. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get input. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get input. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get input. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get input. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get input. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get input. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get input. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get input. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get input. Failed to process request." -foreground "red"
                    }
                    #Success 2000 API executed successfully.
                    #Failed 4000 Invalid input parameters.
                    #4001 Device busy.
                    #4002 Line not registered.
                    #4003 Operation not allowed.
                    #4004 Operation Not Supported
                    #4005 Line does not exist.
                    #4006 URLs not configured.
                    #4007 Call Does Not Exist
                    #2000, 4008, 5000 Configuration Export Failed
                    #4009 Input Size Limit Exceeded
                    #4010 Default Password Not Allowed
                    #5000 Failed to process request.
                }
                else
                {
                    Write-Host "No json response received..."
                    $DeviceInfoText += "ERROR: Failed to connect to phone.`r`n`r`n"
                    $objInformationTextBox.Text += $DeviceInfoText
                    continue
                }

                $json = $null

                Write-Host "Getting Status..."
                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got Status" -foreground "green"

                        Write-Host "Call Handle: "$json.data.CallHandle
                        Write-Host "Type: "$json.data.Type
                        Write-Host "Protocol: "$json.data.Protocol
                        Write-Host "CallState: "$json.data.CallState
                        Write-Host "LineID: " +$json.data.LineID
                        Write-Host "RemotePartyName: "$json.data.RemotePartyName
                        Write-Host "RemotePartyNumber: "$json.data.RemotePartyNumber
                        Write-Host "DurationInSeconds: "$json.data.DurationInSeconds
                        Write-Host


                        $DeviceInfoText += "--------Call Status--------`r`n"
                        $DeviceInfoText += "Call Handle: " +$json.data.CallHandle+ "`r`n"
                        $DeviceInfoText += "Type: " +$json.data.Type+ "`r`n"
                        $DeviceInfoText += "Protocol: " +$json.data.Protocol+ "`r`n"
                        $DeviceInfoText += "CallState: " +$json.data.CallState+ "`r`n"
                        $DeviceInfoText += "LineID: " +$json.data.LineID+ "`r`n"
                        $DeviceInfoText += "RemotePartyName: " +$json.data.RemotePartyName+ "`r`n"
                        $DeviceInfoText += "RemotePartyNumber: " +$json.data.RemotePartyNumber+ "`r`n"
                        $DeviceInfoText += "DurationInSeconds: " +$json.data.DurationInSeconds+ "`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get info. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get info. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get info. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get info. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get info. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get info. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get info. Call Does Not Exist." -foreground "red"

                        Write-Host "No Call Status" -foreground "green"
                        Write-Host

                        $DeviceInfoText += "--------Call Status--------`r`n"
                        $DeviceInfoText += "Phone is currently not on a call...`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get info. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get info. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get info. Failed to process request." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "No json response received..."

                }

                $json = $null

                Write-Host "Getting Presence..."

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/getPresence" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/getPresence"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got Presence" -foreground "green"
                        Write-Host "Presence: "$json.Presence


                        $DeviceInfoText += "--------Presence Info--------`r`n"
                        $DeviceInfoText += "Presence: " +$json.Presence+ "`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get info. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get info. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get info. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get info. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get info. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get info. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get info. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get info. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get info. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get info. Failed to process request." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "No json response received..."
                }

                $json = $null

                Write-Host "Getting Network Info..."

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/network/info" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/network/info"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got network info" -foreground "green"
                        Write-Host "DHCP: "$json.Data.DHCP
                        Write-Host "DHCPServer: "$json.Data.DHCPServer
                        Write-Host "DHCPBootServerUseOption: "$json.Data.DHCPBootServerUseOption
                        Write-Host "DHCPBootServerOption: "$json.Data.DHCPBootServerOption
                        Write-Host "DHCPBootServerOptionType: "$json.Data.DHCPBootServerOptionType
                        Write-Host "DHCPOption60Format: "$json.Data.DHCPOption60Format
                        Write-Host "IPV4Address: "$json.Data.IPV4Address
                        Write-Host "IPV6Address: "$json.Data.IPV6Address
                        Write-Host "DefaultGateway: "$json.Data.DefaultGateway
                        Write-Host "DNSServer: "$json.Data.DNSServer
                        Write-Host "AlternateDNSServer: "$json.Data.AlternateDNSServer
                        Write-Host "DNSDomain: "$json.Data.DNSDomain
                        Write-Host "SNTPAddress: "$json.Data.SNTPAddress
                        Write-Host "SubnetMask: "$json.Data.SubnetMask
                        Write-Host  "LANPortStatus: "$json.Data.LANPortStatus
                        Write-Host "LANSpeed: "$json.Data.LANSpeed
                        Write-Host "VLANID: "$json.Data.VLANID
                        Write-Host "LLDP: "$json.Data.LLDP
                        Write-Host "CDPCompability: "$json.Data.CDPCompability
                        Write-Host "VLANDiscoveryMode: "$json.Data.VLANDiscoveryMode
                        Write-Host "VLANIDOption: "$json.Data.VLANIDOption
                        Write-Host "ProvServerAddress: "$json.Data.ProvServerAddress
                        Write-Host "ProvServerUser: "$json.Data.ProvServerUser
                        Write-Host "ProvServerType: "$json.Data.ProvServerType
                        Write-Host "UpgradeServer: "$json.Data.UpgradeServer
                        Write-Host "ZTPStatus: "$json.Data.ZTPStatus
                        Write-Host



                        $DeviceInfoText += "--------Network Info--------`r`n"
                        $DeviceInfoText += "DHCP: " +$json.Data.DHCP+ "`r`n"
                        $DeviceInfoText += "DHCPServer: " +$json.Data.DHCPServer+ "`r`n"
                        $DeviceInfoText += "DHCPBootServerUseOption: " +$json.Data.DHCPBootServerUseOption+ "`r`n"
                        $DeviceInfoText += "DHCPBootServerOption: " +$json.Data.DHCPBootServerOption+ "`r`n"
                        $DeviceInfoText += "DHCPBootServerOptionType: " +$json.Data.DHCPBootServerOptionType+ "`r`n"
                        $DeviceInfoText += "DHCPOption60Format: " +$json.Data.DHCPOption60Format+ "`r`n"
                        $DeviceInfoText += "IPV4Address: " +$json.Data.IPV4Address+ "`r`n"
                        $DeviceInfoText += "IPV6Address: " +$json.Data.IPV6Address+ "`r`n"
                        $DeviceInfoText += "DefaultGateway: " +$json.Data.DefaultGateway+ "`r`n"
                        $DeviceInfoText += "DNSServer: " +$json.Data.DNSServer+ "`r`n"
                        $DeviceInfoText += "AlternateDNSServer: " +$json.Data.AlternateDNSServer+ "`r`n"
                        $DeviceInfoText += "DNSDomain: " +$json.Data.DNSDomain+ "`r`n"
                        $DeviceInfoText += "SNTPAddress: " +$json.Data.SNTPAddress+ "`r`n"
                        $DeviceInfoText += "SubnetMask: " +$json.Data.SubnetMask+ "`r`n"
                        $DeviceInfoText += "LANPortStatus: " +$json.Data.LANPortStatus+ "`r`n"
                        $DeviceInfoText += "LANSpeed: " +$json.Data.LANSpeed+ "`r`n"
                        $DeviceInfoText += "VLANID: " +$json.Data.VLANID+ "`r`n"
                        $DeviceInfoText += "LLDP: " +$json.Data.LLDP+ "`r`n"
                        $DeviceInfoText += "CDPCompability: " +$json.Data.CDPCompability+ "`r`n"
                        $DeviceInfoText += "VLANDiscoveryMode: " +$json.Data.VLANDiscoveryMode+ "`r`n"
                        $DeviceInfoText += "VLANIDOption: " +$json.Data.VLANIDOption+ "`r`n"
                        $DeviceInfoText += "ProvServerAddress: " +$json.Data.ProvServerAddress+ "`r`n"
                        $DeviceInfoText += "ProvServerUser: " +$json.Data.ProvServerUser+ "`r`n"
                        $DeviceInfoText += "ProvServerType: " +$json.Data.ProvServerType+ "`r`n"
                        $DeviceInfoText += "UpgradeServer: " +$json.Data.UpgradeServer+ "`r`n"
                        $DeviceInfoText += "ZTPStatus: " +$json.Data.ZTPStatus+ "`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get info. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get info. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get info. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get info. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get info. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get info. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get info. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get info. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get info. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get info. Failed to process request." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "No json response received..."
                }

                $json = $null

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/lineInfo" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/lineInfo"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got network info" -foreground "green"
                        Write-Host "LineNumber: "$json.Data.LineNumber
                        Write-Host "Protocol: "$json.Data.Protocol
                        Write-Host "SIPAddress: "$json.Data.SIPAddress
                        Write-Host "ProxyAddress: "$json.Data.ProxyAddress
                        Write-Host "UserID: "$json.Data.UserID
                        Write-Host "Label: "$json.Data.Label
                        Write-Host "LineType: "$json.Data.LineType
                        Write-Host "RegistrationStatus: "$json.Data.RegistrationStatus
                        Write-Host "Port: "$json.Data.Port
                        Write-Host

                        $DeviceInfoText += "--------Line Info--------`r`n"
                        $DeviceInfoText += "LineNumber: " +$json.Data.LineNumber+ "`r`n"
                        $DeviceInfoText += "Protocol: " +$json.Data.Protocol+ "`r`n"
                        $DeviceInfoText += "SIPAddress: " +$json.Data.SIPAddress+ "`r`n"
                        $DeviceInfoText += "ProxyAddress: " +$json.Data.ProxyAddress+ "`r`n"
                        $DeviceInfoText += "UserID: " +$json.Data.UserID+ "`r`n"
                        $DeviceInfoText += "Label: " +$json.Data.Label+ "`r`n"
                        $DeviceInfoText += "LineType: " +$json.Data.LineType+ "`r`n"
                        $DeviceInfoText += "RegistrationStatus: " +$json.Data.RegistrationStatus+ "`r`n"
                        $DeviceInfoText += "Port: " +$json.Data.Port+ "`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get info. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get info. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get info. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get info. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get info. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get info. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get info. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get info. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get info. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get info. Failed to process request." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "No json response received..."
                }

                $json = $null

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/sipStatus" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/sipStatus"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got SIP Status" -foreground "green"
                        Write-Host "UUID: "$json.Data.UUID
                        Write-Host "Name: "$json.Data.User[0].Name
                        Write-Host "GRUUID: "$json.Data.User[0].GRUUID
                        Write-Host "LineNumber: "$json.Data.User[0].LineNumber
                        Write-Host "TotalCalls: "$json.Data.User[0].TotalCalls
                        Write-Host

                        $DeviceInfoText += "--------SIP Status--------`r`n"
                        $DeviceInfoText += "UUID: " +$json.Data.UUID+ "`r`n"
                        $DeviceInfoText += "Name: " +$json.Data.User[0].Name+ "`r`n"
                        $DeviceInfoText += "GRUUID: " +$json.Data.User[0].GRUUID+ "`r`n"
                        $DeviceInfoText += "LineNumber: " +$json.Data.User[0].LineNumber+ "`r`n"
                        $DeviceInfoText += "TotalCalls: " +$json.Data.User[0].TotalCalls+ "`r`n"
                        $DeviceInfoText += "TotalEvents: " +$json.Data.User[0].TotalEvents+ "`r`n"
                        foreach($VVXEvent in $json.Data.User[0].Events)
                        {
                            $DeviceInfoText += "`r`n"
                            $DeviceInfoText += "Type: " +$VVXEvent.Type+ "`r`n"
                            $DeviceInfoText += "RegistrationState: " +$VVXEvent.RegistrationState+ "`r`n"
                            $DeviceInfoText += "Expires: " +$VVXEvent.Expires+ "`r`n"
                            $DeviceInfoText += "CallID: " +$VVXEvent.CallID+ "`r`n"
                            $DeviceInfoText += "Overlap: " +$VVXEvent.Overlap+ "`r`n"

                        }
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get info. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get info. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get info. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get info. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get info. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get info. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get info. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get info. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get info. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get info. Failed to process request." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "No json response received..."
                }

                $json = $null

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/network/stats" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/network/stats"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got network statistics" -foreground "green"
                        Write-Host "UpTime: "$json.Data.UpTime
                        Write-Host "RxPackets: "$json.Data.RxPackets
                        Write-Host "TxPackets: "$json.Data.TxPackets

                        $DeviceInfoText += "--------Network Statistics--------`r`n"
                        $DeviceInfoText += "UpTime: " +$json.Data.UpTime+ "`r`n"
                        $DeviceInfoText += "RxPackets: " +$json.Data.RxPackets+ "`r`n"
                        $DeviceInfoText += "TxPackets: " +$json.Data.TxPackets+ "`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get network statistics. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get network statistics. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get network statistics. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get network statistics. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get network statistics. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get network statistics. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get network statistics. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get network statistics. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get network statistics. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get network statistics. Failed to process request." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "No json response received..."
                }
                $DeviceInfoText += "`r`n"
                $objInformationTextBox.Text += $DeviceInfoText
            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }
        }
    }
}

#Set Config VVX phones  ============================================================
function SetConfig
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP

            if($user -eq $SipUser)
            {

                $user = $script:AdminUsername
                $pass= $script:AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                $ParamText = $ParamTextBox.Text
                $ValueText = $ValueTextBox.Text


                $body = @"
{
`"data`":
{
`"$ParamText`": `"$ValueText`"
}
}

"@

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #REPLACED - 2.10
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/set" -Credential $cred -body $body -Method Post -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/set"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "POST"
                    $request.ContentType = "application/json"
                    #$request.Accept = "text/xml"

                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                    $json = $output | ConvertFrom-Json

                    $reader.Close()
                    $response.Close()
                    Write-Output $output

                } catch {

                    $RetryOK = $true
                    if($_.Exception.Message -imatch "The underlying connection was closed")
                    {
                        Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                        try {
                            #REPLACED - 2.10
                            #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/set" -Credential $cred -body $body -Method Post -ContentType "application/json"  -TimeoutSec 2

                            $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/set"

                            # Create a request object using the URI
                            $request = [System.Net.HttpWebRequest]::Create($uri)

                            $request.Credentials = $cred
                            $request.KeepAlive = $true
                            $request.Pipelined = $true
                            $request.AllowAutoRedirect = $false
                            $request.Method = "POST"
                            $request.ContentType = "application/json"
                            #$request.Accept = "text/xml"

                            $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                            $json = $output | ConvertFrom-Json

                            $reader.Close()
                            $response.Close()
                            Write-Output $output

                            $RetryOK = $false
                        } catch {
                            Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/set" -Credential $cred -body $body -Method Post -ContentType "application/json"  -TimeoutSec 2

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/set"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "POST"
                                $request.ContentType = "application/json"
                                #$request.Accept = "text/xml"

                                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                                $json = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output

                                $RetryOK = $false
                            } catch {
                                $RetryOK = $true
                            }
                        }
                    }
                    if($RetryOK)
                    {
                        Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                        Write-Host "Exception:" $_.Exception.Message -foreground "red"
                        if($_.Exception.Response.StatusCode.value__ -eq "")
                        {
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                            $DeviceInfoText += "---------Setting Config--------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                        else
                        {
                            $DeviceInfoText += "---------Setting Config--------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                    }

                }

                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully set data..." -foreground "green"

                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Setting: " +$ParamText+ "`r`n"
                        $DeviceInfoText += "Made Setting: " +$ValueText+ "`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to set data. Invalid input parameters." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Invalid input parameters.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to set data. Device busy." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Device busy.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to set data. Line not registered." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Line not registered.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to set data. Operation Not Supported." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Operation Not Supported.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to set data. Line does not exist." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Line does not exist.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to set data. URLs not configured." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. URLs not configured.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to set data. Call Does Not Exist." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Call Does Not Exist.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to set data. Input Size Limit Exceeded." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Input Size Limit Exceeded.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to set data. Default Password Not Allowed." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Default Password Not Allowed.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to set data. Failed to process request." -foreground "red"
                        $DeviceInfoText += "--------Setting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to set data. Failed to process request.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                }
                else
                {
                    Write-Host "No json response received..."

                }

                $DeviceInfoText += "`r`n"
                $objInformationTextBox.Text += $DeviceInfoText
            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }
        }
    }
}

#Get Config VVX phones  ============================================================
function GetConfig
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP


            if($user -eq $SipUser)
            {
                ##GET CONFIG
                $user = $script:AdminUsername
                $pass= $script:AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                $ParamText = $ParamTextBox.Text

                <#
                $body = @"
{
`"data`":
[
`"$ParamText`"
]
}

"@
#>
                # The old format of this was causing issues. Replaced with this...
                $body = "{`"data`":[`"$ParamText`"]}"

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #REPLACED - 2.10
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/get" -Credential $cred -body $body -Method Post -ContentType "application/json" -TimeoutSec 2 #-Proxy "127.0.0.1:8888"

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/get"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "POST"
                    $request.ContentType = "application/json"
                    #$request.Accept = "text/xml"

                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                    $json = $output | ConvertFrom-Json

                    $reader.Close()
                    $response.Close()
                    Write-Output $output

                } catch {

                    $RetryOK = $true
                    if($_.Exception.Message -imatch "The underlying connection was closed")
                    {
                        Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                        try {
                            #REPLACED - 2.10
                            #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/get" -Credential $cred -body $body -Method Post -ContentType "application/json" -TimeoutSec 2 #-Proxy "127.0.0.1:8888"

                            $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/get"


                            # Create a request object using the URI
                            $request = [System.Net.HttpWebRequest]::Create($uri)

                            $request.Credentials = $cred
                            $request.KeepAlive = $true
                            $request.Pipelined = $true
                            $request.AllowAutoRedirect = $false
                            $request.Method = "POST"
                            $request.ContentType = "application/json"
                            #$request.Accept = "text/xml"

                            $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                            $json = $output | ConvertFrom-Json

                            $reader.Close()
                            $response.Close()
                            Write-Output $output

                            $RetryOK = $false
                        } catch {
                            Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/get" -Credential $cred -body $body -Method Post -ContentType "application/json" -TimeoutSec 2 #-Proxy "127.0.0.1:8888"

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/config/get"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "POST"
                                $request.ContentType = "application/json"
                                #$request.Accept = "text/xml"

                                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                                $json = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output

                                $RetryOK = $false
                            } catch {
                                $RetryOK = $true
                            }
                        }
                    }

                    if($RetryOK)
                    {
                        Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                        Write-Host "Exception:" $_.Exception.Message -foreground "red"
                        if($_.Exception.Response.StatusCode.value__ -eq "")
                        {
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                            $DeviceInfoText += "----------Get Config-----------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                        else
                        {
                            $DeviceInfoText += "----------Get Config-----------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                    }
                }


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got data..." -foreground "green"

                        $ValueTextBox.Text = $json.data.${ParamText}.Value

                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Getting: " +$ParamText+ "`r`n"
                        $DeviceInfoText += "Current Setting: " +$json.data.${ParamText}.Value+ "`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to get data. Invalid input parameters." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Invalid input parameters.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to get data. Device busy." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Device busy.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to get data. Line not registered." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Line not registered.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to get data. Operation Not Supported." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Operation Not Supported.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to get data. Line does not exist." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Line does not exist.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to get data. URLs not configured." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. URLs not configured.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to get data. Call Does Not Exist." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Call Does Not Exist.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to get data. Input Size Limit Exceeded." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Input Size Limit Exceeded.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to get data. Default Password Not Allowed." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Default Password Not Allowed.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to get data. Failed to process request." -foreground "red"
                        $DeviceInfoText += "--------Getting Config--------`r`n"
                        $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "Error: Failed to get data. Failed to process request.`r`n"
                        $DeviceInfoText += "------------------------------`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                }
                else
                {
                    Write-Host "No json response received..."
                }
                $DeviceInfoText += "`r`n"
                $objInformationTextBox.Text += $DeviceInfoText
            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }
        }
    }
}



#Dial VVX phones  ============================================================
function DialNumber
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP

            if($user -eq $SipUser)
            {
                ##REBOOT REST CALL
                $user = $script:AdminUsername
                $pass= $script:AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                $DialText = $DialTextBox.Text

                $body = @"
{
`"data`":
{
`"Dest`": `"$DialText`",
`"Line`": `"1`",
`"Type`": `"SIP`"
}
}

"@

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #REPLACED - 2.10
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/dial" -Credential $cred -body $body -Method Post -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/dial"


                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "POST"
                    $request.ContentType = "application/json"
                    #$request.Accept = "text/xml"

                    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                    $json = $output | ConvertFrom-Json

                    $reader.Close()
                    $response.Close()
                    Write-Output $output

                } catch {
                    $RetryOK = $true
                    if($_.Exception.Message -imatch "The underlying connection was closed")
                    {
                        Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                        try {
                            #REPLACED - 2.10
                            #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/dial" -Credential $cred -body $body -Method Post -ContentType "application/json"  -TimeoutSec 2

                            $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/dial"


                            # Create a request object using the URI
                            $request = [System.Net.HttpWebRequest]::Create($uri)

                            $request.Credentials = $cred
                            $request.KeepAlive = $true
                            $request.Pipelined = $true
                            $request.AllowAutoRedirect = $false
                            $request.Method = "POST"
                            $request.ContentType = "application/json"
                            #$request.Accept = "text/xml"

                            $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                            $json = $output | ConvertFrom-Json

                            $reader.Close()
                            $response.Close()
                            Write-Output $output

                            $RetryOK = $false
                        } catch {
                            Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/dial" -Credential $cred -body $body -Method Post -ContentType "application/json"  -TimeoutSec 2

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/dial"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "POST"
                                $request.ContentType = "application/json"
                                #$request.Accept = "text/xml"

                                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                                $json = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output

                                $RetryOK = $false
                            } catch {
                                $RetryOK = $true
                            }
                        }
                    }
                    if($RetryOK)
                    {
                        Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                        Write-Host "Exception:" $_.Exception.Message -foreground "red"
                        if($_.Exception.Response.StatusCode.value__ -eq "")
                        {
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                            $DeviceInfoText += "----------Making Call----------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                        else
                        {
                            $DeviceInfoText += "----------Making Call----------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                    }

                }

                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully dialled $DialText" -foreground "green"

                        $DeviceInfoText += "----------Making Call----------`r`n"
                        $DeviceInfoText += "From User: " +$SipUser+ "`r`n"
                        $DeviceInfoText += "To User: " +$DialText+ "`r`n"
                        $DeviceInfoText += "-------------------------------`r`n"
                        $DeviceInfoText += "`r`n"

                        $DeviceInfoText += "Successfully made call!`r`n"
                        $DeviceInfoText += "`r`n"

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to dial. Invalid input parameters" -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to dial. Device busy." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to dial. Line not registered." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to dial. Operation Not Supported." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to dial. Line does not exist." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to dial. URLs not configured." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to dial. Call Does Not Exist." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to dial. Input Size Limit Exceeded." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to dial. Default Password Not Allowed." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to dial. Failed to process request." -foreground "red"

                        $DeviceInfoText += "Failed to make call!`r`n"
                        $DeviceInfoText += "`r`n"
                    }

                }
                else
                {
                    Write-Host "No json response received..."

                }
                $DeviceInfoText += "`r`n"
                $objInformationTextBox.Text = $DeviceInfoText
            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }
        }
    }
}


#GetCallStatus VVX phones  ============================================================
function GetCallStatus
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP

            if($user -eq $SipUser)
            {
                ##REBOOT REST CALL
                $user = $script:AdminUsername
                $pass= $script:AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json = $output | ConvertFrom-Json

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


                if($json -ne $null)
                {
                    Write-Host "Status: " $json.Status
                    if($json.Status -eq "2000")
                    {
                        Write-Host "Successfully got call status" -foreground "green"

                        #Start-Sleep -m 500
                        Write-Host "Status: " $json.Status
                        if($json.Status -eq "2000")
                        {
                            $DeviceInfoText += "--------Call Status--------`r`n"
                            $DeviceInfoText += "Call Handle: " +$json.Data.CallHandle+ "`r`n"
                            $DeviceInfoText += "Type: " +$json.Data.Type+ "`r`n"
                            $DeviceInfoText += "Protocol: " +$json.Data.Protocol+ "`r`n"
                            $DeviceInfoText += "CallState: " +$json.Data.CallState+ "`r`n"
                            $DeviceInfoText += "LineID: " +$json.Data.LineID+ "`r`n"
                            $DeviceInfoText += "RemotePartyName: " +$json.Data.RemotePartyName+ "`r`n"
                            $DeviceInfoText += "RemotePartyNumber: " +$json.Data.RemotePartyNumber+ "`r`n"
                            $DeviceInfoText += "DurationInSeconds: " +$json.Data.DurationInSeconds+ "`r`n"
                            $DeviceInfoText += "`r`n"

                            $objInformationTextBox.Text = $DeviceInfoText
                        }

                    }
                    elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed to dial. Invalid input parameters" -foreground "red"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed to dial. Device busy." -foreground "red"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed to dial. Line not registered." -foreground "red"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed to dial. Operation Not Supported." -foreground "red"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed to dial. Line does not exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed to dial. URLs not configured." -foreground "red"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed to dial. Call Does Not Exist." -foreground "red"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed to dial. Input Size Limit Exceeded." -foreground "red"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed to dial. Default Password Not Allowed." -foreground "red"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed to dial. Failed to process request." -foreground "red"
                    }
                }
                else
                {
                    Write-Host "No json response received..."
                }

            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }
        }
    }
}

#End Call VVX phones  ============================================================
function EndCall
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $DeviceInfoText = ""

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $SipUser = $vvxphone.SipUser
            $ClientIP = $vvxphone.ClientIP

            if($user -eq $SipUser)
            {
                ##REBOOT REST CALL
                $user = $script:AdminUsername
                $pass= $script:AdminPassword
                $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

                Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                try {
                    #REPLACED - 2.10
                    #$json2 = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                    $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus"

                    # Create a request object using the URI
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    $request.Credentials = $cred
                    $request.KeepAlive = $true
                    $request.Pipelined = $true
                    $request.AllowAutoRedirect = $false
                    $request.Method = "GET"
                    $request.ContentType = "application/json"

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
                    $json2 = $output | ConvertFrom-Json

                    $reader.Close()
                    $response.Close()
                    Write-Output $output

                } catch {
                    $RetryOK = $true
                    if($_.Exception.Message -imatch "The underlying connection was closed")
                    {
                        Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                        try {
                            #REPLACED - 2.10
                            #$json2 = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                            $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus"

                            # Create a request object using the URI
                            $request = [System.Net.HttpWebRequest]::Create($uri)

                            $request.Credentials = $cred
                            $request.KeepAlive = $true
                            $request.Pipelined = $true
                            $request.AllowAutoRedirect = $false
                            $request.Method = "GET"
                            $request.ContentType = "application/json"

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
                            $json2 = $output | ConvertFrom-Json

                            $reader.Close()
                            $response.Close()
                            Write-Output $output

                            $RetryOK = $false
                        } catch {
                            Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                            try {
                                #REPLACED - 2.10
                                #$json2 = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus" -Credential $cred -Method Get -ContentType "application/json"  -TimeoutSec 2

                                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/webCallControl/callStatus"

                                # Create a request object using the URI
                                $request = [System.Net.HttpWebRequest]::Create($uri)

                                $request.Credentials = $cred
                                $request.KeepAlive = $true
                                $request.Pipelined = $true
                                $request.AllowAutoRedirect = $false
                                $request.Method = "GET"
                                $request.ContentType = "application/json"

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
                                $json2 = $output | ConvertFrom-Json

                                $reader.Close()
                                $response.Close()
                                Write-Output $output

                                $RetryOK = $false
                            } catch {
                                $RetryOK = $true
                            }
                        }
                    }
                    if($RetryOK)
                    {
                        Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                        Write-Host "Exception:" $_.Exception.Message -foreground "red"
                        if($_.Exception.Response.StatusCode.value__ -eq "")
                        {
                            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                            $DeviceInfoText += "----------Ending Call----------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Response: " +$_.Exception.Response.StatusDescription+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                        else
                        {
                            $DeviceInfoText += "----------Ending Call----------`r`n"
                            $DeviceInfoText += "User: " +$SipUser+ "`r`n"
                            $DeviceInfoText += "Error: " +$_.Exception.Message+ "`r`n"
                            $DeviceInfoText += "-------------------------------`r`n"
                            $DeviceInfoText += "`r`n"
                        }
                    }

                }


                if($json2 -ne $null)
                {
                    Write-Host "Status: " $json2.Status
                    if($json2.Status -eq "2000")
                    {

                        $DeviceInfoText += "--------Ending Call--------`r`n"
                        $DeviceInfoText += "Call Handle: " +$json2.data.CallHandle+ "`r`n"
                        $DeviceInfoText += "Type: " +$json2.data.Type+ "`r`n"
                        $DeviceInfoText += "Protocol: " +$json2.data.Protocol+ "`r`n"
                        $DeviceInfoText += "CallState: " +$json2.data.CallState+ "`r`n"
                        $DeviceInfoText += "LineID: " +$json2.data.LineID+ "`r`n"
                        $DeviceInfoText += "RemotePartyName: " +$json2.data.RemotePartyName+ "`r`n"
                        $DeviceInfoText += "RemotePartyNumber: " +$json2.data.RemotePartyNumber+ "`r`n"
                        $DeviceInfoText += "DurationInSeconds: " +$json2.data.DurationInSeconds+ "`r`n"
                        $DeviceInfoText += "---------------------------`r`n"
                        $DeviceInfoText += "`r`n"

                        if($json2.data.CallState -eq "RingBack" -or $json2.data.CallState -eq "Connected")
                        {
                            $Script:CurrentCallID = $json2.data.CallHandle
                        }

                        Write-Host "Current CallID:" $Script:CurrentCallID

                    }
                }

                if($Script:CurrentCallID -ne "")
                {
                    $Ref = $Script:CurrentCallID
                    Write-Host "Current Call Reference: $Ref"

                    $body = @"
{
`"data`":
{
`"Ref`": `"$Ref`"
}
}
"@

                    Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
                    try {
                        #REPLACED - 2.10
                        #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/endCall" -Credential $cred -body $body -Method Post -ContentType "application/json"  -TimeoutSec 2

                        $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/callctrl/endCall"

                        # Create a request object using the URI
                        $request = [System.Net.HttpWebRequest]::Create($uri)

                        $request.Credentials = $cred
                        $request.KeepAlive = $true
                        $request.Pipelined = $true
                        $request.AllowAutoRedirect = $false
                        $request.Method = "POST"
                        $request.ContentType = "application/json"
                        #$request.Accept = "text/xml"

                        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
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
                        $json = $output | ConvertFrom-Json

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


                    if($json -ne $null)
                    {
                        Write-Host "Status: " $json.Status
                        if($json.Status -eq "2000")
                        {
                            Write-Host "Successfully Ended Call" -foreground "green"

                            $DeviceInfoText += "Successfully Ended Call!`r`n"

                        }
                        elseif($json.Status -eq "4000")
                        {
                            Write-Host "Failed to end call. Invalid input parameters" -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4001")
                        {
                            Write-Host "Failed to end call. Device busy." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4002")
                        {
                            Write-Host "Failed to end call. Line not registered." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4004")
                        {
                            Write-Host "Failed to end call. Operation Not Supported." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4005")
                        {
                            Write-Host "Failed to end call. Line does not exist." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4006")
                        {
                            Write-Host "Failed to end call. URLs not configured." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4007")
                        {
                            Write-Host "Failed to end call. Call Does Not Exist." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4009")
                        {
                            Write-Host "Failed to end call. Input Size Limit Exceeded." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "4010")
                        {
                            Write-Host "Failed to end call. Default Password Not Allowed." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }
                        elseif($json.Status -eq "5000")
                        {
                            Write-Host "Failed to end call. Failed to process request." -foreground "red"

                            $DeviceInfoText += "Failed to End Call!`r`n"
                        }


                    }
                    else
                    {
                        Write-Host "No json response received..."
                        $DeviceInfoText += "Failed to End Call!`r`n"
                    }

                }
                else
                {
                    Write-Host "ERROR: No Call ID Available..." -foreground "red"
                    $DeviceInfoText += "ERROR: Phone is currently not on a call...`r`n"
                }
                $Script:CurrentCallID = ""
                $DeviceInfoText += "`r`n"
                $objInformationTextBox.Text = $DeviceInfoText
            }
            else
            {
                #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
            }

        }
    }
}



#Discover VVX phones in IP Address Range  ============================================================
function DiscoverVVX
{
    $DiscoverSyncHash.VVXphones = @()
    $DiscoverSyncHash.NumberOfUsersDiscovered = 0

    $objInformationTextBox.Text = ""

    $FinalSummaryString = "`r`n`r`n-----------------------------------------------------------------------------------------`r`nFINAL DISCOVERY SUMMARY`r`n"

    foreach($IPRange in $DiscoverRangeListbox.Items)
    {

        [string]$IPRange = $IPRange

        if($IPRange.Contains("/")) #PROCESS A SUBNET STRING
        {
            $IPRangeSplit = $IPRange -split "/"
            [string]$Network = $IPRangeSplit[0]
            if($Network -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
            {
                [string]$Mask = $IPRangeSplit[1]

                if($Mask -match "^([0-9]|[1-2][0-9]|30)$")
                {

                    [Net.IPAddress]$NetworkIPAddress = [System.Net.IPAddress]::Parse($Network)
                    [int]$MaskNumber = [int]::Parse($Mask)

                    [UInt32] $DecimalMaskIP = [Convert]::ToUInt32($(("1" * $MaskNumber).PadRight(32, "0")), 2)

                    $i = 3; $DecimalNetworkIP = 0;
                    $NetworkIPAddress.GetAddressBytes() | ForEach-Object { [UInt32]$DecimalNetworkIP += $_ * [Math]::Pow(256, $i); $i-- }

                    [UInt32] $NetworkAddressInt = $DecimalNetworkIP -band $DecimalMaskIP
                    [UInt32]$InvertedMask = $DecimalMaskIP -bxor 0xFFFFFFFF
                    [UInt32] $BroadcastInt = $DecimalNetworkIP -bor $InvertedMask

                    $StartTempInt = $NetworkAddressInt + 1

                    $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
                    $Remainder = $StartTempInt % [Math]::Pow(256, $i)
                    ($StartTempInt - $Remainder) / [Math]::Pow(256, $i)
                    $StartTempInt = $Remainder
                    } )
                    #Start Address
                    [string]$StartTemp = [String]::Join('.', $DottedIP)

                    $EndTempInt = $BroadcastInt - 1
                    $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
                    $Remainder = $EndTempInt % [Math]::Pow(256, $i)
                    ($EndTempInt - $Remainder) / [Math]::Pow(256, $i)
                    $EndTempInt = $Remainder
                    } )
                    #End Address
                    [string]$EndTemp = [String]::Join('.', $DottedIP)

                }
                else
                {
                    Write-Host "ERROR: Bad subnet mask." -foreground "red"
                }
            }
            else
            {
                Write-Host "ERROR: Bad network address." -foreground
            }

        }
        else #PROCESS A RANGE STRING
        {
            $IPRangeSplit = $IPRange -split "-"
            [string]$StartTemp = $IPRangeSplit[0]
            [string]$EndTemp = $IPRangeSplit[1]
        }
        #Check IP Addresses
        if($StartTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
        {
            [string]$StartIP = $StartTemp
        }
        else
        {
            [string]$StartIP = ""
        }
        if($EndTemp -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
        {
            [string]$EndIP = $EndTemp
        }
        else
        {
            [string]$EndIP = ""
        }

        if($StartIP -ne "" -and $EndIP -ne "")
        {
        Write-Host ""
        Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
        Write-Host "Scanning Range of IP Addresses $StartIP to $EndIP. Starting Scan!" -foreground "Green"
        Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

        # Get Start Time
        $startDTMScan = (Get-Date)

        [int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $StartIP.split('.')
        [int]$FirstOctetEnd,[int]$SecondOctetEnd,[int]$ThirdOctetEnd,[int]$FourthOctetEnd = $EndIP.split('.')

        $FinalAddressOct1 = ""
        $FinalAddressOct2 = ""
        $FinalAddressOct3 = ""
        $FinalAddressOct4 = ""
        $DiscoverSyncHash.NumberOfUsersDiscovered = 0


        $UserIPAddressArray = @()

        foreach ($i in ($FirstOctet..$FirstOctetEnd))
        {
            $FinalAddressOct1 = "${i}."
            foreach ($j in ($SecondOctet..$SecondOctetEnd))
            {
                $FinalAddressOct2 = "${FinalAddressOct1}${j}."

                foreach ($k in ($ThirdOctet..$ThirdOctetEnd))
                {
                    $FinalAddressOct3 = "${FinalAddressOct2}${k}."

                    foreach ($l in ($FourthOctet..$FourthOctetEnd))
                    {
                        # Get Start Time
                        #$startDTM = (Get-Date)

                        $FinalAddressOct4 = "${FinalAddressOct3}${l}"

                        [string]$ClientIP = $FinalAddressOct4

                        [String[]]$UserIPAddressArray += $ClientIP

                    }
                }
            }
        }


        $CurrentNumberOfConnections = 0
        $AllowedConnections = 10
        $NumberOfLoops = 0
        # Get Start Time
        $startDTM = (Get-Date)



        $Jobs = @()
        Write-Host "Starting Discovery..." -foreground "green"
        foreach($IPAddress in $UserIPAddressArray)
        {

            Write-Host "Attempting to discover: $IPAddress" -foreground "yellow"
            #Write-Host "-----------------------------------------------------------------------------------------"

            #This is to ensure randomness of Get-Random command for port selection...
            Start-Sleep -Milliseconds 1

            [string]$LocalIP = GetLocalIP

            ##MOVED FROM THREADED SECTION
            DO
            {
                [string]$ticks = (get-date).ticks
                [int]$tick32 = $ticks.substring($ticks.length - 8, 8)
                #Write-Host "TICKS: LONG: $ticks INT: $tick32"
                $LocalPort = Get-Random -min 10000 -max 65535 -SetSeed $tick32  #"51234"
                #Write-Host "Checking if local ${LocalIP}:${LocalPort} is in use for $IPAddress" -foreground "blue"
            }while(!(Check-UsedPortsUDP $LocalIP $LocalPort))
            #####MOVED FROM OTHER SECTION

            Write-Host "Checking local ${LocalIP}:${LocalPort}" -foreground "green"


            $objConnectionData = New-Object -Type PSCustomObject -Property @{
            strIPAddress = $IPAddress
            strUsername = $VVXHTTPUsername
            strPassword = $VVXHTTPPassword
            strLocalIP = $LocalIP
            strLocalPort = $LocalPort
            strAdminModePassword = $VVXAdminModePassword
            strDiscoveryWaitTime = $DiscoveryWaitTime
            objRunspacePool = $objRunspacePool
            objPowerShellPipeline = $Null
            objIAsyncResult = $Null
            }

            $objConnectionData.objPowerShellPipeline = [System.Management.Automation.PowerShell]::Create()
            $objConnectionData.objPowerShellPipeline.AddScript($sbDiscoverVVXIPScript) | Out-Null
            $objConnectionData.objPowerShellPipeline.AddArgument($objConnectionData) | Out-Null
            $objConnectionData.objPowerShellPipeline.AddArgument($DiscoverSyncHash) | Out-Null
            $objConnectionData.objPowerShellPipeline.RunspacePool = $objConnectionData.objRunspacePool

            $Jobs += New-Object PSObject -Property @{
               Pipe = $objConnectionData.objPowerShellPipeline
               Result = $objConnectionData.objPowerShellPipeline.BeginInvoke()
            }

            $CurrentNumberOfConnections++


            #Check the number of concurrent connections is more than the number of allow connections
            if($AllowedConnections -gt $UserIPAddressArray.length -and $CurrentNumberOfConnections -eq $UserIPAddressArray.length)
            {
                Do {
                       Start-Sleep -Milliseconds 50
                       #Write-Host "Checking Jobs... " $Jobs.Result.IsCompleted

                    } While ( $Jobs.Result.IsCompleted -contains $false )
                    Write-Host "Batch completed! Starting new batch..." -foreground "blue"
                    $CurrentNumberOfConnections = 0
                    $NumberOfLoops++
                    $Jobs = @()
            }
            elseif((([Math]::Floor([decimal]($UserIPAddressArray.length / $AllowedConnections))) -eq $NumberOfLoops) -and $CurrentNumberOfConnections -eq ($UserIPAddressArray.length % $AllowedConnections))
            {
                Do {
                        Start-Sleep -Milliseconds 50
                        #Write-Host "Checking Jobs... " $Jobs.Result.IsCompleted

                    } While ( $Jobs.Result.IsCompleted -contains $false )
                    Write-Host "Batch completed! Starting new batch..." -foreground "blue"
                    $CurrentNumberOfConnections = 0
                    $NumberOfLoops++
                    $Jobs = @()
            }
            else
            {
                $Remainder = $CurrentNumberOfConnections % $AllowedConnections
                if($Remainder -eq 0)
                {
                    Do {
                       Start-Sleep -Milliseconds 50
                       #Write-Host "Checking Jobs... " $Jobs.Result.IsCompleted

                    } While ( $Jobs.Result.IsCompleted -contains $false )
                    Write-Host "Batch completed! Starting new batch..." -foreground "blue"
                    $CurrentNumberOfConnections = 0
                    $NumberOfLoops++
                    $Jobs = @()
                }
            }

            [System.Windows.Forms.Application]::DoEvents()
            if($DiscoverSyncHash.CancelScan)
            {break}

        }

        # Get End Time
        $endDTM = (Get-Date)
        # Echo Time elapsed
        Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds"
        Write-Host "-----------------------------------------------------------------------------------------"

        }
        else
        {
            Write-Host "IP Addresses used in IP Range are incorrent. Please correct the address range and try again." -foreground "red"
            return
        }

        $NumberDiscovered = $DiscoverSyncHash.NumberOfUsersDiscovered
        Write-Host "Discovered $NumberDiscovered VVX phone(s) in Range $StartIP - $EndIP!" -foreground "green"
        $FinalSummaryString += "Discovered $NumberDiscovered VVX phone(s) in Range $StartIP - $EndIP`r`n"
    }
    $FinalSummaryString += "-----------------------------------------------------------------------------------------`r`n`r`n"
    Write-Host $FinalSummaryString -foreground "green"
}


function ExportDataToCSV
{
    $filename = ""

    Write-Host "Exporting..." -foreground "yellow"
    [string] $pathVar = "c:\"
    $Filter="All Files (*.*)|*.*"
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $objDialog = New-Object System.Windows.Forms.SaveFileDialog
    #$objDialog.InitialDirectory =
    $objDialog.FileName = "VVXPhoneData.csv"
    $objDialog.Filter = $Filter
    $objDialog.Title = "Export File Name"
    $objDialog.CheckFileExists = $false
    $Show = $objDialog.ShowDialog()
    if ($Show -eq "OK")
    {
        [string]$content = ""
        [string] $filename = $objDialog.FileName
    }

    if($filename -ne "")
    {
    if($ExportAdvancedCheckBox.Checked)
    {
        $csv = "`"Sip User`",`"Client IP`",`"Client Firmware`",`"Lync Server`",`"MAC Address`",`"VoicePolicy`",`"PINPolicy`",`"LineUri`",`"IsPinSet`",`"DialPlan`",`"IsLockedOut`"`r`n"

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            [string]$ClientApp = $vvxphone.ClientApp
            [string]$SipUser = $vvxphone.SipUser

            $userArray = $SipUser.Split(" ")
            $SipUser = $userArray[0]

            if(!$SipUser.Contains(" "))
            {
                if($ClientApp.length -gt 13)
                {
                    $startValue = $ClientApp.Length - 12
                    $EndValue = $ClientApp.Length - $startValue
                    $MACAddress = $ClientApp.Substring($startValue,$EndValue)
                    #Test that it's a polycom MAC address
                    if($MACAddress -imatch "0004f2" -or $MACAddress -imatch "64167F")
                    {
                        $MACAddressString = $MACAddress
                    }
                    else
                    {
                        $MACAddressString = ""
                    }
                }

                if(!($SipUser -match "VVXNot@LoggedIn"))
                {
                    $UserSettings = Invoke-Expression "Get-CsUser -Identity sip:${SipUser} -ErrorAction SilentlyContinue"
                    if($UserSettings -eq $null)
                    {
                        $UserSettings = Invoke-Expression "Get-CsCommonAreaPhone -Identity sip:${user} -ErrorAction SilentlyContinue"
                    }
                    $UserPINSettings = Invoke-Expression "Get-CsClientPinInfo -Identity sip:${SipUser}"
                    $command = "Get-CsEffectivePolicy"
                    if(Get-Command $command -errorAction SilentlyContinue)
                    {
                        $UserEffective = Invoke-Expression "Get-CsEffectivePolicy -Identity sip:${SipUser}"
                        [string]$VoicePolicy = $UserEffective.VoicePolicy
                        [string]$PinPolicy = $UserEffective.UserPinPolicy
                    }
                    else
                    {
                        [string]$VoicePolicy = $UserSettings.VoicePolicy
                        if($VoicePolicy -eq "")
                        {$VoicePolicy="Automatic"}

                        [string]$PinPolicy = $UserSettings.$PinPolicy
                        if($PinPolicy -eq "")
                        {$PinPolicy="Automatic"}
                    }
                    $csv += "`"" +[string]$vvxphone.SipUser +"`",`""+ [string]$vvxphone.ClientIP + "`",`"" +[string]$vvxphone.ClientApp +"`",`""+[string]$vvxphone.LyncServer +"`",`"" + $MACAddressString + "`",`"" + $VoicePolicy + "`",`"" + $PinPolicy + "`",`"" + $UserSettings.LineUri + "`",`"" + $UserPINSettings.IsPinSet + "`",`"" + $UserSettings.DialPlan + "`",`"" + $UserPINSettings.IsLockedOut + "`"`r`n"

                }
                else
                {
                    $csv += "`"" +[string]$vvxphone.SipUser +"`",`""+ [string]$vvxphone.ClientIP + "`",`"" +[string]$vvxphone.ClientApp +"`",`""+[string]$vvxphone.LyncServer +"`",`"" + $MACAddressString + "`",`"NOT APPLICABLE`",`"NOT APPLICABLE`",`"NOT APPLICABLE`",`"NOT APPLICABLE`",`"NOT APPLICABLE`",`"NOT APPLICABLE`"`r`n"
                }
            }

        }
    }
    else
    {
        $csv = "`"Sip User`",`"Client IP`",`"Client Firmware`",`"Lync Server`",`"MAC Address`"`r`n"

        foreach($vvxphone in $DiscoverSyncHash.VVXphones)
        {
            $ClientApp = $vvxphone.ClientApp

            if($ClientApp.length -gt 13)
            {
                $startValue = $ClientApp.Length - 12
                $EndValue = $ClientApp.Length - $startValue
                $MACAddress = $ClientApp.Substring($startValue,$EndValue)
                #Test that it's a polycom MAC address
                if($MACAddress -imatch "0004f2" -or $MACAddress -imatch "64167F")
                {
                    $MACAddressString = $MACAddress
                }
                else
                {
                    $MACAddressString = ""
                }
            }

            $csv += "`"" +[string]$vvxphone.SipUser +"`",`""+ [string]$vvxphone.ClientIP + "`",`"" +[string]$vvxphone.ClientApp +"`",`""+[string]$vvxphone.LyncServer +"`",`"" + $MACAddressString + "`"`r`n"
        }
    }

    #Excel seems to only like UTF-8 for CSV files...
    $csv | out-file -Encoding UTF8 -FilePath $filename -Force
    Write-Host "Completed Export." -foreground "yellow"
    }
    else
    {
        Write-Host "INFO: Cancelled Export." -foreground "Yellow"
    }
}


function ImportDataFromCSV
{
    $DiscoverSyncHash.VVXphones = @()

    #File Dialog
    [string] $pathVar = $pathbox.Text
    $Filter="All Files (*.*)|*.*"
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $objDialog = New-Object System.Windows.Forms.OpenFileDialog
    $objDialog.InitialDirectory =
    $objDialog.FileName = "VVXphoneData.csv"
    $objDialog.Filter = $Filter
    $objDialog.Title = "Select File Name"
    $objDialog.CheckFileExists = $false
    $Show = $objDialog.ShowDialog()
    if ($Show -eq "OK")
    {
        [string]$content = ""
        [string] $filename = $objDialog.FileName
        $UserRecords = Import-Csv $filename


        foreach($UserRecord in $UserRecords)
        {
            $theSipUser = $UserRecord."Sip User"
            $ClientIP = $UserRecord."Client IP"
            $ClientApp = $UserRecord."Client Firmware"
            $LyncServer = $UserRecord."Lync Server"
            $MACAddress = $UserRecord."MAC Address"

            if($RescanCheckBox.Checked -eq $true -and $ClientIP -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
            {
                DiscoverVVXIP -IPAddress $ClientIP
            }
            else
            {
                if($theSipUser -ne "" -and $theSipUser -ne $null -and $LyncServer -ne "" -and $LyncServer -ne $null -and $ClientApp -ne "" -and $ClientApp -ne $null)
                {
                    #ADD USER
                    Write-Host "Adding user $theSipUser to database..." -foreground "green"
                    #$script:NumberOfUsersImported++
                    $DiscoverSyncHash.NumberOfUsersImported++
                    $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$theSipUser";"ClientIP" = "$ClientIP";"ClientApp" = "$ClientApp";"LyncServer"="$LyncServer";"MACAddress"="$MACAddress"})
                }
            }
        }
        Write-Host "Imported" $DiscoverSyncHash.NumberOfUsersImported "Users."
        #$script:NumberOfUsersImported = 0
        $DiscoverSyncHash.NumberOfUsersImported = 0
    }
    else
    {
        Write-Host "INFO: Cancelled Import." -foreground "Yellow"
    }
}

function DiscoverVVXIP([string]$IPAddress)
{
    [string]$LocalIP = GetLocalIP

    #######################################
    [string]$returndata = ""
    $receivebytes = $null
    $LocalPort = "51234"    #Invoke-Expression "Get-Random -min 50000 -max 65535"
    $ClientIP = $IPAddress
    $serverip = "${LocalIP}:${LocalPort}"
    $call_id = "${time}msgto${phoneid}"

#This is a Notify message
$message = @"
NOTIFY sip:${phoneid}:5060 SIP/2.0
Via: SIP/2.0/UDP ${serverip}
From: <sip:discover>;tag=1530231855-106746376154
To: <sip:${ClientIP}:5060>
Call-ID: ${call_id}
CSeq: 1500 NOTIFY
Contact: <sip:${phoneid}>
Content-Length: 0


"@

        $Port = 5060

        ###Can only achieve 600ms per device with this method! Due to 500ms UDP receive delay  http://msdn.microsoft.com/en-us/library/system.net.sockets.socket.sendtimeout
        #$udpobject = new-Object system.Net.Sockets.Udpclient($LocalPort)
        #$udpobject.Client.ReceiveTimeout = 150   ###Minimum setting is 500ms

        $a = new-object system.text.asciiencoding
        $byte = $a.GetBytes($message)

        #Use base level UDP socket implementation for faster for discovery!
        $Socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,
                        [Net.Sockets.SocketType]::Dgram,
                        [Net.Sockets.ProtocolType]::Udp)

        $LocalEndpoint = New-Object system.net.ipendpoint([System.Net.IPAddress]::Parse($LocalIP),$LocalPort)
        $Socket.Bind($LocalEndpoint)
        $Socket.Connect($ClientIP,$Port)
        try
        {
            [Void]$Socket.Send($byte)
        }
        catch
        {
            "Unable to connect to host {0}:{1}" -f $ClientIP,$Port
        }

        # Buffer to hold the returned Bytes.
        [Byte[]]$buffer = New-Object -TypeName Byte[]($Socket.ReceiveBufferSize)
        $BytesReceivedError = $false

        Try {
                $theDiscoveryWaitTime = $DiscoveryWaitTime * 1000
                #Write-Host "DISCOVERY WAIT TIME: $discoveryWaitTime"
                if($Socket.Poll($theDiscoveryWaitTime,[System.Net.Sockets.SelectMode]::SelectRead)) {
                    $receivebytes = $Socket.Receive($buffer)
                }
                else {
                    // Timed out
                    Write-Host "INFO: No response from $ClientIP." -Foreground "yellow"
                    $objInformationTextBox.Text += "No Response from $ClientIP.`n"
                    $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                    $objInformationTextBox.ScrollToCaret()
                    $BytesReceivedError = $true
                }
        }
        Catch {

            #Write-Warning "$($Error[0])"
            Write-Host "INFO: No response from $ClientIP." -Foreground "yellow"
            $objInformationTextBox.Text += "No Response from $ClientIP.`n"
            $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
            $objInformationTextBox.ScrollToCaret()
            $BytesReceivedError = $true
        }
        if(!$BytesReceivedError)
        {
            if ($receivebytes) {
                [string]$returndata = $a.GetString($buffer, 0, $receivebytes)
                Write-Host $returndata
                [string]$SIPUserName = ""
                [string]$LyncServer = ""
                [string]$ClientApp = ""
                if($returndata -imatch "SIP/2.0 200 OK")
                {
                    if($returndata -imatch "Contact: <sip:" -and $returndata -imatch "PolycomVVX")
                    {
                        [string]$returndataSplit = ($returndata -split 'Contact: <sip:')[1]
                        if($returndataSplit.Contains(";"))
                        {
                            [string]$SIPUserName = ($returndataSplit -split ';')[0]

                            if($returndata -imatch "targetname=")
                            {
                                [string]$LyncServerStringTemp = ($returndata -split "targetname=`"")[1]
                                [string]$LyncServer = ($LyncServerStringTemp -split "`",")[0]
                            }
                            if($returndata -imatch "User-Agent: ")
                            {
                                [string]$ClientAppTemp = ($returndata -split 'User-Agent: ')[1]
                                [string]$ClientApp = ($ClientAppTemp -split "`r`n")[0]
                            }
                            Write-Host "Discovered User: $SIPUserName on $LyncServer running app $ClientApp" -Foreground "green"

                            if($SIPUserName -ne "" -and $LyncServer -ne "" -and $ClientApp -ne "")
                            {
                                $NumberOfUsersDiscovered++

                                #Confirm how many phones this user is logged into Lync
                                $numberofphones = 1
                                foreach($vvxphone2 in $vvxphones)
                                {
                                    [string]$SipUser2 = $vvxphone2.SipUser
                                    [string]$SipUserLower = $SipUser2.ToLower()
                                    [string]$SIPUserNameLower = $SIPUserName.ToLower()
                                    if($SipUserLower -eq $SIPUserNameLower)
                                    {
                                        if($numberofphones -gt 1)
                                        {
                                            $SipUser = "$SIPUserName $loop"
                                        }
                                        $numberofphones++
                                    }
                                }
                                #Check if the user has multiple phones
                                if($numberofphones -gt 1)
                                {
                                    $SIPUserName = "$SIPUserName $numberofphones"
                                }


                                $objInformationTextBox.Text += "Discovered Device $SIPUserName.`n"
                                $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                                $objInformationTextBox.ScrollToCaret()
                                Write-Host "Discovered Device for $SIPUserName at $ClientIP." -Foreground "green"

                                #$script:NumberOfUsersImported++
                                $DiscoverSyncHash.NumberOfUsersImported++
                                $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$SIPUserName";"ClientIP" = "$ClientIP";"ClientApp" = "$ClientApp";"LyncServer"="$LyncServer"})
                            }

                        }
                        elseif($returndataSplit -imatch "VVX500@" -or $returndataSplit -imatch "VVX501@" -or $returndataSplit -imatch "VVX600@" -or $returndataSplit -imatch "VVX601@" -or $returndataSplit -imatch "VVX300@" -or $returndataSplit -imatch "VVX301@" -or $returndataSplit -imatch "VVX310@" -or $returndataSplit -imatch "VVX311@" -or $returndataSplit -imatch "VVX400@" -or $returndataSplit -imatch "VVX401@" -or $returndataSplit -imatch "VVX410@" -or $returndataSplit -imatch "VVX411@" -or $returndataSplit -imatch "VVX200@" -or $returndataSplit -imatch "VVX201@") {

                            $objInformationTextBox.Text += "Discovered device with no user logged in.`n"
                            $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                            $objInformationTextBox.ScrollToCaret()

                            if($returndata -imatch "User-Agent: ")
                            {
                                [string]$ClientAppTemp = ($returndata -split 'User-Agent: ')[1]
                                [string]$ClientApp = ($ClientAppTemp -split "`r`n")[0]
                            }

                            $numberOfNotLoggedInPhones = 0
                            foreach($vvxphone in $vvxphones) {
                                [string]$PhoneSipUser = $vvxphone.SipUser
                                if($PhoneSipUser -match "VVXNot@LoggedIn") {
                                    $numberOfNotLoggedInPhones++
                                }
                            }

                            $theSipUser = "VVXNot@LoggedIn_$numberOfNotLoggedInPhones"
                            Write-Host "Discovered Device with no user logged in at $ClientIP. Naming phone $theSipUser." -Foreground "green"
                            $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$theSipUser";"ClientIP" = "$ClientIP";"ClientApp" = "$ClientApp";"LyncServer"="NOT AVAILABLE"})

                        }
                    }
                    else {
                        Write-Host "INFO: Ignoring SIP response. Non VVX response."
                    }
                }
                else {
                    Write-Host "ERROR RESPONSE:" -Foreground "red"
                    Write-Host "$returndata" -Foreground "red"
                    $objInformationTextBox.Text += "Error in response from endpoint. Ignoring device.`n"
                    $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                    $objInformationTextBox.ScrollToCaret()
                }
            }
            else {
                Write-Host "INFO: No data received from $Computername on port $Port" -foreground "yellow"
            }
        }
        $Socket.Close()
        $Socket.Dispose()
        $Socket = $null
}

function RebootAllVVX2
{

    $objInformationTextBox.Text = "Rebooting all phones:`n`n"
    if($DiscoverSyncHash.VVXphones.length -eq 0)
    {
            $objInformationTextBox.Text += "There are no phones to reboot."
    }

    foreach($vvxphone in $DiscoverSyncHash.VVXphones)
    {
        $SipUser = $vvxphone.SipUser
        $userArray = $SipUser.Split(" ")
        $SipUser = $userArray[0]

        $ClientIP = $vvxphone.ClientIP
        $ClientApp = $vvxphone.ClientApp

        if($ClientIP -ne "IP NOT IN LYNC DATABASE")
        {

            ##REBOOT REST CALL
            $user = $script:AdminUsername
            $pass= $script:AdminPassword
            $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)

            Write-Host "CONNECTING TO: $(Script:Proto)://${ClientIP}:${WebServicePort}" -foreground "green"
            try {
                #REPLACED - 2.10
                #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart"

                # Create a request object using the URI
                $request = [System.Net.HttpWebRequest]::Create($uri)

                $request.Credentials = $cred
                $request.KeepAlive = $true
                $request.Pipelined = $true
                $request.AllowAutoRedirect = $false
                $request.Method = "POST"
                $request.ContentType = "application/json"
                #$request.Accept = "text/xml"

                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                $json = $output | ConvertFrom-Json

                $reader.Close()
                $response.Close()
                Write-Output $output


            } catch {
                $RetryOK = $true
                if($_.Exception.Message -imatch "The underlying connection was closed")
                {
                    Write-Host "INFO: TLS failed: Retrying 1..." -foreground "yellow"
                    try {
                        #REPLACED - 2.10
                        #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                        $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart"

                        # Create a request object using the URI
                        $request = [System.Net.HttpWebRequest]::Create($uri)

                        $request.Credentials = $cred
                        $request.KeepAlive = $true
                        $request.Pipelined = $true
                        $request.AllowAutoRedirect = $false
                        $request.Method = "POST"
                        $request.ContentType = "application/json"
                        #$request.Accept = "text/xml"

                        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                        $json = $output | ConvertFrom-Json

                        $reader.Close()
                        $response.Close()
                        Write-Output $output


                        $RetryOK = $false
                    } catch {
                        Write-Host "INFO: TLS failed: Retrying 2..." -foreground "yellow"
                        try {
                            #REPLACED - 2.10
                            #$json = Invoke-RestMethod -Uri "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart" -Credential $cred -Method Post -ContentType "application/json"  -TimeoutSec 2

                            $uri = "$(Script:Proto)://${ClientIP}:${WebServicePort}/api/v1/mgmt/safeRestart"

                            # Create a request object using the URI
                            $request = [System.Net.HttpWebRequest]::Create($uri)

                            $request.Credentials = $cred
                            $request.KeepAlive = $true
                            $request.Pipelined = $true
                            $request.AllowAutoRedirect = $false
                            $request.Method = "POST"
                            $request.ContentType = "application/json"
                            #$request.Accept = "text/xml"

                            $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes("")
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
                            $json = $output | ConvertFrom-Json

                            $reader.Close()
                            $response.Close()
                            Write-Output $output


                            $RetryOK = $false
                        } catch {
                            $RetryOK = $true
                        }
                    }
                }
                if($RetryOK)
                {
                    Write-Host "ERROR: Failed to connect to phone..." -foreground "red"
                    Write-Host "Exception:" $_.Exception.Message -foreground "red"
                    if($_.Exception.Response.StatusCode.value__ -eq "")
                    {
                        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -foreground "red"
                        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -foreground "red"
                    }
                }
            }


            if($json -ne $null)
            {
                Write-Host "Status: " $json.Status
                if($json.Status -eq "2000")
                {
                    Write-Host "Successfully rebooted" -foreground "green"
                    $objInformationTextBox.Text += "${SipUser}: Rebooted OK`n`n"
                }
                elseif($json.Status -eq "4000")
                    {
                        Write-Host "Failed reboot. Invalid input parameters" -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Invalid input parameters.`n`n"
                    }
                    elseif($json.Status -eq "4001")
                    {
                        Write-Host "Failed reboot. Device busy." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Device busy.`n`n"
                    }
                    elseif($json.Status -eq "4002")
                    {
                        Write-Host "Failed reboot. Line not registered." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Line not registered.`n`n"
                    }
                    elseif($json.Status -eq "4004")
                    {
                        Write-Host "Failed reboot. Operation Not Supported." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Operation Not Supported.`n`n"
                    }
                    elseif($json.Status -eq "4005")
                    {
                        Write-Host "Failed reboot. Line does not exist." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Line does not exist.`n`n"
                    }
                    elseif($json.Status -eq "4006")
                    {
                        Write-Host "Failed reboot. URLs not configured." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. URLs not configured.`n`n"
                    }
                    elseif($json.Status -eq "4007")
                    {
                        Write-Host "Failed reboot. Call Does Not Exist." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Call Does Not Exist.`n`n"
                    }
                    elseif($json.Status -eq "4009")
                    {
                        Write-Host "Failed reboot. Input Size Limit Exceeded." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Input Size Limit Exceeded.`n`n"
                    }
                    elseif($json.Status -eq "4010")
                    {
                        Write-Host "Failed reboot. Default Password Not Allowed." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Default Password Not Allowed.`n`n"
                    }
                    elseif($json.Status -eq "5000")
                    {
                        Write-Host "Failed reboot. Failed to process request." -foreground "red"
                        $objInformationTextBox.Text += "${SipUser}: Failed reboot. Failed to process request.`n`n"
                    }
            }
            else
            {
                Write-Host "No json response received..."
                $objInformationTextBox.Text += "${SipUser}: Failed reboot. No response received.`n`n"
            }
        }
        else
        {
            #Write-Host "Cannot connect to $SipUser as there is no IP NOT IN LYNC DATABASE" -foreground "yellow"
        }
    }
}


#Set the PIN for selected users ============================================================
function SetPin
{
    $objInformationTextBox.Text = ""

    $objInformationTextBox.Text = "The current PIN policy of the system is:`n`n"
    $PINPolicy = Invoke-Expression "Get-CsPinPolicy"
    $pinlength = $PINPolicy.MinPasswordLength
    $pinhistory = $PINPolicy.PINHistoryCount
    $pincommon = $PINPolicy.AllowCommonPatterns
    $objInformationTextBox.Text += "Min PIN Length: $pinlength`nPIN History Count: $pinhistory`nAllow Common Patterns: $pincommon`n`n"

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $userArray = $user.Split(" ")
        $user = $userArray[0]
        $pin = $PinTextBox.text
        if(!($user -imatch "VVXNot@LoggedIn"))
        {
            if($user -ne "" -and $user -ne $null)
            {
                if($PinTextBox.text -ne "")
                {
                    write-host "------------------------------------------------------"
                    write-host "RUNNING COMMAND: Set-CsClientPin -Identity sip:${user} -Pin $pin"

                    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                    $pinfo.FileName = "powershell.exe"
                    $pinfo.RedirectStandardError = $true
                    $pinfo.RedirectStandardOutput = $true
                    $pinfo.UseShellExecute = $false
                    $pinfo.Arguments = "`"Import-Module Lync`nSet-CsClientPin -Identity sip:${user} -Pin $pin`""
                    $p = New-Object System.Diagnostics.Process
                    $p.StartInfo = $pinfo
                    $p.Start() | Out-Null
                    $p.WaitForExit()
                    $stdout = $p.StandardOutput.ReadToEnd()
                    $stderr = $p.StandardError.ReadToEnd()

                    Write-Host $stderr.Trim()
                    Write-Host $stdout.Trim()

                    if($stdout -imatch ".*error.*" -or $stderr -imatch ".*error.*")
                    {
                        $objInformationTextBox.Text += "${user}: PIN set FAILED. Make sure the PIN matches the system PIN policy.`n`n"
                    }
                    else
                    {
                        $objInformationTextBox.Text += "${user}: Set PIN to: $pin`n`n"
                    }

                    write-host "------------------------------------------------------"

                }
                else
                {
                    $result = Invoke-Expression "Set-CsClientPin -Identity sip:${user}"
                    Write-Host "RUNNING COMMAND: Set-CsClientPin -Identity sip:${user}"
                    $setPin = $result.Pin
                    $objInformationTextBox.Text += "${user}: Set PIN to a random value: $setPin`n`n"

                    #Possible Future option:
                    #Set-CsPinSendCAWelcomeMail -UserUri bob.kelly@mylynclab.com -From Service.Desk@mylynclab.com �SmtpServer 2013ENTEX001.mylynclab.com -TemplatePath c:/CAWelcomeEmailTemplate.html -Subject "Your Desk Phone PIN Number" -Force
                }
            }
        }
        else
        {
            Write-Host "Error: This is a VVX device, not a logged in user." -foreground "red"
        }
    }
}

# Lock the PIN of selected users  ============================================================
function LockPin
{
    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $userArray = $user.Split(" ")
        $user = $userArray[0]
        if(!($user -imatch "VVXNot@LoggedIn"))
        {
            if($user -ne "" -and $user -ne $null)
            {
                Invoke-Expression "Lock-CsClientPin -Identity sip:${user}"
                Write-Host "RUNNING COMMAND: Lock-CsClientPin -Identity sip:${user}"
                UpdatePhoneInfoText
            }
        }
        else
        {
            Write-Host "Error: This is a VVX device, not a logged in user." -foreground "red"
        }
    }
}

#Unlock the PIN of selected users  ============================================================
function UnlockPin
{
    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $userArray = $user.Split(" ")
        $user = $userArray[0]
        if(!($user -match "VVXNot@LoggedIn"))
        {
            if($user -ne "" -and $user -ne $null)
            {
                Invoke-Expression "Unlock-CsClientPin -Identity sip:${user}"
                Write-Host "RUNNING COMMAND: Unlock-CsClientPin -Identity sip:${user}"
                UpdatePhoneInfoText
            }
        }
        else
        {
            Write-Host "Error: This is a VVX device, not a logged in user." -foreground "red"
        }
    }
}

# Get the local IP of the server for return response  ============================================================
function GetLocalIP
{
    # Get Networking Adapter Configuration
    $Computer = "."
    $IPconfigset = Get-WmiObject Win32_NetworkAdapterConfiguration
    $LocalIP = ""

    # Iterate and get IP address
    $count = 0
    foreach ($IPConfig in $IPConfigSet) {
       if ($Ipconfig.IPaddress) {
          foreach ($addr in $Ipconfig.Ipaddress) {
            #write-host "IP Address   : $addr"
            $count++
            if($addr -match "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b")
            {
                $LocalIP = $addr
                break;
            }
          }
       }
    }
    if ($count -eq 0) {write-host "ERROR: No IP addresses found on system." -foreground "red"}
    else {
    #write-host "Discovered local IP address $LocalIP." -foreground "green"
    }

    return [string]$LocalIP
}

#Test the FTP server  ============================================================
function TestFTPServer
{
    $ftp = $TestFTPBox.text

    if($ftp -imatch "ftp://")
    {

        Write-Host "Connecting to FTP Server..."
        $objInformationTextBox.Text = ""


        #ftp server creds for Polycom phones
        $user = "PlcmSpIp"
        $pass = "PlcmSpIp"

        $objInformationTextBox.Text += "Connecting to FTP Server...`n"
        $objInformationTextBox.Text += "User: $user, Pass: $pass`n`n"

        [System.Net.FtpWebRequest]$request = [System.Net.WebRequest]::Create($ftp)
        $request.Method = [System.Net.WebRequestMethods+FTP]::listdirectorydetails
        $request.Credentials = New-Object System.Net.NetworkCredential($user,$pass)

        try{

        $response = $request.GetResponse()

        $stream = $response.GetResponseStream()

        $buffer = new-object System.Byte[] 1024
        $encoding = new-object System.Text.AsciiEncoding

        $outputBuffer = ""
        $foundMore = $false

        ## Read all the data available from the stream, writing it to the
        ## output buffer when done.
        do
        {
            ## Allow data to buffer for a bit
            start-sleep -m 500

            ## Read what data is available
            $foundmore = $false
            $stream.ReadTimeout = 500

            do {
            try    {
                $read = $stream.Read($buffer, 0, 1024)
                if($read -gt 0)
                {
                    $foundmore = $true
                    $outputBuffer += ($encoding.GetString($buffer, 0, $read))
            }
            } catch { $foundMore = $false; $read = 0 }
            } while($read -gt 0)
        } while($foundmore)

        $outputBuffer
        Write-Host ""
        Write-Host "----------------FTP DIRECTORY LISTUP-------------------"
        Write-Host ""
        Write-Host "$outputBuffer"
        Write-Host "-------------------------------------------------------"
        Write-Host ""


        }catch [System.Net.WebException]{
            [string]$res = $_.Exception.ToString()
            Write-Host "ERROR: Unable to connect to FTP Server. Please check the FQDN/IP Address specified.`n`n" -foreground red
            Write-Host $res -foreground red
            $objInformationTextBox.Text += "ERROR: Unable to connect to FTP Server. Please check the FQDN/IP Address specified. Also check that a user: $user, with password: $pass has been configured on the FTP server."
        }
        if($outputBuffer -ne $null)
        {
            if($outputBuffer -imatch "000000000000.cfg")
            {
                $objInformationTextBox.Text += "Found: 000000000000.cfg`n"
                $objInformationTextBox.Text += "Successfully found base config file.`n`n"

                $uri = New-Object System.Uri("$ftp/000000000000.cfg")
                $webclient = New-Object System.Net.WebClient
                $webclient.Credentials = New-Object System.Net.NetworkCredential($user,$pass)

                #Check Temp Directory if it doesn't exist
                if (!(Test-Path $tempFTPTestFilePath)) {md $tempFTPTestFilePath}

                $webclient.DownloadFile($uri,"${tempFTPTestFilePath}000000000000.cfg")
                [string]$content = [IO.File]::ReadAllText("${tempFTPTestFilePath}000000000000.cfg")
                Write-Host ""
                Write-Host "------------000000000000.cfg CONTENT-------------------"
                Write-Host ""
                Write-Host "$content"
                Write-Host "-------------------------------------------------------"
                Write-Host ""
                if($content -imatch "CONFIG_FILES")
                {
                    #Example: CONFIG_FILES="Lync_DeviceSet.cfg, Lync_Shared.cfg, Debug.cfg"
                    $splitFile = $content -Split "CONFIG_FILES"
                    [string]$splitFile2 = $splitFile[1]
                    $FileOrder = $splitFile2.Split("`"")
                    $theString = $FileOrder[1]
                    $objInformationTextBox.Text += "Configuration File Order: $theString `n`n"

                    $individualFiles = $theString.Split(",")

                    foreach($file in $individualFiles)
                    {
                        $file = $file.trim()
                        if($outputBuffer -imatch "$file")
                        {
                            $objInformationTextBox.Text += "Found: $file on FTP server.`n"
                        }
                        else
                        {
                            $objInformationTextBox.Text += "ERROR: Can't find $file on FTP server. Either remove this file from the CONFIG_FILES line in the 000000000000.cfg file, or create this file and put it on the FTP server."
                        }
                    }
                    $objInformationTextBox.Text += "`n"
                }
                else
                {
                    Write-host "ERROR: Base configuration file doesn't contain: CONFIG_FILES tag. Without this the VVX can't find it's config files." -foreground red
                    $objInformationTextBox.Text += "ERROR: Base configuration file doesn't contain: CONFIG_FILES tag. Without this the VVX can't find it's config files.`n`n"
                }

            }
            else
            {
                $objInformationTextBox.Text += "ERROR: Unable to find: 000000000000.cfg in the home directory of user: $user. You either need this file or one named <MAC Address>.cfg for the phone to know which config files to download.`n`n"
            }
            #Check for MAC files
            foreach($vvxphone in $DiscoverSyncHash.VVXphones)
            {
                $SipUser = $vvxphone.SipUser
                $ClientApp = $vvxphone.ClientApp

                if($ClientApp.length -gt 13)
                {
                    $startValue = $ClientApp.Length - 12
                    $EndValue = $ClientApp.Length - $startValue
                    $MACAddress = $ClientApp.Substring($startValue,$EndValue)
                    #Test that it's a polycom MAC address
                    if($MACAddress -imatch "0004f2" -or $MACAddress -imatch "64167F")
                    {
                        $fileName = "${MACAddress}.cfg"
                        if($outputBuffer -imatch $fileName)
                        {
                            $objInformationTextBox.Text += "Found: ${MACAddress}.cfg file for user $SipUser.`n`n"
                        }
                    }
                }
            }
            #Check Firmware files
            if($outputBuffer -imatch " sip.ld")
            {
                $objInformationTextBox.Text += "Found: sip.ld - Found Combined Firmware file.`n"
            }
            else
            {
                $objInformationTextBox.Text += "Not Found: sip.ld - This file contains firmware for all VVX phones combined into one file. If you are hosting your firmware on the FTP server, you either need this file or the individual firmware files for your devices.`n`n"
            }
            if($outputBuffer.contains("2345-17960-001.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 2345-17960-001.sip.ld - VVX 1500 Firmware`n"
            }
            if($outputBuffer.contains("3111-33215-001.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 3111-33215-001.sip.ld - SoundStructure Firmware`n"
            }
            if($outputBuffer.contains("3111-44500-001.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 3111-44500-001.sip.ld - VVX 500 Firmware`n"
            }
            if($outputBuffer.contains("3111-44600-001.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 3111-44600-001.sip.ld - VVX 600 Firmware`n"
            }
            if($outputBuffer.contains("3111-46135-002.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 3111-46135-002.sip.ld - VVX 300 Firmware`n"
            }
            if($outputBuffer.contains("3111-46157-002.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 3111-46157-002.sip.ld - VVX 400 Firmware`n"
            }
            if($outputBuffer.contains("3111-46161-001.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 3111-46161-001.sip.ld - VVX 310 Firmware`n"
            }
            if($outputBuffer.contains("3111-46162-001.sip.ld"))
            {
                $objInformationTextBox.Text += "Found: 3111-46162-001.sip.ld - VVX 410 Firmware`n"
            }
        }
    }
    else
    {
        $objInformationTextBox.Text = "Please enter correct format for FTP server address: ftp://<FQND/IPaddress>"
        Write-host "Please enter correct format for FTP server address: ftp://<FQND/IPaddress>" -foreground red
    }

}


function SendTextMessage
{
    [string]$Message = $MessageTextbox.Text
    [string]$Priority = $MessagePriority
    [string]$Title = $MessageTitleTextBox.text

    $objInformationTextBox.Text = ""

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

function SendMessageToAll
{
    [string]$Message = $MessageTextbox.Text
    [string]$Priority = $MessagePriority
    [string]$Title = $MessageTitleTextBox.text

    $objInformationTextBox.Text = "Sending Message to all phones:`n`n"
    if($DiscoverSyncHash.VVXphones.length -eq 0)
    {
            $objInformationTextBox.Text += "There are no phones to message.`n"
    }

    foreach($vvxphone in $DiscoverSyncHash.VVXphones)
    {
        $SipUser = $vvxphone.SipUser
        $userArray = $SipUser.Split(" ")
        $SipUser = $userArray[0]

        $ClientIP = $vvxphone.ClientIP
        $ClientApp = $vvxphone.ClientApp
        $Port = "51234"

        if($ClientIP -ne "IP NOT IN LYNC DATABASE")
        {
            #VVX Display Resolutions - Use the same for 400/500/600, and special formatting for 300.
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
                            $uri = New-Object System.Uri ("$(Script:Proto)://${ClientIP}:${WebServicePort}/push")
                        }
                        else
                        {
                            $uri = New-Object System.Uri ("http://${ClientIP}:${WebServicePort}/push")
                        }

                        $secpasswd = ConvertTo-SecureString $PushPassword -AsPlainText -Force
                        $mycreds = New-Object System.Management.Automation.PSCredential ($PushUsername, $secpasswd)

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
                        if($r -imatch "Push Message will be displayed successfully")
                        {
                            $objInformationTextBox.Text += "${SipUser}: Send SUCCESS!`n"
                            Write-Host "${SipUser}: Send SUCCESS!" -foreground "green"
                            Write-Host "RESPONSE: $r"
                        }
                        else
                        {
                            $objInformationTextBox.Text += "${SipUser}: Send FAILURE.`n"
                            Write-Host "${SipUser}: Send FAILURE." -foreground "red"
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
        else
        {
            Write-Host "No IP for ${SipUser}"
            $objInformationTextBox.Text += "No IP for ${SipUser}."
        }
    }
}


#Test that the phone PIN works  ============================================================
function TestBootstrap
{
    $objInformationTextBox.Text = ""

    foreach ($item in $lv.SelectedItems)
    {
        $user = $item.Text
        $userArray = $user.Split(" ")
        $user = $userArray[0]

        if(!($user -match "VVXNot@LoggedIn"))
        {
            $UserSettings = Invoke-Expression "Get-CsUser -Identity sip:${user} -ErrorAction SilentlyContinue"
            if($UserSettings -eq $null)
            {
                $UserSettings = Invoke-Expression "Get-CsCommonAreaPhone -Identity sip:${user} -ErrorAction SilentlyContinue"
            }
            $LineURI = $UserSettings.LineURI

            if($LineURI -ne "" -and $LineURI -ne $null)
            {

                $SplitNumber = $LineURI.Split(";")
                $PhoneNumber = $SplitNumber[0] -ireplace "tel:"
                $PINNumber = $PinTextBox.Text

                $objInformationTextBox.Text += "User: sip:${user}`nPhone Number: $PhoneNumber`nPIN: $PINNumber`n"

                write-host "------------------------------------------------------"
                write-host "RUNNING COMMAND: Test-CsPhoneBootstrap -PhoneOrExt `"$PhoneNumber`" -Pin `"$PINNumber`" -UserSipAddress `"sip:${user}`""

                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "powershell.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "`"Import-Module Lync`nTest-CsPhoneBootstrap -PhoneOrExt `"$PhoneNumber`" -Pin `"$PINNumber`" -UserSipAddress `"sip:${user}`"`""
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $p.WaitForExit()
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()

                Write-Host $stderr.Trim()
                Write-Host $stdout.Trim()

                if($stdout.Contains(" : Success"))
                {
                    $objInformationTextBox.Text += "Result: PIN Test SUCCESS. (See powershell window for more details)`n`n"
                }
                elseif($stdout.Contains(" : Failure"))
                {
                    $objInformationTextBox.Text += "Result: PIN Test FAILED. (See powershell window for more details)`n`n"
                }
                else
                {
                    $objInformationTextBox.Text += $stdout.Trim()
                }

                write-host "------------------------------------------------------"

            }
            else
            {
                $objInformationTextBox.Text += "sip:${user}: Missing PIN or Phone Number. You must test a PIN number against a users with a LineURI assigned.`n`n"
            }
        }
        else
        {
            Write-Host "Error: This is a VVX device, not a logged in user." -foreground "red"
        }

    }

}

function Check-UsedPortsUDP([string]$RequestedIP, [string]$RequestedPort)
{
    $ListingConnections = [net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveUdpListeners()
    #$ListingConnections += [net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpConnections().LocalEndpoint

    foreach($ListingConnection in $ListingConnections)
    {
        [string]$UsedLocalIP = $ListingConnection.Address
        [string]$UsedLocalPort = $ListingConnection.Port

        if($UsedLocalIP -eq $RequestedIP -and $UsedLocalPort -eq $RequestedPort)
        {
            #Don't try and Listen on this port because it's used.
            return $false
        }
        elseif($UsedLocalIP -eq "0.0.0.0" -and $UsedLocalPort -eq $RequestedPort)
        {
            #Don't try and Listen on this port because it's used.
            return $false
        }
        elseif($UsedLocalIP -eq "127.0.0.1" -and $UsedLocalPort -eq $RequestedPort)
        {
            #Don't try and Listen on this port because it's used.
            return $false
        }
    }
    #Port is free to use.
    return $true
}

function DiscoverLyncMonitoring
{

    $DiscoverSyncHash.VVXphones = @()
    $DiscoverSyncHash.NumberOfUsersDiscovered = 0

    $DatabaseServers = $Null
    $DatabaseServers = Get-CSService -MonitoringDatabase | Select-Object Identity,SqlInstanceName

    if($DatabaseServers -eq $null)
    {
        Write-Host "No Monitoring Database found in this Lync environment..." -foreground "red"
    }
    else
    {
        $UserIPAddressArray = @()
        foreach($DatabaseServer in $DatabaseServers)  #CHECK ALL MONITORING DATABASES
        {
            $sqlconnecterror = $false
            [string]$Server = $DatabaseServer.Identity
            [string]$SQLInstance = $DatabaseServer.SqlInstanceName
            $Server = $Server.Replace("MonitoringDatabase:","")
            Write-Host "Connecting to Monitoring server: $Server Instance: $SQLInstance" -foreground "Yellow"

            #Define SQL Connection String
            [string]$connstring = "server=$Server\$SQLInstance;database=LcsCDR;trusted_connection=true;"

            #Define SQL Command
            [object]$command = New-Object System.Data.SqlClient.SqlCommand

            #SELECT Registration.ClientVersionId,Registration.IpAddress,ClientVersions.Version,ClientVersions.VersionId
            #FROM Registration
            #INNER JOIN ClientVersions
            #ON Registration.ClientVersionId=ClientVersions.VersionId
            #WHERE ClientVersions.Version LIKE '%VVX%'
            ######################## AND Registration.DeRegisterTime is NULL;  ###REMOVED THIS LINE

            [string] $QueryMonths = $Script:MonitoringDatabaseQueryMonths

            #NEW WAY - This method checks if the registration was made in the last 6 months... This saves having to scan very old registration IPs.
            $command.CommandText = "DECLARE @startOfCurrentMonth DATETIME
            SET @startOfCurrentMonth = DATEADD(month, DATEDIFF(month, 0, CURRENT_TIMESTAMP), 0)
            SELECT Registration.ClientVersionId,Registration.IpAddress,Registration.RegisterTime,ClientVersions.Version,ClientVersions.VersionId
            FROM Registration
            INNER JOIN ClientVersions
            ON Registration.ClientVersionId=ClientVersions.VersionId
            WHERE ClientVersions.Version LIKE `'%vvx%`'
            AND Registration.RegisterTime >= DATEADD(month, -${QueryMonths}, @startOfCurrentMonth);"

            #Note: Using the de-register time check to only look at currently registered clients was causing some phones to be missed in discovery. So I had no choice but to remove it... doh!

            [object]$connection = New-Object System.Data.SqlClient.SqlConnection
            $connection.ConnectionString = $connstring
            try {
            $connection.Open()
            } catch [Exception] {
                write-host ""
                write-host "WARNING: Skype4B/Lync VVX Manager was unable to connect to database $server\$SQLInstance. Note: This error is expected if this is a secondary SQL mirrored database. If this is a primary database, please check that the server is online. Also check that UDP 1434 and the Dynamic SQL TCP Port for the Lync/Skype4B Named Instance are open in the Windows Firewall on $server." -foreground "red"
                write-host ""
                #$StatusLabel.Text = "Error connecting to $server. Refer to Powershell window."
                $sqlconnecterror = $true
            }

            $tempstore = @()
            if(!$sqlconnecterror)
            {
                $command.Connection = $connection


                [object]$sqladapter = New-Object System.Data.SqlClient.SqlDataAdapter
                $sqladapter.SelectCommand = $command

                [object]$results = New-Object System.Data.Dataset
                try {
                $recordcount = $sqladapter.Fill($results)
                } catch [Exception] {
                    write-host ""
                    write-host "Error running SQL on $server : $_" -foreground "red"
                    write-host ""
                }

                $tempstore = $results.Tables[0].rows
            }
            $connection.Close()


            foreach ($t in $tempstore)
            {
                if ($t.isserversource -ne "False")
                {
                    [string]$UserIPAddress = $t.IpAddress
                    if($UserIPAddress -ne "")
                    {
                        [String[]]$UserIPAddressArray += $UserIPAddress
                    }
                }
            }

        }

        $UserIPAddressArray = $UserIPAddressArray | sort -unique

        Write-Host "INFO: No of IP Addresses found in Monitoring DB:" $UserIPAddressArray.length -foreground "Yellow"

        #SCAN IP ADDRESSES
        if($UserIPAddressArray.length -ne 0)
        {
            Write-Host ""
            Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"
            Write-Host "Obtained list of VVX phone IP Addresses from $Server. Starting Scan!" -foreground "Green"
            Write-Host "-----------------------------------------------------------------------------------------" -foreground "Green"

            $CurrentNumberOfConnections = 0
            $AllowedConnections = 10
            $NumberOfLoops = 0
            # Get Start Time
            $startDTM = (Get-Date)

            Write-Host "Starting Discovery..." -foreground "green"
            $Jobs = @()
            foreach($IPAddress in $UserIPAddressArray)
            {
                if($IPAddress -ne $null -and $IPAddress -ne "")
                {
                    Write-Host "Attempting to discover: $IPAddress" -foreground "yellow"

                    #This is to ensure randomness of Get-Random command for port selection...
                    Start-Sleep -Milliseconds 1

                    [string]$LocalIP = GetLocalIP

                    ##MOVED FROM THREADED SECTION
                    DO
                    {
                        [string]$ticks = (get-date).ticks
                        [int]$tick32 = $ticks.substring($ticks.length - 8, 8)
                        #Write-Host "TICKS: LONG: $ticks INT: $tick32"
                        $LocalPort = Get-Random -min 10000 -max 65535 -SetSeed $tick32  #"51234"
                        #Write-Host "Checking if local ${LocalIP}:${LocalPort} is in use for $IPAddress" -foreground "blue"
                    }while(!(Check-UsedPortsUDP $LocalIP $LocalPort))
                    #####MOVED FROM OTHER SECTION

                    Write-Host "Checking local ${LocalIP}:${LocalPort}" -foreground "green"

                    $objConnectionData = New-Object -Type PSCustomObject -Property @{
                    strIPAddress = $IPAddress
                    strUsername = $VVXHTTPUsername
                    strPassword = $VVXHTTPPassword
                    strLocalIP = $LocalIP
                    strLocalPort = $LocalPort
                    strAdminModePassword = $VVXAdminModePassword
                    strDiscoveryWaitTime = $DiscoveryWaitTime
                    objRunspacePool = $objRunspacePool
                    objPowerShellPipeline = $Null
                    objIAsyncResult = $Null
                    }

                    $objConnectionData.objPowerShellPipeline = [System.Management.Automation.PowerShell]::Create()
                    $objConnectionData.objPowerShellPipeline.AddScript($sbDiscoverVVXIPScript) | Out-Null
                    $objConnectionData.objPowerShellPipeline.AddArgument($objConnectionData) | Out-Null
                    $objConnectionData.objPowerShellPipeline.AddArgument($DiscoverSyncHash) | Out-Null
                    $objConnectionData.objPowerShellPipeline.RunspacePool = $objConnectionData.objRunspacePool

                    $Jobs += New-Object PSObject -Property @{
                       Pipe = $objConnectionData.objPowerShellPipeline
                       Result = $objConnectionData.objPowerShellPipeline.BeginInvoke()
                    }

                    $CurrentNumberOfConnections++
                    #Only run AllowedConnections number of threads then wait...
                    #Check the number of concurrent connections is more than the number of allow connections
                    $ArrayLength = $UserIPAddressArray.length
                    if($AllowedConnections -gt $ArrayLength -and $CurrentNumberOfConnections -eq $ArrayLength)
                    {
                            While ( $Jobs.Result.IsCompleted -contains $false )
                            {
                                Start-Sleep -Milliseconds 50
                                #Write-Host "Checking Jobs... " $Jobs.Result.IsCompleted
                               #foreach($JobID in $Jobs)
                               #{
                               #         Write-Host "Job is complete? " $JobID.Result.IsCompleted
                               #}
                            }
                            Write-Host ""
                            Write-Host "Batch completed!" -foreground "blue"
                            $CurrentNumberOfConnections = 0
                            $NumberOfLoops++
                            $Jobs = @()

                    }
                    elseif((([Math]::Floor([decimal]($ArrayLength / $AllowedConnections))) -eq $NumberOfLoops) -and $CurrentNumberOfConnections -eq ($ArrayLength % $AllowedConnections))
                    {
                        Do {
                               Start-Sleep -Milliseconds 50
                               #Write-Host "Checking Jobs... " $Jobs.Result.IsCompleted

                            } While ( $Jobs.Result.IsCompleted -contains $false )
                            Write-Host ""
                            Write-Host "Batch completed! Starting new batch..." -foreground "blue"
                            $CurrentNumberOfConnections = 0
                            $NumberOfLoops++
                            $Jobs = @()

                    }
                    else
                    {
                        $Remainder = $CurrentNumberOfConnections % $AllowedConnections
                        if($Remainder -eq 0)
                        {
                            Do {
                               Start-Sleep -Milliseconds 50
                               #Write-Host "Checking Jobs... " $Jobs.Result.IsCompleted

                            } While ( $Jobs.Result.IsCompleted -contains $false )
                            Write-Host "Batch completed!" -foreground "blue"
                            $CurrentNumberOfConnections = 0
                            $NumberOfLoops++
                            $Jobs = @()

                        }
                    }
                }

            }

            # Get End Time
            $endDTM = (Get-Date)
            # Echo Time elapsed
            Write-Host "Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds"
            Write-Host "-----------------------------------------------------------------------------------------"
            $NumberDiscovered = $DiscoverSyncHash.NumberOfUsersDiscovered
            Write-Host "Discovered $NumberDiscovered VVX phone(s)!" -foreground "green"


        }
        else
        {
            Write-Host "INFO: No VVX Phones found in monitoring database." -foreground "Yellow"
        }


    }
}


# The return from this is $true if Auth passed, and $false if Auth failed.
#Script Block...

$sbDiscoverVVXIP = {
    param($objConnectionData, $DiscoverSyncHash)

    [string]$username = $objConnectionData.strUsername
    [string]$password = $objConnectionData.strPassword
    [string]$adminModePassword = $objConnectionData.strAdminModePassword
    [string]$IPAddress = $objConnectionData.strIPAddress
    #ADDED
    [string]$LocalIP = $objConnectionData.strLocalIP
    [string]$LocalPort = $objConnectionData.strLocalPort
    [int]$DiscoveryWaitTime = $objConnectionData.strDiscoveryWaitTime

    $PreauthAttempt = 0
    $AdminModeCheckLoop = 0
    $WebPageReturnedCheckLoop = 0


    # The return from this is $true if Auth passed, and $false if Auth failed.
    function DiscoverVVXIP([string]$strIPAddress, [string]$strUsername, [string]$strPassword, [string]$strLocalIP, [string]$strLocalPort, [int]$strDiscoveryWaitTime)
    {

        [string]$username = $strUsername
        [string]$password = $strPassword
        [string]$IPAddress = $strIPAddress

        ##ADDED
        [string]$LocalIP = $strLocalIP
        [string]$LocalPort = $strLocalPort
        [int]$DiscoveryWaitTime = $strDiscoveryWaitTime

        #######################################
    [string]$returndata = ""
    $receivebytes = $null
    #[string]$LocalIP = GetLocalIP


    #Write-Host "Checking if local ${LocalIP}:${LocalPort} is in use for $IPAddress" -foreground "blue"

    #Write-Host "Using Local Port $LocalPort for $IPAddress"
    $ClientIP = $IPAddress

    $serverip = "${LocalIP}:${LocalPort}"
    $phoneid = "discover"
    [string]$time = [DateTime]::Now
    $time = $time.Replace(" ","").Replace("/","").Replace(":","")
    $call_id = "${time}msgto${phoneid}"



        $message = @"
NOTIFY sip:${phoneid}:5060 SIP/2.0
Via: SIP/2.0/UDP ${serverip}
From: <sip:discover>;tag=1530231855-106746376154
To: <sip:${ClientIP}:5060>
Call-ID: ${call_id}
CSeq: 1500 NOTIFY
Contact: <sip:${phoneid}>
Content-Length: 0


"@

        $Port = 5060

        ###Can only achieve 600ms per device with this method! Due to 500ms UDP receive delay  http://msdn.microsoft.com/en-us/library/system.net.sockets.socket.sendtimeout
        #$udpobject = new-Object system.Net.Sockets.Udpclient($LocalPort)
        #$udpobject.Client.ReceiveTimeout = 500   ###Minimum setting is 500ms

        $a = new-object system.text.asciiencoding
        $byte = $a.GetBytes($message)

        #Use base level UDP socket implementation for faster for discovery!
        $Socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,
                        [Net.Sockets.SocketType]::Dgram,
                        [Net.Sockets.ProtocolType]::Udp)

        $LocalEndpoint = New-Object system.net.ipendpoint([System.Net.IPAddress]::Parse($LocalIP),$LocalPort)
        $Socket.Bind($LocalEndpoint)
        $Socket.Connect($ClientIP,$Port)
        try
        {
            [Void]$Socket.Send($byte)
        }
        catch
        {
            Write-Host "Unable to connect to host ${ClientIP}:${Port}" -foreground "red"
        }

        # Buffer to hold the returned Bytes.
        [Byte[]]$buffer = New-Object -TypeName Byte[]($Socket.ReceiveBufferSize)
        $BytesReceivedError = $false

        Try {
                #Note: This socket timeout has been tuned to allow phones to respond within 350ms. This timer should work well in most cases, however, if you have a device that is on a slow link you may need to make this value higher.
                $theDiscoveryWaitTime = $DiscoveryWaitTime * 1000
                #Write-Host "DISCOVERY WAIT TIME: $discoveryWaitTime" #DEBUGGING
                if($Socket.Poll($theDiscoveryWaitTime,[System.Net.Sockets.SelectMode]::SelectRead))
                {
                    $receivebytes = $Socket.Receive($buffer)
                }
                else
                {
                    #Timed out
                    Write-Host "INFO: No response from $ClientIP." -Foreground "yellow"
                    $objInformationTextBox.Text += "No Response from $ClientIP.`n"
                    $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                    $objInformationTextBox.ScrollToCaret()
                    $BytesReceivedError = $true
                }
        } Catch {

            #Write-Warning "$($Error[0])"
            Write-Host "INFO: No response from $ClientIP." -Foreground "yellow"
            $objInformationTextBox.Text += "No Response from $ClientIP.`n"
            $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
            $objInformationTextBox.ScrollToCaret()
            $BytesReceivedError = $true
        }
        if(!$BytesReceivedError)
        {
            if ($receivebytes) {
                [string]$returndata = $a.GetString($buffer, 0, $receivebytes)
                Write-Host $returndata
                [string]$SIPUserName = ""
                [string]$LyncServer = ""
                [string]$ClientApp = ""
                if($returndata -imatch "SIP/2.0 200 OK")
                {
                    if($returndata -imatch "Contact: <sip:" -and $returndata -imatch "PolycomVVX")
                    {
                        [string]$returndataSplit = ($returndata -split 'Contact: <sip:')[1]
                        [string]$returndataSplit = ($returndataSplit -split "`r`n")[0]
                        #Write-Host "Returned Data Split: $returndataSplit"

                        if($returndataSplit -imatch "VVX500@" -or $returndataSplit -imatch "VVX501@" -or $returndataSplit -imatch "VVX600@" -or $returndataSplit -imatch "VVX601@" -or $returndataSplit -imatch "VVX300@" -or $returndataSplit -imatch "VVX301@" -or $returndataSplit -imatch "VVX310@" -or $returndataSplit -imatch "VVX311@" -or $returndataSplit -imatch "VVX400@" -or $returndataSplit -imatch "VVX401@" -or $returndataSplit -imatch "VVX410@" -or $returndataSplit -imatch "VVX411@" -or $returndataSplit -imatch "VVX200@" -or $returndataSplit -imatch "VVX201@")
                        {

                            $DiscoverSyncHash.NumberOfUsersDiscovered++
                            $objInformationTextBox.Text += "Discovered device with no user logged in.`n"
                            $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                            $objInformationTextBox.ScrollToCaret()

                            if($returndata -imatch "User-Agent: ")
                            {
                                [string]$ClientAppTemp = ($returndata -split 'User-Agent: ')[1]
                                [string]$ClientApp = ($ClientAppTemp -split "`r`n")[0]
                            }

                            $numberOfNotLoggedInPhones = 0
                            foreach($vvxphone in $DiscoverSyncHash.VVXphones)
                            {
                                [string]$PhoneSipUser = $vvxphone.SipUser
                                if($PhoneSipUser -match "VVXNot@LoggedIn")
                                {
                                    $numberOfNotLoggedInPhones++
                                }
                            }

                            $theSipUser = "VVXNot@LoggedIn_$numberOfNotLoggedInPhones"
                            Write-Host "Discovered Device with no user logged in at $ClientIP. Naming phone $theSipUser." -Foreground "green"
                            $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$theSipUser";"ClientIP" = "$ClientIP";"ClientApp" = "$ClientApp";"LyncServer"="NOT AVAILABLE"})

                        }
                        elseif($returndataSplit.Contains(";opaque"))  #;opaque
                        {
                            [string]$SIPUserName = ($returndataSplit -split ';')[0]

                            if($returndata -imatch "targetname=")
                            {
                                [string]$LyncServerStringTemp = ($returndata -split "targetname=`"")[1]
                                [string]$LyncServer = ($LyncServerStringTemp -split "`",")[0]
                            }
                            if($returndata -imatch "User-Agent: ")
                            {
                                [string]$ClientAppTemp = ($returndata -split 'User-Agent: ')[1]
                                [string]$ClientApp = ($ClientAppTemp -split "`r`n")[0]
                            }
                            Write-Host "Discovered User: $SIPUserName on $LyncServer running app $ClientApp" -Foreground "green"

                            if($SIPUserName -ne "" -and $LyncServer -ne "" -and $ClientApp -ne "")
                            {
                                $DiscoverSyncHash.NumberOfUsersDiscovered++

                                #Confirm how many phones this user is logged into Lync
                                $numberofphones = 1
                                foreach($vvxphone2 in $DiscoverSyncHash.VVXphones)
                                {
                                    $SipUser2 = $vvxphone2.SipUser
                                    if($SipUser2 -imatch $SIPUserName)
                                    {
                                        if($numberofphones -gt 1)
                                        {
                                            $SipUser = "$SIPUserName $loop"
                                        }
                                        $numberofphones++
                                    }
                                }
                                #Check if the user has multiple phones
                                if($numberofphones -gt 1)
                                {
                                    $SIPUserName = "$SIPUserName $numberofphones"
                                }


                                $objInformationTextBox.Text += "Discovered Device $SIPUserName.`n"
                                $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                                $objInformationTextBox.ScrollToCaret()
                                Write-Host "Discovered Device for $SIPUserName at $ClientIP." -Foreground "green"

                                $DiscoverSyncHash.NumberOfUsersImported++
                                $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$SIPUserName";"ClientIP" = "$ClientIP";"ClientApp" = "$ClientApp";"LyncServer"="$LyncServer"})
                            }

                        }
                        else
                        {
                            #[string]$SIPUserName = ($returndataSplit -split '@')[0]   - If you needed to get the actual username

                            $DiscoverSyncHash.NumberOfUsersDiscovered++
                            $objInformationTextBox.Text += "Discovered device with no user logged in.`n"
                            $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                            $objInformationTextBox.ScrollToCaret()

                            if($returndata -imatch "User-Agent: ")
                            {
                                [string]$ClientAppTemp = ($returndata -split 'User-Agent: ')[1]
                                [string]$ClientApp = ($ClientAppTemp -split "`r`n")[0]
                            }

                            $numberOfNotLoggedInPhones = 0
                            foreach($vvxphone in $DiscoverSyncHash.VVXphones)
                            {
                                [string]$PhoneSipUser = $vvxphone.SipUser
                                if($PhoneSipUser -match "VVXNot@LoggedIn")
                                {
                                    $numberOfNotLoggedInPhones++
                                }
                            }

                            $theSipUser = "VVXNot@LoggedIn_$numberOfNotLoggedInPhones"
                            Write-Host "Discovered Device with no user logged in at $ClientIP. Naming phone $theSipUser." -Foreground "green"
                            $DiscoverSyncHash.VVXphones += @(@{"SipUser" = "$theSipUser";"ClientIP" = "$ClientIP";"ClientApp" = "$ClientApp";"LyncServer"="NOT AVAILABLE"})

                        }
                    }
                    else
                    {
                        Write-Host "INFO: Ignoring SIP response. Non VVX response."
                    }
                }
                else
                {
                    Write-Host "ERROR RESPONSE:" -Foreground "red"
                    Write-Host "$returndata" -Foreground "red"
                    $objInformationTextBox.Text += "Error in response from endpoint. Ignoring device.`n"
                    $objInformationTextBox.Select($objInformationTextBox.Text.Length - 1, 0)
                    $objInformationTextBox.ScrollToCaret()
                }


            } else {
                Write-Host "INFO: No data received from $ClientIP on port $Port" -foreground "yellow"
            }
        }
        $Socket.Close()
        $Socket.Dispose()
        $Socket = $null

    }

    #Write-Host "CALLING: DiscoverVVXIP -strIPAddress $IPAddress -strUsername $username -strPassword $password"
    DiscoverVVXIP -strIPAddress $IPAddress -strUsername $username -strPassword $password -strLocalIP $LocalIP -strLocalPort $LocalPort -strDiscoveryWaitTime $DiscoveryWaitTime
}
$sbDiscoverVVXIPScript = [System.Management.Automation.ScriptBlock]::Create($sbDiscoverVVXIP)



# Uncomment the following items if you want the Tool to automatically check the Lync database at load time.
#GetUsersFromDatabase
#UpdateUsersList
#$lv.Items[0].Selected = $true

$ConnectButton.enabled = $false
$MessageButton.Enabled = $false
$GetInfoButton.Enabled = $false
$SendButton.Enabled = $false
$GetConfigButton.Enabled = $false
$SetConfigButton.Enabled = $false
$DialButton.Enabled = $false
$EndCallButton.Enabled = $false
$ScreenButton.Enabled = $false


UpdatePhoneInfoText



# Activate the form ============================================================
$objForm.Add_Shown({$objForm.Activate()})
[void] $objForm.ShowDialog()


# SIG # Begin signature block
# MIIcZgYJKoZIhvcNAQcCoIIcVzCCHFMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOZag814qvxE1X5WU7J5R1AIk
# JxWggheVMIIFHjCCBAagAwIBAgIQBqM5iX2/nFGN8MjuodKqbDANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMB4XDTE3MDMwNjAwMDAwMFoXDTE4MDMx
# NDEyMDAwMFowWzELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1ZJQzEQMA4GA1UEBxMH
# TWl0Y2hhbTEVMBMGA1UEChMMSmFtZXMgQ3Vzc2VuMRUwEwYDVQQDEwxKYW1lcyBD
# dXNzZW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCg8fMN/8rshNlQ
# 8Potedk7oUmxaYvNpCh0o+ikv1QgPaB8KaL2bUahLL8/uZmqK7pO3ANjQhh3SM/Q
# aURzhwk9cI096G3Hc9wIPf7qJPQk63cmErSsV1cHATPib34bEi4RjJPtesdUqFS0
# PzgR1x/fzZy8P5AgRJF/BzPXZK5L3UVHv4JYWbXcvPMtQ3wNNlFheZMRXMAbAJFr
# o7bHvpZdQVOIgFOPUtHgIkkun87HAuzr8RxKcir2rWPwz0E3Gv9iWVA/UVx6mScr
# JomojtkU8f5UqE2vrmHeiw4n+lgAOD8jDD7GFYMwucOStXqBkMOvYYdWVK+TO4vo
# Bl58b4/1AgMBAAGjggHFMIIBwTAfBgNVHSMEGDAWgBRaxLl7KgqjpepxA8Bg+S32
# ZXUOWDAdBgNVHQ4EFgQUA7w5BxjbNMvUcqd4V+o9YGLoXZowDgYDVR0PAQH/BAQD
# AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGA1UdHwRwMG4wNaAzoDGGL2h0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMDWgM6Ax
# hi9odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNy
# bDBMBgNVHSAERTBDMDcGCWCGSAGG/WwDATAqMCgGCCsGAQUFBwIBFhxodHRwczov
# L3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEEATCBhAYIKwYBBQUHAQEEeDB2
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTgYIKwYBBQUH
# MAKGQmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1
# cmVkSURDb2RlU2lnbmluZ0NBLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEB
# CwUAA4IBAQBGvQDleLco72A/aFvQWtH7VwxaTCVK2SP0OQFi9mD/VdflJwKMOg1k
# ZpidEd9FlB1Dm/HfntfVTQGSSKbwOWmjX/gd0rfj1hYi/KgNWsoPZIGJHWa5KitU
# 92qYHhbOuLety4xqK4/94IjwhinavMsOqEqplAxzglCLAWI7Xhj4KR9J8cLbi/MR
# lAUsV96QHOiO6+JnLPyMaPGRH1PWNuXzp/1dum3enR77HjcEpPPjBO5CrCI2UFLJ
# ByhZRkQ7L1i6ZcHJNLA7X+OEnDhVir6gJnMxx0OORz1M3UxPALifVhZdKuAYmy4w
# JHzuO/vEu/C2kwA/BvYVL4ASMEh81sQlMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1
# U0O1b5VQCDANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcN
# MjgxMDIyMTIwMDAwWjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2Vy
# dCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEA+NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid
# 2zLXcep2nQUut4/6kkPApfmJ1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sj
# lOSRI5aQd4L5oYQjZhJUM1B0sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjf
# DPXiTWAYvqrEsq5wMWYzcT6scKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzL
# fnQ5Ng2Q7+S1TqSp6moKq4TzrGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR
# 93O8vYWxYoNzQYIH5DiLanMg0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckw
# EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYI
# KwYBBQUHAwMweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgw
# OqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIE
# MCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYI
# YIZIAYb9bAMwHQYDVR0OBBYEFFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1a
# JLPzItEVyCx8JSl2qB1dHC06GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUP
# UbRupY5a4l4kgU4QpO4/cY5jDhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1
# UcKNJK4kxscnKqEpKBo6cSgCPC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjF
# Emifz0DLQESlE/DmZAwlCEIysjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM
# 1ekN3fYBIM6ZMWM9CBoYs4GbT8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhs
# RDKyZqHnGKSaZFHvMIIGajCCBVKgAwIBAgIQAwGaAjr/WLFr1tXq5hfwZjANBgkq
# hkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBB
# c3N1cmVkIElEIENBLTEwHhcNMTQxMDIyMDAwMDAwWhcNMjQxMDIyMDAwMDAwWjBH
# MQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJTAjBgNVBAMTHERpZ2lD
# ZXJ0IFRpbWVzdGFtcCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQCjZF38fLPggjXg4PbGKuZJdTvMbuBTqZ8fZFnmfGt/a4ydVfiS457V
# WmNbAklQ2YPOb2bu3cuF6V+l+dSHdIhEOxnJ5fWRn8YUOawk6qhLLJGJzF4o9GS2
# ULf1ErNzlgpno75hn67z/RJ4dQ6mWxT9RSOOhkRVfRiGBYxVh3lIRvfKDo2n3k5f
# 4qi2LVkCYYhhchhoubh87ubnNC8xd4EwH7s2AY3vJ+P3mvBMMWSN4+v6GYeofs/s
# jAw2W3rBerh4x8kGLkYQyI3oBGDbvHN0+k7Y/qpA8bLOcEaD6dpAoVk62RUJV5lW
# MJPzyWHM0AjMa+xiQpGsAsDvpPCJEY93AgMBAAGjggM1MIIDMTAOBgNVHQ8BAf8E
# BAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCCAb8G
# A1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcBMIIBkjAoBggrBgEFBQcCARYcaHR0
# cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCCAWQGCCsGAQUFBwICMIIBVh6CAVIA
# QQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMA
# YQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4A
# YwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAA
# UwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAA
# QQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkA
# YQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIA
# YQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUA
# LjALBglghkgBhv1sAxUwHwYDVR0jBBgwFoAUFQASKxOYspkH7R7for5XDStnAs0w
# HQYDVR0OBBYEFGFaTSS2STKdSip5GoNL9B6Jwcp9MH0GA1UdHwR2MHQwOKA2oDSG
# Mmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEu
# Y3JsMDigNqA0hjJodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURDQS0xLmNybDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcnQwDQYJKoZIhvcN
# AQEFBQADggEBAJ0lfhszTbImgVybhs4jIA+Ah+WI//+x1GosMe06FxlxF82pG7xa
# FjkAneNshORaQPveBgGMN/qbsZ0kfv4gpFetW7easGAm6mlXIV00Lx9xsIOUGQVr
# NZAQoHuXx/Y/5+IRQaa9YtnwJz04HShvOlIJ8OxwYtNiS7Dgc6aSwNOOMdgv420X
# Ewbu5AO2FKvzj0OncZ0h3RTKFV2SQdr5D4HRmXQNJsQOfxu19aDxxncGKBXp2JPl
# VRbwuwqrHNtcSCdmyKOLChzlldquxC5ZoGHd2vNtomHpigtt7BIYvfdVVEADkitr
# wlHCCkivsNRu4PQUCjob4489yq9qjXvc2EQwggbNMIIFtaADAgECAhAG/fkDlgOt
# 6gAK6z8nu7obMA0GCSqGSIb3DQEBBQUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0wNjExMTAwMDAwMDBa
# Fw0yMTExMTAwMDAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IEFzc3VyZWQgSUQgQ0EtMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAOiCLZn5ysJClaWAc0Bw0p5WVFypxNJBBo/JM/xNRZFcgZ/tLJz4FlnfnrUk
# FcKYubR3SdyJxArar8tea+2tsHEx6886QAxGTZPsi3o2CAOrDDT+GEmC/sfHMUiA
# fB6iD5IOUMnGh+s2P9gww/+m9/uizW9zI/6sVgWQ8DIhFonGcIj5BZd9o8dD3QLo
# Oz3tsUGj7T++25VIxO4es/K8DCuZ0MZdEkKB4YNugnM/JksUkK5ZZgrEjb7Szgau
# rYRvSISbT0C58Uzyr5j79s5AXVz2qPEvr+yJIvJrGGWxwXOt1/HYzx4KdFxCuGh+
# t9V3CidWfA9ipD8yFGCV/QcEogkCAwEAAaOCA3owggN2MA4GA1UdDwEB/wQEAwIB
# hjA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEF
# BQcDBAYIKwYBBQUHAwgwggHSBgNVHSAEggHJMIIBxTCCAbQGCmCGSAGG/WwAAQQw
# ggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9zc2wtY3Bz
# LXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUA
# cwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMA
# bwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYA
# IAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQA
# IAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUA
# bQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkA
# dAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAA
# aABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG
# /WwDFTASBgNVHRMBAf8ECDAGAQH/AgEAMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsNC5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMB0GA1UdDgQW
# BBQVABIrE5iymQftHt+ivlcNK2cCzTAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYun
# pyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEARlA+ybcoJKc4HbZbKa9Sz1LpMUer
# Vlx71Q0LQbPv7HUfdDjyslxhopyVw1Dkgrkj0bo6hnKtOHisdV0XFzRyR4WUVtHr
# uzaEd8wkpfMEGVWp5+Pnq2LN+4stkMLA0rWUvV5PsQXSDj0aqRRbpoYxYqioM+Sb
# OafE9c4deHaUJXPkKqvPnHZL7V/CSxbkS3BMAIke/MV5vEwSV/5f4R68Al2o/vsH
# OE8Nxl2RuQ9nRc3Wg+3nkg2NsWmMT/tZ4CMP0qquAHzunEIOz5HXJ7cW7g/DvXwK
# oO4sCFWFIrjrGBpN/CohrUkxg0eVd3HcsRtLSxwQnHcUwZ1PL1qVCCkQJjGCBDsw
# ggQ3AgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNI
# QTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0ECEAajOYl9v5xRjfDI7qHSqmww
# CQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# IwYJKoZIhvcNAQkEMRYEFLlNFhZmlcfKxKwpJWZCuRLDk0WvMA0GCSqGSIb3DQEB
# AQUABIIBAHFCaV3LIhOjgiimi7S59iVxqzt/BUmZwX7SN57LEiaf4MFGe5MWjexB
# WL1OCY+aXkRIS5cdU1pTXpceGBoAhq65EO4eMWwvbcZ9WrWPN8u8c8GgTUePQ1rH
# PDR14SzBZmwuYH8B5dNminkr2bbQ6Gx+EjI1lbNz3twCp2/8G8KsfOUcrpV4dcIL
# rpGyTr9qXf4fqnZlbm7A7CtoBJx+aI3Ows9vjG/wS16ptmGUQWVZKdbdKm9Tocte
# VD5fsvqngyrAs15D89JeW55tVCUblb4vuUcfptXkuDbuxxQ10GhfXBJoarhwwE5Z
# ZwThsgQfEoDby3PeBYv+YdhVMRsprOahggIPMIICCwYJKoZIhvcNAQkGMYIB/DCC
# AfgCAQEwdjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1
# cmVkIElEIENBLTECEAMBmgI6/1ixa9bV6uYX8GYwCQYFKw4DAhoFAKBdMBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MDcyODEzMDAw
# MlowIwYJKoZIhvcNAQkEMRYEFC4ncn62P7aO18sb5+/lWyp9igeZMA0GCSqGSIb3
# DQEBAQUABIIBAIxepmVuWMD4Tt60iVFV5FlyjeLXTtQazIhs3dr6yENc3VKZ+3al
# mSoVwjWVzxbfdIkJqgro1OFIMnfc0as2QzT9F/Omoy6CVe3PpPKdWBZXu1LgjTcN
# h4Oq7jv/zLyZK1WtPVvzUhdzWTDrSXQ3ZfVXScIafrhuv078+aK8CCRG1dmBBjd+
# dzI8p6wv5qYDCK4NkcoX6ryxILlZZZ/Ak71e3LwZPrn7LQ5PGk1X57eQaM4qvqWT
# Mi+RjnPkA+vB0PH8IFyvmXD8g5F9cGn0xcJmEAvgztuwMiMlIu9byGiWzS20Y3G7
# epPS1RO3e9w1OQ2XGReTeGJDb744k0BphFc=
# SIG # End signature block
