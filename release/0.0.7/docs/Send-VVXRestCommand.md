---
external help file: PSVVX-help.xml
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Send-VVXRestCommand

## SYNOPSIS
Sends a REST command to a VVX device.

## SYNTAX

### URINotPassed (Default)
```
Send-VVXRestCommand [-Device] <String> [[-Protocol] <String>] [-Port <Int32>] [-Command] <String>
 [-Base <String>] [-Method <String>] [-Body <Object>] [-RetryCount <Int32>] [-RequestTimeOut <Int32>]
 [-IgnoreSSLCertificate] [-Credential <PSCredential>]
```

### URIPassed
```
Send-VVXRestCommand [-FullURI] <String> [-Method <String>] [-Body <Object>] [-RetryCount <Int32>]
 [-RequestTimeOut <Int32>] [-IgnoreSSLCertificate] [-Credential <PSCredential>]
```

## DESCRIPTION
Sends a REST command to a VVX device.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$cred = Get-Credential -UserName 'Polycom' -Message 'Please supply the admin password for the device'
```

Send-VVXRestCommand -Command 'mgmt/device/info' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
Send-VVXRestCommand -Command 'webCallControl/callStatus' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
Send-VVXRestCommand -Command 'mgmt/network/info' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
Send-VVXRestCommand -Command 'mgmt/lineInfo' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
Send-VVXRestCommand -Command 'webCallControl/sipStatus' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate
Send-VVXRestCommand -Command 'mgmt/network/stats' -Method 'Get' -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate

## PARAMETERS

### -Device
Device to send command for processing.

```yaml
Type: String
Parameter Sets: URINotPassed
Aliases: Phone, DeviceName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Protocol
Protocol to use.
Must be HTTP or HTTPS.
Default is HTTP.

```yaml
Type: String
Parameter Sets: URINotPassed
Aliases: 

Required: False
Position: 2
Default value: HTTP
Accept pipeline input: False
Accept wildcard characters: False
```

### -Port
Port to use.
Default is 80.

```yaml
Type: Int32
Parameter Sets: URINotPassed
Aliases: 

Required: False
Position: Named
Default value: 80
Accept pipeline input: False
Accept wildcard characters: False
```

### -Command
RESTful command to send.

```yaml
Type: String
Parameter Sets: URINotPassed
Aliases: 

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Base
Base REST uri path.
Defaults to api/v1

```yaml
Type: String
Parameter Sets: URINotPassed
Aliases: 

Required: False
Position: Named
Default value: Api/v1
Accept pipeline input: False
Accept wildcard characters: False
```

### -FullURI
A full web url to parse

```yaml
Type: String
Parameter Sets: URIPassed
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Method
REST method to send.
Can be Head, Get, Put, Patch, Post, or Delete.
Default is Get.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Get
Accept pipeline input: False
Accept wildcard characters: False
```

### -Body
The body of the REST request

```yaml
Type: Object
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RetryCount
Number of times to retry if unsuccessful.
Default is 3 times.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 3
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequestTimeOut
Amount of time to allow for the request to process (in ms).
Defaults to 300 ms.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 300
Accept pipeline input: False
Accept wildcard characters: False
```

### -IgnoreSSLCertificate
Ignore any certificate warnings

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
User ID and password for the device

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: Creds, Cred

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
Author: Zachary Loeber

## RELATED LINKS

[https://github.com/zloeber/PSVVX](https://github.com/zloeber/PSVVX)

