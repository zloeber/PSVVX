---
external help file: PSVVX-help.xml
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Get-VVXScreenShot

## SYNOPSIS
Returns a screenshot of the vvx device screen.

## SYNTAX

### AsStream
```
Get-VVXScreenShot [-Device] <String> [-Screen <String>] [-AsStream] [-Protocol <String>] [-Port <Int32>]
 [-RetryCount <Int32>] [-IgnoreSSLCertificate] [-Credential <PSCredential>]
```

### AsFile
```
Get-VVXScreenShot [-Device] <String> [-Screen <String>] -File <String> [-Protocol <String>] [-Port <Int32>]
 [-RetryCount <Int32>] [-IgnoreSSLCertificate] [-Credential <PSCredential>] [-Silent]
```

## DESCRIPTION
Returns a screenshot of the vvx device screen.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$cred = Get-Credential -UserName 'Polycom' -Message 'Please supply the admin password for the device'
```

Get-VVXScreenShot -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -File c:\temp\vvxscreenshot.bmp

## PARAMETERS

### -Device
Device to send command for processing.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Phone, DeviceName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Screen
Which screen to capture.
Can be 'mainScreen','em/1','em/2', or 'em/3'.
Defaults to mainScreen.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: MainScreen
Accept pipeline input: False
Accept wildcard characters: False
```

### -File
File name to save screenshot to.

```yaml
Type: String
Parameter Sets: AsFile
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsStream
Return results as a stream instead of saving to a file.

```yaml
Type: SwitchParameter
Parameter Sets: AsStream
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Protocol
Protocol to use.
Must be HTTP or HTTPS.
Default is HTTP.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: HTTP
Accept pipeline input: False
Accept wildcard characters: False
```

### -Port
Port to use.
Default is 80.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 80
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
Aliases: Creds

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Silent
Do not display progress indicators

```yaml
Type: SwitchParameter
Parameter Sets: AsFile
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
For this function to work the user must manually configure Settings -\> Basic -\> Preferences -\> Screen Capture -\> Enabled

You can view all screens in your browser by directly going to http\<s\>:\\\\\<device\>:\<port\>\captureScreen as well.

Author: Zachary Loeber

## RELATED LINKS

[https://github.com/zloeber/PSVVX](https://github.com/zloeber/PSVVX)

