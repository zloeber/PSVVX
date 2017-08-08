---
external help file: PSVVX-help.xml
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Send-VVXTextMessage

## SYNOPSIS
Set the screen capture setting of a device

## SYNTAX

```
Send-VVXTextMessage [-Device] <String> -Message <String> -Priority <String> [-Theme <String>] -Title <String>
 [-Protocol <String>] [-Port <Int32>] [-Base <String>] [-RetryCount <Int32>] [-IgnoreSSLCertificate]
 [-Credential <PSCredential>]
```

## DESCRIPTION
Set the screen capture setting of a device

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$cred = Get-Credential -UserName 'vvxmanager' -Message 'Please supply the push account password for the device'
```

Send-VVXTextMessage -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -ErrorAction:Ignore -Title 'test' -Message 'Test message' -Priority 1

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

### -Message
Body of the message

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Priority
Message priority

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Theme
Messagebox theme

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: S4B
Accept pipeline input: False
Accept wildcard characters: False
```

### -Title
Message title

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
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

### -Base
Base URL for push messages (defaults to 'push')

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Push
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

## INPUTS

## OUTPUTS

## NOTES
Author: Zachary Loeber

## RELATED LINKS

[https://github.com/zloeber/PSVVX](https://github.com/zloeber/PSVVX)

