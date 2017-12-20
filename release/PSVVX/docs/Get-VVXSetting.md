---
external help file: PSVVX-help.xml
Module Name: PSVVX
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Get-VVXSetting

## SYNOPSIS
Retreive a configuration setting from a device.

## SYNTAX

```
Get-VVXSetting [-Device] <String> -Setting <String> [-Protocol <String>] [-Port <Int32>] [-RetryCount <Int32>]
 [-IgnoreSSLCertificate] [-Credential <PSCredential>]
```

## DESCRIPTION
Retreive a configuration setting from a device.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$cred = Get-Credential -UserName 'Polycom' -Message 'Please supply the admin password for the device'
```

Get-VVXSetting -Credential $cred -Device '10.0.29.20' -ErrorAction:Ignore -Setting 'up.screenCapture.enabled'

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

### -Setting
Setting to look up.

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

