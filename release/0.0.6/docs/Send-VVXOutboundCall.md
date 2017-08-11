---
external help file: PSVVX-help.xml
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Send-VVXOutboundCall

## SYNOPSIS
Send a call from the specified VVX device.

## SYNTAX

```
Send-VVXOutboundCall [-Device] <String> -Number <String> [-Line <String>] [-Protocol <String>] [-Port <Int32>]
 [-RetryCount <Int32>] [-IgnoreSSLCertificate] [-Credential <PSCredential>]
```

## DESCRIPTION
Send a call from the specified VVX device.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$cred = Get-Credential -UserName 'Polycom' -Message 'Please supply the admin password for the device'
```

Set-VVXScreenCapture -Credential $cred -Protocol 'https' -Port 443 -Device '10.0.29.20' -IgnoreSSLCertificate -ErrorAction:Ignore -Value 1

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

### -Number
Number to dial.

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

### -Line
Line to use.
Defaults to 1.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 1
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

