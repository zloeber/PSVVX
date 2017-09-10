---
external help file: PSVVX-help.xml
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Send-VVXPushCommand

## SYNOPSIS
Sends a push command to a VVX device.

## SYNTAX

### URINotPassed (Default)
```
Send-VVXPushCommand [-Device] <String> [[-Protocol] <String>] [-Port <Int32>] [-Base <String>] -Body <Object>
 [-RetryCount <Int32>] [-IgnoreSSLCertificate] [-Credential <PSCredential>]
```

### URIPassed
```
Send-VVXPushCommand [-FullURI] <String> -Body <Object> [-RetryCount <Int32>] [-IgnoreSSLCertificate]
 [-Credential <PSCredential>]
```

## DESCRIPTION
Sends a push command to a VVX device.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
TBD
```

## PARAMETERS

### -Device
Device to send push command for processing.

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

### -Base
Base push URI path.
Defaults to push

```yaml
Type: String
Parameter Sets: URINotPassed
Aliases: 

Required: False
Position: Named
Default value: Push
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

### -Body
The body of the push command

```yaml
Type: Object
Parameter Sets: (All)
Aliases: 

Required: True
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

