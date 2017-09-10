---
external help file: PSVVX-help.xml
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Get-VVXURI

## SYNOPSIS
Attempts to retrieve a VVX URI.

## SYNTAX

### URINotPassed (Default)
```
Get-VVXURI [-Device] <String> [[-Protocol] <String>] [-Port <Int32>] [-Path <String>] [-RetryCount <Int32>]
 [-RequestTimeOut <Int32>] [-IgnoreSSLCertificate] [-Credential <PSCredential>]
```

### URIPassed
```
Get-VVXURI [-FullURI] <String> [-RetryCount <Int32>] [-RequestTimeOut <Int32>] [-IgnoreSSLCertificate]
 [-Credential <PSCredential>]
```

## DESCRIPTION
Attempts to retrieve a VVX URI.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
TBD
```

## PARAMETERS

### -Device
Device to send HTTP get request

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

### -Path
Base REST uri path.

```yaml
Type: String
Parameter Sets: URINotPassed
Aliases: 

Required: False
Position: Named
Default value: None
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
Defaults to 800 ms.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 800
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

