---
external help file: PSVVX-help.xml
online version: https://github.com/zloeber/PSVVX
schema: 2.0.0
---

# Send-VVXSIPNotify

## SYNOPSIS
Sends a SIP signal to a device.

## SYNTAX

```
Send-VVXSIPNotify [-Device] <String> [-Port <Int32>] [-WaitTime <Int32>] [-Event <String>] [-LocalIP <String>]
 [-LocalPort <Int32>]
```

## DESCRIPTION
Sends a SIP signal to a device.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-VVXDevice -Device 10.0.29.20 | Where {$_.Status -eq 'online'} | Send-VVXSIPNotify
```

Sends the check-sync sip signal command (event) to 10.0.29.20 if the device is found.

## PARAMETERS

### -Device
Device to send to.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Phone, DeviceName, IP

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Port
Port to use for remote device connection.
Default is 5060.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 5060
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -WaitTime
Time in ms to wait for responses.
Defaults to 350ms

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 350
Accept pipeline input: False
Accept wildcard characters: False
```

### -Event
The SIP notify event to send.
Defaults to 'check-sync'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Check-sync
Accept pipeline input: False
Accept wildcard characters: False
```

### -LocalIP
Local IP address to use for connection to device.
Defaults to an autodiscovered IP of the local system.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: (Get-PIIPAddress | Select -First 1).IP.ToString()
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -LocalPort
Local port to use for connection to device.
Defaults to a random unused high port.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: (Get-UnusedHighPort)
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
Author: Zachary Loeber

## RELATED LINKS

[https://github.com/zloeber/PSVVX](https://github.com/zloeber/PSVVX)

