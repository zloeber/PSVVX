function Get-LocalIP
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