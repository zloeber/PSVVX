function Get-UnusedHighPort {
    $UsedLocalPorts = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).GetActiveTcpListeners() | Where-Object -FilterScript {$PSitem.AddressFamily -eq 'Internetwork'} | Select-Object -ExpandProperty Port
    do {
        $UnusedLocalPort = $(Get-Random -Minimum 49152 -Maximum 65535 )
    } until ( $UsedLocalPorts -notcontains $UnusedLocalPort )

    $UnusedLocalPort
}