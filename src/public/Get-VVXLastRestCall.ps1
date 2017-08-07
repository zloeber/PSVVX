function Get-VVXLastRESTCall {
    <#
    .SYNOPSIS
    Returns the last REST call information that was used.
    .DESCRIPTION
    Returns the last REST call information that was used.
    .EXAMPLE
    Get-VVXLastRestCall
    .NOTES
    Author: Zachary Loeber
    .LINK
    https://github.com/zloeber/PSVVX
    #>
    [CmdletBinding()]
    param()

    $Script:LastRESTCall
}