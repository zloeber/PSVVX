function SaveImageFile([System.Drawing.Image] $bmp) {

    Write-Host "Saving Image..." -foreground "yellow"
    #File Dialog
    $objFileForm = New-Object System.Windows.Forms.SaveFileDialog
    $objFileForm.FileName = "VVXScreenShot.jpg"
    $objFileForm.Title = "Save Image"
    $objFileForm.CheckFileExists = $false
    $Show = $objFileForm.ShowDialog()
    if ($Show -eq "OK")
    {
        [string]$imageTarget = $objFileForm.FileName

        Write-Host "Output File: $imageTarget" -foreground "green"
        [int]$quality = 95

        #Encoder parameter for image quality
        $myEncoder = [System.Drawing.Imaging.Encoder]::Quality
        $encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
        $encoderParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter($myEncoder, $quality)
        # get codec
        $myImageCodecInfo = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|where {$_.MimeType -eq 'image/jpeg'}

        #save to file
        $bmp.Save($imageTarget,$myImageCodecInfo, $($encoderParams))
        $bmp.Dispose()

    }
    else
    {
        Write-Host "INFO: Cancelled save image dialog..." -foreground "Yellow"
        return
    }

}