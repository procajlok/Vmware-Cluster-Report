<#
=============================================================================================
Name:           Skrypt generujący raport podsumowania środowiska Vmware
Version:        2.0
Script by:      Krzysztof Procajło
Date:           06.2024 
Description:    
============================================================================================
#>

####################################
# Funkcje skryptu                  #
####################################
#LOG Function
Function sPrint {
    param( 
        
        [byte]$Type,

        [string]$Message,

        [bool]$WriteToLogFile
        
    )
    <#
        1- INFO
        2- WARNING
        5- DEBUG
        9- info do pliku LOGu
        0- ERROR
    #>
    

    $TimeStamp = Get-Date -Format "dd.MMM.yyyy HH:mm:ss"
    $Time = Get-Date -Format "HH:mm:ss"

    if ($Type -eq 1) {
        Write-Host "[INFO]    - $Time - $Message" -ForegroundColor Green

        if (($WriteToLogFile) -and ($Logging)) {
            Add-Content -Path $LogFile -Value "[INFO]    - $TimeStamp - $Message"
        }
    }
    elseif ($Type -eq 2) {
        Write-Host "[WARNING] - $Time - $Message" -ForegroundColor Yellow

        if (($WriteToLogFile) -and ($Logging)) {
            Add-Content -Path $LogFile -Value "[WARNING] - $TimeStamp - $Message"
        }
    }
    elseif ($Type -eq 5) {
        if (($WriteToLogFile) -and ($Logging)) {
            Add-Content -Path $LogFile -Value "[DEBUG]   - $TimeStamp - $Message"
        }
    }
    elseif ($Type -eq 9) {
        if (($WriteToLogFile) -and ($Logging)) {
            Add-Content -Path $LogFile -Value "$Message"
        }
    }
    elseif ($Type -eq 6) {
        if (($WriteToLogFile) -and ($Logging)) {
            Add-Content -Path $LogFile -Value ""
        }
    }
    elseif ($Type -eq 0) {
        Write-Host "[ERROR]   - $Time - $Message" -ForegroundColor Red

        if (($WriteToLogFile) -and ($Logging)) {
            Add-Content -Path $LogFile -Value "[ERROR]   - $TimeStamp - $Message"
        }
    }
    else {
        Write-Host "[UNKNOWN] - $Time - $Message" -ForegroundColor Gray

        if (($WriteToLogFile) -and ($Logging)) {
            Add-Content -Path $LogFile -Value "[UNKNOWN] - $TimeStamp - $Message"
        }
    }
}
#Get DRS Score Function
Function Get-DRSScore {
    param(
        [Parameter(Mandatory = $true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.ComputeResourceImpl]$Cluster,
        [switch]$OnlyScore
    )

    $drsScoreBuckets = @("0%-20%", "21%-40%", "41%-60%", "61%-80%", "81%-100%")

    $drsScoreResults = $Cluster.ExtensionData.SummaryEx | select DrsScore, NumVmsPerDrsScoreBucket

    if ($OnlyScore) {
        return "$(${drsScoreResults}.DrsScore)"
    }
    else {
        $output = "Cluster DRS Score: $(${drsScoreResults}.DrsScore)`n"
        $output += "VM DRS Score`n"
        $count = 0
        foreach ($i in ${drsScoreBuckets}) {
            $output += "${i} - $(${drsScoreResults}.NumVmsPerDrsScoreBucket[$count]) VMs`n"
            $count++
        }
        return $output
    }
}
#Get letter from Windows Drives
function GetDriveLetter {
    param( 
        
        [string]$VM,
        [string]$VMDKFile,
        [pscredential]$credential1,
        [pscredential]$credential2,
        [string]$CIMSessionAttr
    )
    
    $CIMEnable = ""
    
        try {
            sPrint -WriteToLogFile $true -Type 1 -Message "Dla $VM próba uprawnieniami #1"
            $CimSesion = New-CimSession -ComputerName $VM  -Credential $credential1 -ErrorAction Stop
            sPrint -WriteToLogFile $true -Type 1 -Message "Dla $VM próba uprawnieniami #1 UDANA"
        }
        catch {
            sPrint -WriteToLogFile $true -Type 2 -Message "Dla $VM próba uprawnieniami #1 NIEUDANA"
            try {
                sPrint -WriteToLogFile $true -Type 1 -Message "Dla $VM próba uprawnieniami #2"
                $CimSesion = New-CimSession -ComputerName $VM  -Credential $credential2 -ErrorAction Stop
                sPrint -WriteToLogFile $true -Type 1 -Message "Dla $VM próba uprawnieniami #2 UDANA"
            }
            catch {
                sPrint -WriteToLogFile $true -Type 2 -Message "Dla $VM CIM/WMI NIEDOSTĘPNE!"
            }
        }

    try {
        Get-CimInstance -CimSession $CimSesion -ClassName Win32_DiskDrive -ErrorAction Stop
        $CIMEnable = "true"
    }
    catch {
        $CIMEnable = "false"
        sPrint -WriteToLogFile $true -Type 2 -Message "Dla $VM CIM/WMI niedostępne!"
    }

    If ($CIMEnable -eq "true"){
        $VMView = Get-VM -Name $VM | Get-View
        $ServerDiskToVolume = Get-CimInstance -CimSession $CimSesion -Class Win32_DiskDrive | ForEach-Object {
            $Dsk = $_
            $query = "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($_.DeviceID)'} WHERE ResultClass=Win32_DiskPartition" 
            Get-CimInstance -CimSession $CimSesion -Query $query | ForEach-Object { 
                $partition = $_
                $query = "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($_.DeviceID)'} WHERE ResultClass=Win32_LogicalDisk" 
                Get-CimInstance -CimSession $CimSesion -Query $query | Select-Object DeviceID, VolumeName,
                    @{ Label = "SCSITarget"; Expression = { $Dsk.SCSITargetId } },
                    @{ Label = "SCSIBus"; Expression = { $Dsk.SCSIBus } }
            }
        }
        
        $VMDisks = ForEach ($VirtualSCSIController in ($VMView.Config.Hardware.Device | Where-Object { $_.DeviceInfo.Label -match "SCSI Controller" })) {
            ForEach ($VirtualDiskDevice in ($VMView.Config.Hardware.Device | Where-Object { $_.ControllerKey -eq $VirtualSCSIController.Key })) {
                $VMSummary = [pscustomobject]@{
                    VM              = $VMView.Name
                    HostName        = $VMView.Guest.HostName
                    PowerState      = $VMView.Runtime.PowerState
                    DiskFile        = $VirtualDiskDevice.Backing.FileName
                    DiskName        = $VirtualDiskDevice.DeviceInfo.Label
                    DiskSize        = $VirtualDiskDevice.CapacityInKB * 1KB
                    SCSIController  = $VirtualSCSIController.BusNumber
                    SCSITarget      = $VirtualDiskDevice.UnitNumber
                    DeviceID        = $null
                }
                $MatchingDisk = $ServerDiskToVolume | Where-Object {
                    $_.SCSITarget -eq $VMSummary.SCSITarget -and $_.SCSIBus -eq $VMSummary.SCSIController
                } 
                if ($MatchingDisk.Count -gt 1) {
                    Write-Error "Too many matches: $($MatchingDisk | Select-Object -Property DeviceID, VolumeName, SCSI* | Out-String)"
                    $VMSummary.DeviceID = "Error: Too Many"
                } elseif (@($MatchingDisk).Count -eq 1) {
                    $VMSummary.DeviceID = $MatchingDisk.DeviceID
                } else {
                    Write-Error "No match found"
                    $VMSummary.DeviceID = "Error: None found"
                }
        
                $VMSummary
            }
        }
        $VMDisks
    }    
}

function Get-MemoryInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [switch]$Summary
    )

    $cluster = Get-Cluster -Name $ClusterName

    $hosts = Get-VMHost -Location $cluster | Sort-Object Name

    $totalMemoryGB = 0
    $usedMemoryGB = 0

    $memoryInfo = @()
    
    foreach ($vmhost in $hosts) {
        $hostTotalMemoryGB = [math]::round($vmhost.MemoryTotalMB / 1024, 2)
        $hostUsedMemoryGB = [math]::round($vmhost.MemoryUsageMB / 1024, 2)
        $hostFreeMemoryGB = $hostTotalMemoryGB - $hostUsedMemoryGB
        
        $totalMemoryGB += $hostTotalMemoryGB
        $usedMemoryGB += $hostUsedMemoryGB

        $info = [PSCustomObject]@{
            HostName      = $vmhost.Name
            TotalMemoryGB = $hostTotalMemoryGB
            UsedMemoryGB  = $hostUsedMemoryGB
            FreeMemoryGB  = $hostFreeMemoryGB
        }
        
        $memoryInfo += $info
    }

    if ($Summary.IsPresent) {
        $totalFreeMemoryGB = $totalMemoryGB - $usedMemoryGB
        $summaryInfo = [PSCustomObject]@{
            TotalMemoryGB = [math]::round($totalMemoryGB, 2)
            UsedMemoryGB  = [math]::round($usedMemoryGB, 2)
            FreeMemoryGB  = [math]::round($totalFreeMemoryGB, 2)
            PercentUsedMemory = ([math]::round($usedMemoryGB, 2)/[math]::round($totalMemoryGB, 2))*100
        }

        return $summaryInfo
    } else {
        return $memoryInfo
    }
}

function Get-VMStatusSummary {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClusterName
    )
    
    $cluster = Get-Cluster -Name $ClusterName
    
    $vms = Get-VM -Location $cluster

    $runningVMs = 0
    $stoppedVMs = 0
    
    foreach ($vm in $vms) {
        if ($vm.PowerState -eq 'PoweredOn') {
            $runningVMs++
        } elseif ($vm.PowerState -eq 'PoweredOff') {
            $stoppedVMs++
        }
    }
    
    $summary = [PSCustomObject]@{
        RunningVMs = $runningVMs
        StoppedVMs = $stoppedVMs
    }
    
    return $summary
}

function Get-LVVolumesReport {
    $Datastores = Get-Datastore
    $totalUsed = 0
    $totalSize = 0

    ForEach ($Datastore in $Datastores) {
        if ($Datastore.Name -like "*LV*") {
            $totalCapacityGB += [math]::round($Datastore.CapacityGB, 2) 
            $FreeCapacityGB += [math]::round($Datastore.FreeSpaceGB, 2)
        }
    }
    
    $usedCapacityGB = [math]::round($totalCapacityGB - $FreeCapacityGB, 2)

    $LVVolumeSummary = [PSCustomObject]@{
        usedCapacityGB = $usedCapacityGB
        totalCapacityGB  = [math]::round($totalCapacityGB, 2)
        FreeCapacityGB  = [math]::round($FreeCapacityGB, 2)
        PercentUsedMemory = ([math]::round($usedCapacityGB, 2)/[math]::round($totalCapacityGB, 2))*100
    }
    return $LVVolumeSummary
}

####################################
# Potrzebne moduły                 #
####################################
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
# PowerCLI
if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI)) {
    Write-Output "VMware.PowerCLI nie jest zainstalowane. Instalacja..."
    Install-Module -Name VMware.PowerCLI -AllowClobber -Force -SkipPublisherCheck -Confirm:$False

    # Konfiguracja PowerCLI
    Import-Module VMware.PowerCLI
    Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$False
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$False
} else {
    Write-Output "VMware.PowerCLI jest już zainstalowane."
    Import-Module VMware.PowerCLI
}

# ActiveDirectory
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Output "ActiveDirectory nie jest zainstalowane. Instalacja..."
    Install-WindowsFeature -Name RSAT-AD-PowerShell
} else {
    Write-Output "ActiveDirectory jest już zainstalowane."
    Import-Module ActiveDirectory
}

# ImportExcel
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Output "ImportExcel nie jest zainstalowane. Instalacja..."
    Install-Module -Name ImportExcel -Force -Confirm:$False
} else {
    Write-Output "ImportExcel jest już zainstalowane."
    Import-Module ImportExcel
}

####################################
# Zmienne skryptu                  #
####################################
$ScriptVersion = "2.0"
$ScriptMode = "ESX" # ESX (dla pojedynczego serwera ESX); Cluster (dla klastra vcenter)
$ReportFolderPath = "D:\Scripts\ClusterVmwareReport\Reports"
$ReportFileNamePrefix = "VMCL1_PROD"

# Date and Time format
$Date = Get-Date -Format d/MMM/yyyy
$Time = Get-Date -Format "HH:mm:ss"

# Report File Name
$FileTimeSuffix = ((Get-Date -Format dMMMyy).ToString()) + "-" + ((get-date -Format HHmmss).ToString())
$ReportFileLocation = $ReportFolderPath + "\" + $ReportFileNamePrefix + "-" + $FileTimeSuffix + ".html"
$ExcellFileLocation = $ReportFolderPath + "\" + $ReportFileNamePrefix + "-" + $FileTimeSuffix + ".xlsx"
$ReportFileLocation

#Ustawienia logowania
$LogFile = $ReportFolderPath + "\" + "ScriptLog" + ".txt"
[bool]$Logging = $True

# Ustawienia wysyłki maila
$enablemail = "yes"   # yes/no
$smtpServer = "" # Mailserver
$mailfrom = ""
$mailto = ""
$SMTPUsername = ""
$SMTPPassword = ""


# Print MSG
sPrint -WriteToLogFile $true -Type 9 -Message "========================================================="
sPrint -WriteToLogFile $true -Type 1 -Message "Started! Vmware Reporting Script (Version $ScriptVersion)"

####################################
# Uprawnienia                      #
####################################
$username1 = ""
$password1 = ""
$secstr1 = New-Object -TypeName System.Security.SecureString
$password1.ToCharArray() | ForEach-Object {$secstr1.AppendChar($_)}
$GetCredential1 = new-object -typename System.Management.Automation.PSCredential -argumentlist $username1, $secstr1

$username2 = ""
$password2 = ""
$secstr2 = New-Object -TypeName System.Security.SecureString
$password2.ToCharArray() | ForEach-Object {$secstr2.AppendChar($_)}
$GetCredential2 = new-object -typename System.Management.Automation.PSCredential -argumentlist $username2, $secstr2

####################################
# Połączenie do vCenter            #
####################################
$vcserver = "" # Name or IP vcenter server or single ESXi server
$username = ""
$password = ""

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

try {
    Connect-VIServer -Server $vcserver -Credential $credential -ErrorAction Stop
    sPrint -WriteToLogFile $true -Type 1 -Message "Połączono z vCenter $vcserver"
}
catch {
    sPrint -WriteToLogFile $true -Type 0 -Message "Błąd połączenia z vCenter!"
}

$vcversion = get-view serviceinstance

#############################
# Poczatek raportu HTML     #
#############################
$CSSStyle = "<!DOCTYPE html>
<html>
<head>
<title>VMware Environment Report</title>
<style>
/*Reset CSS*/
html, body, div, span, applet, object, iframe, h1, h2, h3, h4, h5, h6, p, blockquote, pre, a, abbr, acronym, address, big, cite, code, del, dfn, em, img, ins, kbd, q, s, samp,
small, strike, strong, sub, sup, tt, var, b, u, i, center, dl, dt, dd, ol, ul, li, fieldset, form, label, legend, table, caption, tbody, tfoot, thead, tr, th, td,
article, aside, canvas, details, embed, figure, figcaption, footer, header, hgroup, menu, nav, output, ruby, section, summary, 
time, mark, audio, video {margin: 0;padding: 0;border: 0;font-size: 100%;font: inherit;vertical-align: baseline;}
ol, ul {list-style: none;}
blockquote, q {quotes: none;}
blockquote:before, blockquote:after,
q:before, q:after {content: '';content: none;}
table {border-collapse: collapse;border-spacing: 0;}
/*Reset CSS*/

body{
    width:100%;
    min-width:1024px;
    font-family: Verdana, sans-serif;
    font-size:14px;
    /*font-weight:300;*/
    line-height:1.5;
    color:#222222;
    background-color:#fcfcfc;
}

p{
    color:222222;
}

strong{
    font-weight:600;
}

h1{
    font-size:30px;
    font-weight:300;
}

h2{
    font-size:20px;
    font-weight:300;
}

#ReportBody{
    width:95%;
    height:500;
    /*border: 1px solid;*/
    margin: 0 auto;
}

.Overview{
    width:100%;
	min-width:1280px;
    margin-bottom:30px;
}

.OverviewFrame{
    background:#F9F9F9;
    border: 1px solid #CCCCCC;
}

table#Overview-Table{
    width:100%;
    border: 0px solid #CCCCCC;
    background:#F9F9F9;
    margin-top:0px;
}

table#Overview-Table td {
    padding:0px;
    border: 0px solid #CCCCCC;
    text-align:center;
    vertical-align:middle;
}

.VMHosts{
    width:100%;
    /*height:200px;*/
    /*border: 1px solid;*/
    float:left;
    margin-bottom:30px;
}

table#VMHosts-Table tr:nth-child(odd){
    background:#F9F9F9;
}

table#Disks-Volumes-Table tr:nth-child(odd){
    background:#F9F9F9;
}

.Disks-Volumes{
    width:100%;
    /*height:400px;*/
    /*border: 1px solid;*/
    float:left;
    margin-bottom:30px;
}

.VMs{
    width:100%;
    /*height:200px;*/
    /*border: 1px solid;*/
    float:left;
    margin-bottom:22px;
    line-height:1.5;
}

table{
    width:100%;
    min-width:1280px;
    /*table-layout: fixed;*/
    /*border-collapse: collapse;*/
    border: 1px solid #CCCCCC;
    /*margin-bottom:15px;*/
}

/*Row*/
tr{
    font-size: 12px;
}

/*Column*/
td {
    padding:10px 8px 10px 8px;
    font-size: 12px;
    border: 1px solid #CCCCCC;
    text-align:center;
    vertical-align:middle;
}

/*Table Heading*/
th {
    background: #f3f3f3;
    border: 1px solid #CCCCCC;
    font-size: 14px;
    font-weight:normal;
    padding:12px;
    text-align:center !important;
    vertical-align:middle;
}
</style>
</head>
<body>
<br><br>
<center><h1>Vmware Environment Report</h1></center>
<center><font face=""Verdana,sans-serif"" size=""3"" color=""#222222"">Wygenerowano $($Date) o $($Time)</font></center>
$($hlString)
<br>
<div id=""ReportBody""><!--Start ReportBody-->"

$CSSStyle | Out-File $ReportFileLocation

#############################
# Ikony Base64              #
#############################
$Base64Image_ToolsOK            = "data:image/png;base64,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"
$Base64Image_ToolsNotInstalled  = "data:image/png;base64,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"
$Base64Image_ToolsNotRunning    = "data:image/png;base64,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"
$Base64Image_Warning            = "data:image/png;base64,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"
$Base64Image_ErrorCircle        = "data:image/png;base64,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"
$Base64Image_Tools              = "data:image/png;base64,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"
$Base64Image_NIC                = "data:image/png;base64,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"
$Base64Image_CPU                = "data:image/png;base64,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"
$Base64Image_RAM                = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAACXBIWXMAAAsTAAALEwEAmpwYAAABnUlEQVR4nO1VPUvDUBR1cXLTpYvgB4J1FZKgKAXbpDFpbqBUiyIiFURpQasOOlQRilNBcHATcbBSbKPgH9BfII6OVn+BnQrtlVNj2xQRhCCIvXAI99x77nnv5ZF0dLTjf0foJtSvXRt+t0AW9TkMdIvWNIsqumWyW9AsqmgFc7XZpOimgV4HFRsmBbP0WVDPTVbPqA4tZ68s28JnbT7n5KGvmxTM0pcm41FiUWkgkKEa70s6eeTgUW/moW+b8N87LtyW6csG9LzNXzl55DVNvoW3b+O3Jq6i0GQiqfQkqqFntyGp9FQ3ERUq4TzXFyXObg1yLDrJtzu9PBOe4vt9DytGkB/SPSzKRkWQycQTOXjU0Yd+6KDHHPsdNXYiKPQKMrU8ynd7Hk4sjPFjupsXZn1czHSxTgq/HXeyqBjlj0UZZeTgUUcf+qGDHnMwT5DppWknRlJUqOqySVUIGBuOL7EQNEbi89LKUdy7uzQ3ETtJDKciEd/i6ebQgUzy3MX2wKEoU7hmIlMYOXjU0Yd+6KDHHNFven/6u2nH78U7NuvYMfpWvBsAAAAASUVORK5CYII="

#############################
# PANEL PODSUMOWANIA        #
#############################
if ($ScriptMode -eq "Cluster"){

# Wywołanie funkcji dla panelu podsumowania
$DRSScore = Get-DRSScore -Cluster (Get-Cluster VMCL1_PROD) -OnlyScore

$ClusterMemorySummary = Get-MemoryInfo -ClusterName (Get-Cluster VMCL1_PROD) -Summary
$ClusterMemorySummaryPercentUsedGB = [math]::round($ClusterMemorySummary.PercentUsedMemory, 2)
$ClusterMemorySummaryTotalTB = [math]::round($ClusterMemorySummary.TotalMemoryGB/1024, 2)
$ClusterMemorySummaryUsedTB = [math]::round($ClusterMemorySummary.UsedMemoryGB/1024, 2)

$CLusterVMStatusSummary = Get-VMStatusSummary -ClusterName (Get-Cluster VMCL1_PROD)
$CLusterVMStatusSummaryTotal = $CLusterVMStatusSummary.RunningVMs+$CLusterVMStatusSummary.StoppedVMs

$LVVolumesSummary = Get-LVVolumesReport
$LVVolumesSummaryUsedTB = [math]::round($LVVolumesSummary.usedCapacityGB/1024, 2) 
$LVVolumesSummaryFreeTB = [math]::round($LVVolumesSummary.freeCapacityGB/1024, 2) 
$LVVolumesSummaryTotalTB = [math]::round($LVVolumesSummary.totalCapacityGB/1024, 2)  
$LVVolumesSummaryPercentUsedTB = [math]::round($LVVolumesSummary.PercentUsedMemory, 2)  

# Generowanie panelu podsumowania
$PanelshtmlContent = @"
<h2>Cluster DRS Information</h2>
<table border='1'>
    <tr>
        <th>Cluster DRS Score</th>
        <th>Total VM's</th>
        <th>Used RAM</th>
        <th>Used LV Datastore</th>
    </tr>
    <tr>
        <td><center><h2>$DRSScore</h2></center></td>
        <td><center><div><p style="font-size:20px;">$($CLusterVMStatusSummaryTotal)</p> On: $($CLusterVMStatusSummary.RunningVMs) Off: $($CLusterVMStatusSummary.StoppedVMs)</div></center></td>
        <td><center><div><p style="font-size:20px;">$ClusterMemorySummaryUsedTB TB</p>$ClusterMemorySummaryTotalTB TB ($ClusterMemorySummaryPercentUsedGB%)</div></center></td>
        <td><center><div><p style="font-size:20px;">$LVVolumesSummaryUsedTB TB</p>$LVVolumesSummaryTotalTB TB ($LVVolumesSummaryPercentUsedTB%)</div></center></td>
    </tr>
</table>
"@

if ($PanelshtmlContent) { sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano panele główne" }
$PanelshtmlContent | Out-File -Append $ReportFileLocation

}

#############################
# RAM Cluster               #
#############################
function Get-VMHostStatus {
    $vmHosts = Get-VMHost | Get-View | Sort-Object Name
    $vmHostStatus = @()

    foreach ($vmHost in $vmHosts) {
        $triggeredAlarms = if ($vmHost.TriggeredAlarmState) {
            ($vmHost.TriggeredAlarmState | ForEach-Object { (Get-AlarmDefinition -Id $_.Alarm).Name }) -join ", "
        }
        else {
            "Brak"
        }
        
        $status = [PSCustomObject]@{
            HostName        = $vmHost.Name
            OverallStatus   = $vmHost.OverallStatus
            ConfigStatus    = $vmHost.ConfigStatus
            TriggeredAlarms = $triggeredAlarms
        }
        
        $vmHostStatus += $status
    }
    
    return $vmHostStatus
}

# Function to get hardware configuration
function Get-HardwareInfo {
    $vmHosts = Get-VMHost | Get-View | Sort-Object Name
    $hardwareInfo = @()

    foreach ($vmHost in $vmHosts) {
        $hardware = $vmHost.Summary.Hardware
        $uptime = (Get-Date) - $vmHost.Runtime.BootTime
        $serialNumber = $vmHost.Hardware.SystemInfo.OtherIdentifyingInfo | Where-Object { $_.IdentifierType.Key -eq "ServiceTag" } | Select-Object -ExpandProperty IdentifierValue
        
        $info = [PSCustomObject]@{
            HostName      = $vmHost.Name
            Vendor        = $hardware.Vendor
            Model         = $hardware.Model
            MemorySize    = [math]::round($hardware.MemorySize / 1GB, 2)
            CpuModel      = $hardware.CpuModel
            CpuMhz        = $hardware.CpuMhz
            NumCpuPkgs    = $hardware.NumCpuPkgs
            NumCpuCores   = $hardware.NumCpuCores
            NumCpuThreads = $hardware.NumCpuThreads
            NumNics       = $hardware.NumNics
            NumHBAs       = $hardware.NumHBAs
            SerialNumber  = $serialNumber
            Uptime        = '<p style="text-align:center">{0}<span style="font-size:10px;color:#BDBDBD"> Days</span><br>{1}g {2}m</p>' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        }
        $hardwareInfo += $info
    }
    return $hardwareInfo
}

# Function to generate HTML report
function Generate-HTMLReport-HostHardware {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClusterName
    )
    
    # Get all info
    $memoryInfo = Get-MemoryInfo -ClusterName $ClusterName
    $hostStatus = Get-VMHostStatus
    $hardwareInfo = Get-HardwareInfo
    
    # Merge all info by HostName
    $mergedInfo = @()
    foreach ($memory in $memoryInfo) {
        $status = $hostStatus | Where-Object { $_.HostName -eq $memory.HostName }
        $hardware = $hardwareInfo | Where-Object { $_.HostName -eq $memory.HostName }
        
        $info = [PSCustomObject]@{
            HostName        = $memory.HostName
            TotalMemoryGB   = $memory.TotalMemoryGB
            UsedMemoryGB    = $memory.UsedMemoryGB
            FreeMemoryGB    = $memory.FreeMemoryGB
            OverallStatus   = $status.OverallStatus
            ConfigStatus    = $status.ConfigStatus
            TriggeredAlarms = $status.TriggeredAlarms
            Vendor          = $hardware.Vendor
            Model           = $hardware.Model
            #MemorySize     = $hardware.MemorySize
            CpuModel        = $hardware.CpuModel
            CpuMhz          = $hardware.CpuMhz
            NumCpuPkgs      = $hardware.NumCpuPkgs
            NumCpuCores     = $hardware.NumCpuCores
            NumCpuThreads   = $hardware.NumCpuThreads
            NumNics         = $hardware.NumNics
            NumHBAs         = $hardware.NumHBAs
            SerialNumber    = $hardware.SerialNumber
            Uptime          = $hardware.Uptime
        }
        
        $mergedInfo += $info
    }
    
    # Generate HTML content
    $htmlContent = @"
    <html>
    <head>
        <style>
            table { border-collapse: collapse; width: 100%; }
            /*th, td { border: 1px solid black; padding: 8px; text-align: left; }*/
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h2>Cluster Report for $ClusterName</h2>
        <table>
            <tr>
                <th>Host Name</th>
                <th>Total Memory (GB)</th>
                <th>Used Memory (GB)</th>
                <th>Free Memory (GB)</th>
                <th>Overall Status</th>
                <th>Config Status</th>
                <th>Alarms</th>
                <th>Vendor</th>
                <th>Model</th>
                <th>CPU Model</th>
                <th>CPU MHz</th>
                <th><center><div class='tooltip'><img src='$Base64Image_CPU' alt='Tools' ok=''><span class='tooltiptext'>CPU Sockets<br>Cores/Threads</span></div></center></th>
                <th>Num NICs</th>
                <th>Num HBAs</th>
                <th>Serial Number</th>
                <th>Uptime</th>
            </tr>
"@

    foreach ($info in $mergedInfo) {
        $htmlContent += "<tr><td>$($info.HostName)</td><td>$($info.TotalMemoryGB)</td><td>$($info.UsedMemoryGB)</td><td>$($info.FreeMemoryGB)</td><td>$($info.OverallStatus)</td><td>$($info.ConfigStatus)</td><td>$($info.TriggeredAlarms)</td><td>$($info.Vendor)</td><td>$($info.Model)</td><td>$($info.CpuModel)</td><td>$($info.CpuMhz)</td><td>$($info.NumCpuPkgs)<span style='font-size:10px;color:#BDBDBD'> Cores</span><br>$($info.NumCpuCores)/$($info.NumCpuThreads)</td><td>$($info.NumNics)</td><td>$($info.NumHBAs)</td><td>$($info.SerialNumber)</td><td>$($info.Uptime)</td></tr>"
    }

    $htmlContent += @"
        </table>
    </body>
    </html>
"@

    # Save the HTML content to a file
    return $htmlContent
}

# Generate and save the HTML report
Generate-HTMLReport-HostHardware -ClusterName (Get-Cluster VMCL1_PROD) | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje o hostach"

#######################
# VMware ESX versions #
#######################
get-vmhost | 
ForEach-Object { 
    $server = $_ | get-view
    $server.Config.Product | 
    Select-Object @{Name = 'Name'; Expression = { $server.Name } }, Version, Build, FullName 
} | 
Sort-Object Name |
ConvertTo-Html -Title "VMware ESX server versions" -Body "<H2>VMware ESX server versions and builds.</H2>" -Head "<link rel='stylesheet' href='style.css' type='text/css' />" | 
Out-File -Append $ReportFileLocation

######################
# VMware VC version  #
######################
$vcversion.content.about | Select-Object Version, Build, FullName | ConvertTo-Html -Title "VMware VirtualCenter version" -Body "<H2>VMware VC version.</H2>" -Head "<link rel='stylesheet' href='style.css' type='text/css' />" | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje wersji vCenter oraz ESXi"

#############
# Snapshots #
#############

$snapshots = Get-VM | Get-Snapshot
$snapshotData = @()

foreach ($snap in $snapshots) {
    $snapevent = Get-VIEvent -Entity $snap.VM -Types Info -Finish $snap.Created -MaxSamples 1 | Where-Object { $_.FullFormattedMessage -imatch 'Task: Create virtual machine snapshot' }
    $creator = if ($snapevent -ne $null) { $snapevent.UserName } else { "Unknown" }

    $daysOld = (New-TimeSpan -Start $snap.Created -End (Get-Date)).Days

    $snapshotData += [PSCustomObject]@{
        VM          = $snap.VM.Name
        Name        = $snap.Name
        Created     = $snap.Created
        Description = $snap.Description
        Creator     = $creator
        DaysOld     = $daysOld
    }
}

$htmlContent = @"
<html>
<head>
    <title>Snapshots Active</title>
    <link rel='stylesheet' href='style.css' type='text/css' />
</head>
<body>
    <h2>Snapshots Active</h2>
    <table border="1">
        <tr>
            <th>VM</th>
            <th>Name</th>
            <th>Created</th>
            <th>Description</th>
            <th>Creator</th>
            <th>Days Old</th>
        </tr>
"@

foreach ($snapshot in $snapshotData) {
    $color = if ($snapshot.DaysOld -gt 7) { "style='background-color: red;color: white;'" } else { "" }
    $htmlContent += @"
        <tr>
            <td>$($snapshot.VM)</td>
            <td>$($snapshot.Name)</td>
            <td>$($snapshot.Created)</td>
            <td>$($snapshot.Description)</td>
            <td>$($snapshot.Creator)</td>
            <td $color>$($snapshot.DaysOld)</td>
        </tr>
"@
}

$htmlContent += @"
    </table>
</body>
</html>
"@

$htmlContent | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje o Snapshotach"

#################################
# VMware CDROM connected to VMs #
#################################

Get-vm | Where-Object { $_ | get-cddrive } | 
ForEach-Object {
    $vm = $_
    $cdDrive = $vm | get-cddrive 
    if ($cdDrive) {
        $connectionStates = $cdDrive.ConnectionState -split ","
        [PSCustomObject]@{
            VMName          = $vm.Name;
            ISOPath         = $cdDrive.ISOPath;
            Connection      = $connectionStates[0];
            ControlGuest    = $connectionStates[1];
            StartConnection = $connectionStates[2];
        }
    }
} | Where-Object { $_.ISOPath } | Sort-Object VMName | 
ConvertTo-Html -Title "CDROMs connected" -Body "<H2>CDROMs connected.</H2>" -Head @"
    <link rel='stylesheet' href='style.css' type='text/css' />
    <style>
        td { padding: 5px; }
        td.connected { background-color: red; color: white; }
    </style>
"@ | 
ForEach-Object {
    $_ -replace "<td>(Connected)</td>", '<td class="connected">$1</td>'
} | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje o podpiętych CD-ROM"

#########################################
# VMs created in the last 14 days #
#########################################

$StartDate = (Get-Date).AddDays(-14)
$vms = Get-VM | Where-Object {
    $_.CreateDate -gt $StartDate
}

$vmTable = @()
foreach ($vm in $vms) {
    $events = Get-VIEvent -Entity $vm -Start $StartDate -MaxSamples 1000 | Where-Object { $_.FullFormattedMessage -like "*created*" }
    $createEvent = $events | Where-Object { $_.GetType().Name -eq "VmCreatedEvent" } | Select-Object -First 1
    
    if ($createEvent) {
        $vmTable += [PSCustomObject]@{
            VMName     = $vm.Name
            CreateDate = $vm.CreateDate
            CreatedBy  = $createEvent.UserName
            State      = $vm.PowerState
        }
    }
}

$vmTable | Sort-Object CreateDate | ConvertTo-Html -Title "VMs created in the last 14 days" -Body "<H2>List of VMs created in the last 14 days</H2>" -Head "<link rel='stylesheet' href='style.css' type='text/css' />" | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje o utworzonych VMkach w ciągu 14 dni"

#########################################
# VMware floppy drives connected to VMs #
#########################################

Get-vm | Where-Object { $_ | get-floppydrive | Where-Object { $_.ConnectionState.Connected -eq "true" } } | Select-Object Name | ConvertTo-Html -Title "Floppy drives connected" -Body "<H2>Floppy drives connected.</H2>" -Head "<link rel='stylesheet' href='style.css' type='text/css' />" | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje o dyskietkach"

#########################
# Datastore information #
#########################

function UsedSpace {
    param($ds)
    [math]::Round(($ds.CapacityMB - $ds.FreeSpaceMB) / 1024, 2)
}

function FreeSpace {
    param($ds)
    [math]::Round($ds.FreeSpaceMB / 1024, 2)
}

function PercFree {
    param($ds)
    [math]::Round((100 * $ds.FreeSpaceMB / $ds.CapacityMB), 0)
}

$Datastores = Get-Datastore
$Report = @()
ForEach ($Datastore in $Datastores) {
    $dsObj = "" | Select-Object Datastore, UsedGB, FreeGB, PercFree
    $dsObj.Datastore = $Datastore.Name
    $dsObj.UsedGB = UsedSpace $Datastore
    $dsObj.FreeGB = FreeSpace $Datastore
    $dsObj.PercFree = PercFree $Datastore
    $Report += $dsObj
}

$Report = $Report | Sort-Object PercFree

$htmlReport = $Report | ConvertTo-Html -Title "Datastore Space" -PreContent "<H2>Datastore space available</H2>" -PostContent "</html>"

$css = @"
<style>
  table {width: 100%; border-collapse: collapse;}
  th, td {border: 1px solid #ddd; padding: 8px; text-align: left;}
  th {background-color: #f2f2f2;}
  .bar-container { width: 100%; background-color: #f2f2f2; position: relative; }
  .bar { height: 18px; background-color: grey; text-align: left; line-height: 18px; color: white; padding-left: 5px; }
</style>
"@

$htmlReport = $htmlReport -replace '</head>', "$css`n</head>"

$Report | ForEach-Object {
    $percFree = $_.PercFree
    $barHtml = "<div class='bar-container'><div class='bar' style='width:$percFree%'>$percFree%</div></div>"
    $htmlReport = $htmlReport -replace ("<td>$percFree</td>"), ("<td>$barHtml</td>")
}

$htmlReport | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje o datastore"

##################
# VM information #
##################

$Report = @()

get-vm | ForEach-Object {
    $vm = Get-View $_.ID
    $osType = $vm.Guest.GuestFullName
    $vms = "" | Select-Object 'VM Name', Uptime, Backup, IPAddress, GuestFullName, State, TotalCPU, TotalMemory, TotalNics, Tools, MemoryReservation, CPUreservation, HDDs
    $vms.'VM Name'          = $vm.Name
    #$vms.HostName          = $vm.guest.hostname
    $vms.IPAddress          = $vm.guest.ipAddress
    $vms.GuestFullName      = $vm.guest.GuestFullName
    $vms.State              = $vm.summary.runtime.powerState
    $vms.TotalCPU           = $vm.summary.config.numcpu
    $vms.TotalMemory        = [math]::round($vm.summary.config.memorysizemb / 1024, 2)
    #$vms.MemoryUsage       = $vm.summary.quickStats.guestMemoryUsage
    $vms.TotalNics          = $vm.summary.config.numEthernetCards
    $vms.Tools              = $vm.guest.toolsstatus
    #$vms.ToolsVersion      = $vm.config.tools.toolsversion
    #$vms.MemoryLimit       = $vm.resourceconfig.memoryallocation.limit
    $vms.MemoryReservation  = $vm.resourceconfig.memoryallocation.reservation
    $vms.CPUreservation     = $vm.resourceconfig.cpuallocation.reservation
    #$vms.CPUlimit          = $vm.resourceconfig.cpuallocation.limit

    # Get HDD information
    $hdds = $vm.config.hardware.device | Where-Object { $_.DeviceInfo.Label -like "Hard disk*" } | ForEach-Object {
        $diskGuestInfo = ""
        $diskInfo = "" | Select-Object DiskLabel, FileName
        $diskInfo.DiskLabel = $_.DeviceInfo.Label
        $diskInfo.FileName = $_.Backing.Filename
        if ($osType -like "Microsoft Windows*") {$diskGuestInfo = GetDriveLetter -VM $vm.Name -credential1 $GetCredential1 -credential2 $GetCredential2 | Where-Object { $_.DiskFile -eq $diskInfo.FileName }}
        "$($diskInfo.DiskLabel) $($diskGuestInfo.DeviceID): $($diskInfo.FileName)"
    }
    
    $vms.HDDs = $hdds -join "<br>"
    
    # Get Calculate Uptime
    $bootTime = $vm.summary.runtime.bootTime
    if ($bootTime) {
        $uptime = (Get-Date) - $bootTime
        $vms.Uptime = '<p style=text-align:center>{0}<span style=font-size:10px;color:#BDBDBD> Days</span><br>{1}g {2}m</p>' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    }
    else {
        $vms.Uptime = '<p style=text-align:center><span style=font-size:10px;color:#BDBDBD>N/A</span></p>'
    }
    
    #Get Server Backup
    $vms.Backup = Get-TagAssignment -Entity $vm.Name | Where-Object {$_.Tag -like "*Commvault*"}
    if ($vms.Backup){
        $vms.Backup = "<center>$($vms.Backup.Tag)</center>"
    }

    # Replace ToolsStatus with Base64 Images
    $ToolsVersionTooltip = $vm.config.tools.toolsversion
    switch ($vms.Tools) {
        "toolsOk"           { $vms.Tools = "<div class=tooltip><img src=$Base64Image_ToolsOK alt=Tools OK><span class=tooltiptext>Tools OK(V:$ToolsVersionTooltip)</span></div>" }
        "toolsNotInstalled" { $vms.Tools = "<div class=tooltip><img src=$Base64Image_ToolsNotInstalled alt=Tools Not Installed><span class=tooltiptext>Tools not installed</span></div>" }
        "toolsNotRunning"   { $vms.Tools = "<div class=tooltip><img src=$Base64Image_ToolsNotRunning alt=Tools Not Running><span class=tooltiptext>Tools not running</span></div>" }
    }

    switch ($vms.State) {
        "poweredOn"     { $vms.State = "On" }
        "poweredOff"    { $vms.State = "Off" }
    }

    $Report += $vms
}

$Report = $Report | Sort-Object "VM Name"
$ExcellVMReport = $Report

$htmlReport = $Report | ConvertTo-Html -Title "Virtual Machine information" -Body "<H2>Virtual Machine information.</H2>"

$htmlDocument = @"
<html>
<head>
<title>Virtual Machine Information</title>
<style>
  .poweredOn { background-color: green; color: white; }
  .poweredOff { background-color: gray; color: white; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
  th { background-color: #f2f2f2; cursor: pointer; }
  th.sort-asc::after { content: ' ▲'; }
  th.sort-desc::after { content: ' ▼'; }
  .tooltip {
  position: relative;
  display: inline-block;
  /*border-bottom: 1px dotted black;*/ /* If you want dots under the hoverable text */
}

/* Tooltip text */
.tooltip .tooltiptext {
  visibility: hidden;
  width: 120px;
  background-color: black;
  color: #fff;
  text-align: center;
  padding: 5px 0;
  border-radius: 6px;
 
  /* Position the tooltip text - see examples below! */
  position: absolute;
  z-index: 1;
}

.DiskGuestInfo{
  color: red;
  /*font-size: 10px;*/
}

/* Show the tooltip text when you mouse over the tooltip container */
.tooltip:hover .tooltiptext {
  visibility: visible;
}
</style>
<script>
document.addEventListener('DOMContentLoaded', function() {
    const getCellValue = (tr, idx) => tr.children[idx].innerText || tr.children[idx].textContent;
    
    const comparer = (idx, asc) => (a, b) => ((v1, v2) => 
        v1 !== '' && v2 !== '' && !isNaN(v1) && !isNaN(v2) ? v1 - v2 : v1.toString().localeCompare(v2)
        )(getCellValue(asc ? a : b, idx), getCellValue(asc ? b : a, idx));
    
    document.querySelectorAll('th').forEach(th => th.addEventListener('click', (() => {
        const table = th.closest('table');
        Array.from(table.querySelectorAll('tr:nth-child(n+2)'))
            .sort(comparer(Array.from(th.parentNode.children).indexOf(th), this.asc = !this.asc))
            .forEach(tr => table.appendChild(tr));
        
        table.querySelectorAll('th').forEach(th => th.classList.remove('sort-asc', 'sort-desc'));
        th.classList.toggle('sort-asc', this.asc);
        th.classList.toggle('sort-desc', !this.asc);
    })));
});
</script>
</head>
<body>
$htmlReport
</body>
</html>
"@

# Add coloring to the VMState column
$htmlDocument = $htmlDocument -replace '(?s)(<td>On</td>)', '<td class="poweredOn">On</td>'
$htmlDocument = $htmlDocument -replace '(?s)(<td>Off</td>)', '<td class="poweredOff">Off</td>'
$htmlDocument = $htmlDocument -replace '&lt;br&gt;', '<br>'
$htmlDocument = $htmlDocument -replace '&lt;', '<'
$htmlDocument = $htmlDocument -replace '&gt;', '>'
$htmlDocument = $htmlDocument -replace '<th>Tools</th>', "<th><center><div class='tooltip'><img src='$Base64Image_Tools' alt='Tools' ok=''><span class='tooltiptext'>VMTools Status</span></div></center></th>"
$htmlDocument = $htmlDocument -replace '<th>TotalNics</th>', "<th><center><div class='tooltip'><img src='$Base64Image_NIC' alt='Tools' ok=''><span class='tooltiptext'>Total Network Cards</span></div></center></th>"
$htmlDocument = $htmlDocument -replace '<th>TotalCPU</th>', "<th><center><div class='tooltip'><img src='$Base64Image_CPU' alt='Tools' ok=''><span class='tooltiptext'>Total CPU</span></div></center></th>"
$htmlDocument = $htmlDocument -replace '<th>TotalMemory</th>', "<th><center><div class='tooltip'><img src='$Base64Image_RAM' alt='Tools' ok=''><span class='tooltiptext'>Total RAM</span></div></center></th>"

$htmlDocument | Out-File -Append $ReportFileLocation

sPrint -WriteToLogFile $true -Type 1 -Message "Załadowano informacje o wszystkich VMkach"

###############################
# VMware Timesync not enabled #
###############################

if ($false) {
    Get-VM | Get-View | Where-Object { $_.Config.Tools.syncTimeWithHost -eq $false } | Select-Object Name | Sort-object Name | ConvertTo-Html -Title "VMware timesync not enabled" -Body "<H2>VMware timesync not enabled.</H2>" -Head "<link rel='stylesheet' href='style.css' type='text/css' />" | Out-File -Append $ReportFileLocation
}

###############################
# STOPKA RAPORTU              #
###############################
ConvertTo-Html -Body '<br><br><center><p style="font-size:12px;color:#BDBDBD">Version: 2.0 | Powered By Krzysztof Procajło | 2024</p></center><br><br>' | Out-File -Append $ReportFileLocation 

sPrint -WriteToLogFile $true -Type 1 -Message "Koniec raportu"

###############################
# RAPORT EXCELLA              #
###############################
#$ExcellVMReport | Export-Excel -Path $ExcellFileLocation -WorkSheetname "VM Report" -AutoSize
#$data2 | Export-Excel -Path $filePath -WorkSheetname "Sheet2" -AutoSize -Append


######################
# E-mail HTML output #
######################
$SecurePassword = ConvertTo-SecureString $SMTPPassword -AsPlainText -Force
$Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SMTPUsername, $SecurePassword

try {
    $msg                = New-Object Net.Mail.MailMessage
    $att                = New-Object Net.Mail.Attachment($ReportFileLocation)
    #$attExcell          = New-Object Net.Mail.Attachment($ExcellFileLocation)
    $smtp               = New-Object Net.Mail.SmtpClient($smtpServer)
    $msg.From           = $mailfrom
    $msg.To.Add($mailto)
    $msg.Subject        = "Vmware Environment Report"
    $msg.Body           = ""
    $msg.Attachments.Add($att)
    #$msg.Attachments.Add($attExcell)
    $smtp.Port          = 587 # 587 lub 465 dla SSL
    $smtp.EnableSsl     = $false # lub $false w zależności od konfiguracji serwera SMTP
    $smtp.Credentials   = $Credentials
    $smtp.Send($msg)
    #$SendMailInfo = $smtp.Send($msg);
    sPrint -WriteToLogFile $true -Type 1 -Message "Wysłano maila do $mailto"
}
catch {
    sPrint -WriteToLogFile $true -Type 2 -Message "Nie wysłano maila do $mailto"
}
    if ($enablemail -match "yes") {
}

##############################
# Disconnect session from VC #
##############################

disconnect-viserver -confirm:$false
sPrint -WriteToLogFile $true -Type 1 -Message "Koniec skryptu"