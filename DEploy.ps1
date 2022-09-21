#Variables
$CustomName = Read-Host " enter a name Custom Name " #to define a "Firstname"
$api = "xxxxxxxxxxxxxxxxxxx" #Api Token for quick assingment
$confid = "XXXXXXX" #Client Config ID
$uri = "https://drive.google.com/" # Settings file from google Drive
$uri3 = "https://dl.teamviewer.com/download/version_15x/TeamViewer_MSI32.zip" #Host_msi from teamviewer
$dest = "$env:TEMP\xxxx"
$groupid = "gxxxxxxxx"

$twhost = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq “TeamViewer Host"}




function Get-Software{
    <#
        .SYNOPSIS
        Reads installed software from registry

        .PARAMETER DisplayName
        Name or part of name of the software you are looking for

        .EXAMPLE
        Get-Software -DisplayName *Office*
        returns all software with "Office" anywhere in its name
    #>

    param
    (
    # emit only software that matches the value you submit:
    [string]
    $DisplayName = '*'
    )


    #region define friendly texts:
    $Scopes = @{
        HKLM = 'All Users'
        HKCU = 'Current User'
    }

    $Architectures = @{
        $true = '32-Bit'
        $false = '64-Bit'
    }
    #endregion

    #region define calculated custom properties:
        # add the scope of the software based on whether the key is located
        # in HKLM: or HKCU:
        $Scope = @{
            Name = 'Scope'
            Expression = {
            $Scopes[$_.PSDrive.Name]
            }
        }

        # add architecture (32- or 64-bit) based on whether the registry key 
        # contains the parent key WOW6432Node:
        $Architecture = @{
        Name = 'Architecture'
        Expression = {$Architectures[$_.PSParentPath -like '*\WOW6432Node\*']}
        }
    #endregion

    #region define the properties (registry values) we are after
        # define the registry values that you want to include into the result:
        $Values = 'AuthorizedCDFPrefix',
                    'Comments',
                    'Contact',
                    'DisplayName',
                    'DisplayVersion',
                    'EstimatedSize',
                    'HelpLink',
                    'HelpTelephone',
                    'InstallDate',
                    'InstallLocation',
                    'InstallSource',
                    'Language',
                    'ModifyPath',
                    'NoModify',
                    'PSChildName',
                    'PSDrive',
                    'PSParentPath',
                    'PSPath',
                    'PSProvider',
                    'Publisher',
                    'Readme',
                    'Size',
                    'SystemComponent',
                    'UninstallString',
                    'URLInfoAbout',
                    'URLUpdateInfo',
                    'Version',
                    'VersionMajor',
                    'VersionMinor',
                    'WindowsInstaller',
                    'Scope',
                    'Architecture'
    #endregion

    #region Define the VISIBLE properties
        # define the properties that should be visible by default
        # keep this below 5 to produce table output:
        [string[]]$visible = 'DisplayName','DisplayVersion','Scope','Architecture'
        [Management.Automation.PSMemberInfo[]]$visibleProperties = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet',$visible)
    #endregion

    #region read software from all four keys in Windows Registry:
        # read all four locations where software can be registered, and ignore non-existing keys:
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                            'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Ignore |
        # exclude items with no DisplayName:
        Where-Object DisplayName |
        # include only items that match the user filter:
        Where-Object { $_.DisplayName -like $DisplayName } |
        # add the two calculated properties defined earlier:
        Select-Object -Property *, $Scope, $Architecture |
        # create final objects with all properties we want:
        Select-Object -Property $values |
        # sort by name, then scope, then architecture:
        Sort-Object -Property DisplayName, Scope, Architecture |
        # add the property PSStandardMembers so PowerShell knows which properties to
        # display by default:
        Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $visibleProperties -PassThru
    #endregion 
}

Function CheckinstalledTW{

#check if TW is installed multiple steps 

$tw32 = get-software -DisplayName Teamviewer

#check processes
if (get-process | Where-Object{$_.Name -imatch "TeamViewer"}) {Stop-Process -Name TeamViewer} 
    else {Write-Host -Object "no service"}
    if 
    (Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq “TeamViewer Host"}) {(Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq “TeamViewer Host"}).uninstall()}else {Write-Host -Object "no host"}
    if ($tw32) 
    {
        if ((get-software -DisplayName TeamViewer | Select-Object Architecture).architecture -eq "64-bit")
            {
            #64 bit TeamViewer Uninstall
            Start-Process -FilePath "C:\Program Files\TeamViewer\uninstall.exe" -ArgumentList "/S /v/qn"
            Write-Host -Object $tw32.DisplayName, $tw32.Architecture 
            }
        else
            {
            #32 bit TeamViewer Uninstall
            Start-Process -Filepath "C:\Program Files (x86)\TeamViewer\uninstall.exe" -ArgumentList "/S /v/qn"
            Write-Host -Object $tw32.DisplayName, $tw32.Architecture
            }
    }
    else
    {Write-Host -Object "no Full Host"}
}

Function Downloaddata{
#Check if path exists
$exists = Test-Path -Path $dest
if (!$exists) { $null = mkdir -Path $dest} #if path exists do nothing else add path
cd $dest

#DownLoad Settings
$exists = Test-Path -path $dest\Settings.tvopt
if (!$exists) {Invoke-WebRequest -Uri $uri -OutFile $dest\Settings.tvopt}
elseif($exists) {Write-Host -Object "Settings Already existing"}

#Download MSI and extract
$exists = Test-Path -path $dest\TeamViewer_MSI32.zip
if (!$exists) {Start-BitsTransfer -Source $uri3 -Destination $dest
Expand-Archive -Path TeamViewer_MSI32.zip -DestinationPath $dest} 
elseif($exists) {Write-Host -Object "MSI Already existing"}
}

Function Reinstallhost{
 msiexec.exe /x $dest\Host\TeamViewer_Host.msi /qn
 Start-Sleep -Seconds 5
 Write-Host -Object "Reinstalling"
 Installhost
}

Function Uninstallhost{
 msiexec.exe /x $dest\Host\TeamViewer_Host.msi /qn
}

Function Installhost{
msiexec.exe /i $dest\Host\TeamViewer_Host.msi /qn  APITOKEN=$api CUSTOMCONFIGID=$confid settingsfile="$dest\settings.tvopt" ASSIGNMENTOPTIONS=`"--alias=$CustomName-$env:COMPUTERNAME --group-id=$groupid --reassign`" 
Write-Host -Object "Installing, Wait.."
Start-Sleep -Seconds 10
}

Function starttw{
Start-Service -Name TeamViewer
}

Function stoptw{
Stop-Service -Name TeamViewer
}

Function restartTW{
Restart-Service -Name TeamViewer
}

Downloaddata
CheckinstalledTW
Installhost
