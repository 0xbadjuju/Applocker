$WindowsExePolicy = "C:\Windows_Folder_Exe_AppLocker.xml"
$WindowsDllPolicy = "C:\Windows_Folder_Dll_AppLocker.xml"
$ProgramFileExePolicy = "C:\Program_Files_Exe_AppLocker.xml"
$ProgramFileDllPolicy = "C:\Program_Files_Dll_AppLocker.xml"
$ProgramFileX86ExePolicy = "C:\Program_Files_x86_Exe_AppLocker.xml"
$ProgramFileX86DllPolicy = "C:\Program_Files_x86_Dll_AppLocker.xml"
$BlacklistExePolicy = "C:\Blacklist_Exe_AppLocker.xml"

[regex]$LimitAccessExes = "^csc`.exe$|^msbuild`.exe$|^cmd`.exe$|^powershell`.exe$|^powershell_ise`.exe$|^cscript`.exe$|^jscript`.exe$"

################################################################################
################################################################################
$ExeFiles = Get-ChildItem C:\Windows\*.exe -Recurse
$ExeFileInformation = $ExeFiles| Where {$_.Name -notmatch $LimitAccessExes} | Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$ExePublisher = $ExeFileInformation | ? Publisher -NotLike $null
$ExePublisher.Publisher.PublisherName | Sort-Object | Get-Unique

$ExePath = $ExeFileInformation | ? Publisher -Like $null

$ExeFileInformation | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User Everyone -Xml | Out-File $WindowsExePolicy

################################################################################
################################################################################
$DllFiles = Get-ChildItem C:\Windows\*.dll -Recurse
$DllFileInformation = $DllFiles | Where {$_.Name -notmatch $LimitAccessExes} | Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$DllPublisher = $DllFileInformation | ? Publisher -NotLike $null
$DllPublisher.Publisher.PublisherName | Sort-Object | Get-Unique

$DllPath = $DllFileInformation | ? Publisher -Like $null

$DllFileInformation | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User Everyone -Xml | Out-File $WindowsDllPolicy

#Whitelist bypass files
#system.management.automation.dll

################################################################################
################################################################################
$ExeProgramFiles = Get-ChildItem $env:ProgramFiles\*.exe -Recurse
$ExeProgramFilesInformation = $ExeProgramFiles | Where {$_.Name -notmatch $LimitAccessExes} | Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$ExeProgramFilesPublisher = $ExeProgramFilesInformation | ? Publisher -NotLike $null
$ExeProgramFilesPublisher.Publisher.PublisherName | Sort-Object | Get-Unique

$ExeProgramFilesPath = $ExeProgramFilesInformation | ? Publisher -Like $null

$ExeProgramFilesInformation | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User Everyone -Xml | Out-File $ProgramFileExePolicy

#Some folders have the file extention of .exe

################################################################################
################################################################################
$DllProgramFiles = Get-ChildItem $env:ProgramFiles\*.dll -Recurse
$DllProgramFilesInformation = $DllProgramFiles | Where {$_.Name -notmatch $LimitAccessExes} | Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$DllProgramFilesPublisher = $DllProgramFilesInformation | ? Publisher -NotLike $null
$DllProgramFilesPublisher.Publisher.PublisherName | Sort-Object | Get-Unique

$DllProgramFilesPath = $DllProgramFilesInformation | ? Publisher -Like $null

$DllProgramFilesInformation | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User Everyone -Xml | Out-File $ProgramFileDllPolicy

################################################################################
################################################################################
$ExeProgramFiles86 = Get-ChildItem ${env:ProgramFiles(x86)}\*.exe -Recurse
$ExeProgramFiles86Information = $ExeProgramFiles86 | Where {$_.Name -notmatch $LimitAccessExes} | Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$ExeProgramFiles86Publisher = $ExeProgramFiles86Information | ? Publisher -NotLike $null
$ExeProgramFiles86Publisher.Publisher.PublisherName | Sort-Object | Get-Unique

$ExeProgramFiles86Path = $ExeProgramFiles86Information | ? Publisher -Like $null

$ExeProgramFiles86Information | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User Everyone -Xml | Out-File $ProgramFileX86ExePolicy

################################################################################
################################################################################
$DllProgramFiles86 = Get-ChildItem ${env:ProgramFiles(x86)}\*.dll -Recurse
$DllProgramFiles86Information = $DllProgramFiles86 | Where {$_.Name -notmatch $LimitAccessExes} | Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$DllProgramFiles86Publisher = $DllProgramFiles86Information | ? Publisher -NotLike $null
$DllProgramFiles86Publisher.Publisher.PublisherName | Sort-Object | Get-Unique

$DllProgramFiles86Path = $DllProgramFiles86Information | ? Publisher -Like $null

$DllProgramFiles86Information | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User Everyone -Xml | Out-File $ProgramFileX86DllPolicy

################################################################################
################################################################################
$BlacklistExeFiles = @($ExeFiles)
$BlacklistExeFiles += @($ExeProgramFiles)
$BlacklistExeFiles += @($ExeProgramFiles86)

$BlacklistExeFileInformation = $BlacklistExeFiles | Where {$_.Name -match $LimitAccessExes} | Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$BlacklistExeFileInformation | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User Administrators -Xml | Out-File $BlacklistExePolicy

################################################################################
################################################################################
Set-AppLockerPolicy -XmlPolicy $WindowsExePolicy -Merge
Set-AppLockerPolicy -XmlPolicy $WindowsDllPolicy -Merge
Set-AppLockerPolicy -XmlPolicy $ProgramFileExePolicy -Merge
Set-AppLockerPolicy -XmlPolicy $ProgramFileDllPolicy -Merge
Set-AppLockerPolicy -XmlPolicy $ProgramFileX86ExePolicy -Merge
Set-AppLockerPolicy -XmlPolicy $ProgramFileX86DllPolicy -Merge
Set-AppLockerPolicy -XmlPolicy $BlacklistExePolicy -Merge

Start-Service -Name AppIDSvc