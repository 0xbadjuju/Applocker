﻿################################################################################
################################################################################
Function Invoke-AppLockerWhiteListWindows {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Name of Class to Test Against.")]
        [ValidateSet(“exe”,”dll”,”sys”)]
            [string]$FileExtention,
        [Parameter(Mandatory=$false, HelpMessage="Folder to Scan")]
            [string]$Folder,
        [Parameter(Mandatory=$false, HelpMessage="XML Output Policy File Name")]
            [string]$PolicyFileName = "AppLocker_Policy.xml",
        [Parameter(Mandatory=$false, HelpMessage="Default Group to Permit Access to.")]
            [string]$DefaultGroup = "Everyone",
        [Parameter(Mandatory=$false, HelpMessage="Limit Access to Dangerous Files.")]
            [switch]$LimitDangerous,
        [Parameter(Mandatory=$false, HelpMessage="User/Group to Limit to Dangerous Files to.")]
            [string]$User = "$env:COMPUTERNAME\Administrators",
        [Parameter(Mandatory=$false, HelpMessage="Immediately Apply Policy.")]
            [switch]$ApplyPolicy,
        [Parameter(Mandatory=$false, HelpMessage="Input of Object of Files")]
            [Object[]]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage="Additional Exe Files to Limit Access to")]
            [String[]]$AdditionalDangerousExes,
        [Parameter(Mandatory=$false, HelpMessage="Additional Dll Files to Limit Access to")]
            [String[]]$AdditionalDangerousDlls
    )
    Begin {
        
        $LimitAccessExesArray = 
        @(
        "csc.exe", 
        "cmd.exe", 
        "powershell.exe", 
        "powershell_ise.exe", 
        "cscript.exe", 
        "wscript.exe", 
        "jscript.exe",
        #SubTee Bypasses
        #He's done some really awesome work
        #https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
        "IEExec.exe",
        "rundll32.exe",
        "dfsvc.exe",
        "presentationhost.exe",
        "mshta.exe",
        "msdt.exe",
        "InstallUtil.exe", 
        "regsvcs.exe", 
        "regasm.exe", 
        "regsvr32.exe"
        "msbuild.exe"
        )
        $LimitAccessExesArray += @($AdditionalDangerous)
        [string]$LimitAccessExesString = "^"
        $LimitAccessExesString += $LimitAccessExesArray -join "$|^"
        $LimitAccessExesString += "$"
        [regex]$LimitAccessExes = $LimitAccessExesString -replace ".","`."

        $LimitAccessDllsArray = 
        @(
        "system.management.automation.dll",
        #SubTee Bypasses
        "dfshim.dll"
        )
        [string]$LimitAccessDllsString = "^"
        $LimitAccessDllsString += $LimitAccessDllsArray -join "$|^"
        $LimitAccessDllsString += "$"
        [regex]$LimitAccessDlls = $LimitAccessDllsString -replace ".","`."
    } Process {
        if ($InputObject) {
            $Files = $InputObject | Where-Object Name -Like *.$FileExtention | Where-Object { -not $_.PSIsContainer }
        } else {
            $Files = Get-ChildItem $Folder"\*."$FileExtention -Recurse  | Where-Object { -not $_.PSIsContainer }
        }

        if ($LimitDangerous) {
            $DangerousFiles | Where-Object { $_.Name -match $LimitAccessExes }
            $Files = $Files |  Where-Object { $_.Name -notmatch $LimitAccessExes }
        }

        $FileInformation = $Files | Get-AppLockerFileInformation # -ErrorAction SilentlyContinue

        if ($LimitDangerous) {
            $DangerousFileInformation = $DangerousFiles | Get-AppLockerFileInformation #-ErrorAction SilentlyContinue
            $DangerousFileInformation | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User $User -Xml | Out-File $PolicyFileName".xml"
        }

        $Publisher = ($FileInformation | Where-Object Publisher -NotLike $null).Publisher.PublisherName
        Write-Verbose $($Publisher | Sort-Object | Get-Unique | Out-String)

        $Path = $FileInformation | Where-Object Publisher -Like $null
        Write-Verbose $($Path | Out-String)

        $FileInformation | New-AppLockerPolicy -RuleType Publisher, Path -Optimize -User $DefaultGroup -Xml | Out-File $PolicyFileName"_BlackList.xml"
    } End { 
        if($ApplyPolicy) {
            Set-AppLockerPolicy -XmlPolicy $PolicyFileName".xml" -Merge
        }
        if ($ApplyPolicy -and $LimitDangerous) {
            Set-AppLockerPolicy -XmlPolicy $PolicyFileName"_BlackList.xml" -Merge
        }
    }
}

################################################################################
################################################################################
Function Invoke-AppLockerDefaultWhiteList {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$Exe,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$Dll,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$Sys,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$Windows,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$ProgramFiles,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$ProgramFilesX86,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$AppData,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string[]]$CustomFolders
    )
    Begin {
        
    } Process {
        if ($Windows) {
            Write-Verbose "Entering $env:windir" 
            $Files = Get-ChildItem -Path $env:windir -Recurse -Include *.exe,*.dll,*.sys
            if ($Exe) {
                Write-Verbose "Adding exe Files"
                Invoke-AppLockerWhiteListWindows -FileExtention exe -InputObject $Files -PolicyFileName "C:\Windows_Exe_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Dll) {
                Write-Verbose "Adding dll Files"
                Invoke-AppLockerWhiteListWindows -FileExtention dll -InputObject $Files -PolicyFileName "C:\Windows_Dll_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Sys) {
                Write-Verbose "Adding sys Files"
                Invoke-AppLockerWhiteListWindows -FileExtention sys -InputObject $Files -PolicyFileName "C:\Windows_Sys_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
        }
        if ($ProgramFiles) {
            Write-Verbose "Entering $env:ProgramFiles" 
            $Files = Get-ChildItem -Path $env:ProgramFiles -Recurse -Include *.exe,*.dll,*.sys
            if ($Exe) {
                Write-Verbose "Adding exe Files"
                Invoke-AppLockerWhiteListWindows -FileExtention exe -InputObject $Files -PolicyFileName "C:\ProgramFiles_Exe_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Dll) {
                Write-Verbose "Adding dll Files"
                Invoke-AppLockerWhiteListWindows -FileExtention dll -InputObject $Files -PolicyFileName "C:\ProgramFiles_Dll_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Sys) {
                Write-Verbose "Adding sys Files"
                Invoke-AppLockerWhiteListWindows -FileExtention sys -InputObject $Files -PolicyFileName "C:\ProgramFiles_Sys_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
        }
        if ($ProgramFilesX86) {
            Write-Verbose "Entering ${env:ProgramFiles(x86)}" 
            $Files = Get-ChildItem -Path ${env:ProgramFiles(x86)} -Recurse -Include *.exe,*.dll,*.sys
            if ($Exe) {
                Write-Verbose "Adding exe Files"
                Invoke-AppLockerWhiteListWindows -FileExtention exe -InputObject $Files -PolicyFileName "C:\ProgramFilesX86_Exe_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Dll) {
                Write-Verbose "Adding dll Files"
                Invoke-AppLockerWhiteListWindows -FileExtention dll -InputObject $Files -PolicyFileName "C:\ProgramFilesX86_Dll_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Sys) {
                Write-Verbose "Adding sys Files"
                Invoke-AppLockerWhiteListWindows -FileExtention sys -InputObject $Files -PolicyFileName "C:\ProgramFilesX86_Sys_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
        }
        if ($AppData) {
            Write-Verbose "Entering $env:USERPROFILE\AppData"
            $Files = Get-ChildItem -Path $env:USERPROFILE\AppData -Recurse -Include *.exe,*.dll,*.sys
            if ($Exe) {
                Write-Verbose "Adding exe Files"
                Invoke-AppLockerWhiteListWindows -FileExtention exe -InputObject $Files -PolicyFileName "C:\AppData_Exe_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Dll) {
                Write-Verbose "Adding dll Files"
                Invoke-AppLockerWhiteListWindows -FileExtention dll -InputObject $Files -PolicyFileName "C:\AppData_Exe_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
            if ($Sys) {
                Write-Verbose "Adding sys Files"
                Invoke-AppLockerWhiteListWindows -FileExtention sys -InputObject $Files -PolicyFileName "C:\AppData_Sys_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
            }
        }
        if ($CustomFolders) {
            $CustomFolders | ForEach-Object {
                Write-Verbose "Entering $CustomFolder"
                $Files = Get-ChildItem -Path $_ -Recurse -Include *.exe,*.dll,*.sys
                if ($Exe) {
                    Write-Verbose "Adding exe Files"
                    Invoke-AppLockerWhiteListWindows -FileExtention exe -InputObject $Files -PolicyFileName "C:\AppData_Exe_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
                }
                if ($Dll) {
                    Write-Verbose "Adding dll Files"
                    Invoke-AppLockerWhiteListWindows -FileExtention dll -InputObject $Files -PolicyFileName "C:\AppData_Exe_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
                }
                if ($Sys) {
                    Write-Verbose "Adding sys Files"
                    Invoke-AppLockerWhiteListWindows -FileExtention sys -InputObject $Files -PolicyFileName "C:\AppData_Sys_AppLocker_Policy" -LimitDangerous -ApplyPolicy -Verbose
                }
            }
        }
    } End {
        
    }
}