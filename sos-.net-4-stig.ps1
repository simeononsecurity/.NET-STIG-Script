<#
.Author
    SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
    https://github.com/simeononsecurity
    https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
    https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool
 
.Contributor
    Leatherman - Leatherman-Security
    https://github.com/Leatherman-Security
    
.Synopsis
   Configures .NET DoD STIG Requirements
.DESCRIPTION
   Configures .NET DoD STIG Requirements
    .\sos-.net-4-stig.ps1
#>

<#
This script requires admin privs. Use -RunAsAdministrator
.net check on privs. If script does not have, it returns a message and exits.
#>
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (!($CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Output "Script not executed with admin privs.  This is needed to properly run. `n Restart with admin privs"
    Start-Sleep 15
    exit
}

#Continue on error
$ErrorActionPreference = 'SilentlyContinue'

<#
change path to script location
https://stackoverflow.com/questions/4724290/powershell-run-command-from-scripts-directory
$currentPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
https://riptutorial.com/powershell/example/27231/-psscriptroot
$PSScriptRoot is easier usage 
#>
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

#Setting Netframework path variables
$NetFramework32 = "C:\Windows\Microsoft.NET\Framework"
$NetFramework64 = "C:\Windows\Microsoft.NET\Framework64"

#Vul ID: V-7055	   	Rule ID: SV-7438r3_rule	   	STIG ID: APPNET0031
#Removing registry value
If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification") {
    Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
    Write-Output ".Net StrongName Verification Registry Removed"
}

<#
Creating secure configuration Function. It needs to be called in the
two foreach loops as it has to touch every config file in each
.net framework version folder
#>
Function Set-SecureConfig {
    param (
        $VersionPath,
        $SecureMachineConfigPath
    )
    
    #Declaration and error prevention
    $SecureMachineConfig = $Null
    $MachineConfig = $Null
    [system.gc]::Collect() 
    
    #Getting Secure Machine.Configs
    $SecureMachineConfig = [xml](Get-Content $SecureMachineConfigPath)
        
    #Write-Host "Still using test path at $(Get-CurrentLine)"
    #$MachineConfigPath = "C:\Users\hiden\Desktop\NET-STIG-Script-master\Files\secure.machine - Copy.config"
    $MachineConfigPath = "$VersionPath"
    $MachineConfig = [xml](Get-Content $MachineConfigPath)
    #Ensureing file is closed
    [IO.File]::OpenWrite((Resolve-Path $MachineConfigPath).Path).close()

    <#Apply Machine.conf Configurations
    #Pulled XML assistance from https://stackoverflow.com/questions/9944885/powershell-xml-importnode-from-different-file
    #Pulled more XML details from http://www.maxtblog.com/2012/11/add-from-one-xml-data-to-another-existing-xml-file/
    #>
    Write-Host "Begining work on $MachineConfigPath..." -ForegroundColor White -BackgroundColor Black
   
    # Do out. Automate each individual childnode for infinite nested. Currently only goes two deep
    $SecureChildNodes = $SecureMachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name
    $MachineChildNodes = $MachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name


    #Checking if each secure node is present in the XML file
    ForEach ($SecureChildNode in $SecureChildNodes) {
        #If it is not present, easy day. Add it in.
        If ($SecureChildNode -notin $MachineChildNodes) {
            #Adding node from the secure.machine.config file and appending it to the XML file
            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
            $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
            #Saving changes to XML file
            $MachineConfig.Save($MachineConfigPath)
        }
        Elseif ($MachineConfig.configuration.$SecureChildNode -eq "") {
            #Turns out element sometimes is present but entirely empty. If that is the case we need to remove it
            # and add what we want         
            $MachineConfig.configuration.ChildNodes | Where-Object name -eq $SecureChildNode | ForEach-Object { $MachineConfig.configuration.RemoveChild($_) } | Out-Null
            $MachineConfig.Save($MachineConfigPath)
            #Adding node from the secure.machine.config file and appending it to the XML file            
            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
            $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
            #Saving changes to XML file
            $MachineConfig.Save($MachineConfigPath)
        }
        Else {
            
            #If it is present... we have to check if the node contains the elements we want.
            #Going through each node in secure.machine.config for comparison
            $SecureElements = $SecureMachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name        
            #Pull the Machine.config node and childnode and get the data properties for comparison
            $MachineElements = $MachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name

            #I feel like there has got to be a better way to do this as we're three loops deep
            foreach ($SElement in $SecureElements) {
                #Comparing Element pulled earlier against Machine Elements.  If it's not present we will add it in
                If ($SElement -notin $MachineElements) {
                    #Adding in element that is not present
                    If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -NE "") {
                        $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                        #Saving changes to XML file
                        $MachineConfig.Save($MachineConfigPath)
                    }
                    Else {
                        #This is for when the value declared is empty.
                        $NewNode = $MachineConfig.CreateElement("$SElement")                     
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                        #Saving changes to XML file
                        $MachineConfig.Save($MachineConfigPath)
                    }
                }
                Else {
                    $OldNode = $MachineConfig.SelectSingleNode("//$SElement")
                    $MachineConfig.configuration.$SecureChildNode.RemoveChild($OldNode) | Out-Null
                    $MachineConfig.Save($MachineConfigPath)
                    If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -EQ "") {
                        $NewElement = $MachineConfig.CreateElement("$SElement")
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewElement) | Out-Null
                    }
                    Else {
                        $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                        $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                    }
                
                #Saving changes to XML file
                $MachineConfig.Save($MachineConfigPath)               
                }#End else
            }#Foreach Element within SecureElements
        }#Else end for an if statement checking if the desired childnode is in the parent file
    }#End of iterating through SecureChildNodes
   
    Write-Host "Merge Complete" -ForegroundColor White -BackgroundColor Black
}


# .Net 32-Bit
ForEach ($DotNetVersion in (Get-ChildItem $netframework32 -Directory)) {
    Write-Host ".Net 32-Bit $DotNetVersion Is Installed" -ForegroundColor Green -BackgroundColor Black
    #Starting .net exe/API to pass configuration Arguments
    If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
        # Comment lines above and uncomment lines below to see output
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
        Write-Host "Set CAS policy for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\SchUseStrongCrypto") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "$DotNetVersion" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White -BackgroundColor Black
    }

    <# Source for specifying configs for specific .Net versions
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)
    #>
    
    #Ensuring .net version has machine.config
    If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config"){
        #.net Version testing.
        If (($DotNetVersion -Split "v" )[1] -ge 2) {
            #.net version testing.
            If (($DotNetVersion -Split "v" )[1] -ge 4) {
                Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath ".\Files\secure.machine-v4.config"
            }
            Else {
                Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath ".\Files\secure.machine-v2.config"
            }
        }
        Else {
            Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow -BackgroundColor Black
        }#End dotnet version test
    }#End testpath
}

# .Net 64-Bit
ForEach ($DotNetVersion in (Get-ChildItem $netframework64 -Directory)) {  
    Write-Host ".Net 64-Bit $DotNetVersion Is Installed" -ForegroundColor Green -BackgroundColor Black
    #Starting .net exe/API to pass configuration Arguments
    If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
        Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
        # Comment lines above and uncomment lines below to see output
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
        #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
        Write-Host "Set CAS policy for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
        Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\" -Name "$DotNetVersion" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
        Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White -BackgroundColor Black
    }

    <# Source for specifying configs for specific .Net versions
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
    https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)
    #>
    
    #Ensuring current version has a machine.config to use
    If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config"){
        #version testing
        If (($DotNetVersion -Split "v" )[1] -ge 2) {
            #More version testing.
            If (($DotNetVersion -Split "v" )[1] -ge 4) {
                Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath ".\Files\secure.machine-v4.config"
            }
            Else {
                Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White -BackgroundColor Black
                Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath ".\Files\secure.machine-v2.config"
            }
        }
        Else {
            Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow -BackgroundColor Black
        }#End .net version test
    }#End testpath
}

#Vul ID: V-30937	   	Rule ID: SV-40979r3_rule	   	STIG ID: APPNET0064	  
#FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 
