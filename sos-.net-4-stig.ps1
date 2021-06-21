<#
THIS TEMPLATE IS DERIVED FROM POWERSHELL ISE
    ctrl + J > cmdlet(advanced)
    This is normal powershell commenting for ease of understanding between powershell/.net users
Additionally. If using powershell, please follow Verb-Noun nomenclature.  Real pain at first, but the more
you use powershell, the more you will expect it and it quickly becomes a massive time saver. Put author info
in header comments
.Author
    SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
    https://github.com/simeononsecurity
    https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
    https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool
    
    Contributor
        Leatherman
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>

<#
Require elivation for script run
Requires -RunAsAdministrator
This script needs admin privs
The following checks .net to see if script has admin privs.  If it does not, it returns a msg on it and exits script
#>
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (!($CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Output "Script not executed with admin privs.  This is needed to properly run. `n Restart with admin privs"
    sleep 15
    exit
}

#Gets current line script is on for troubleshooting purposes
Function Get-CurrentLine {
    $MyInvocation.ScriptLineNumber
}

#Continue on error
$ErrorActionPreference = 'silentlycontinue'

<#
change path to script location
https://stackoverflow.com/questions/4724290/powershell-run-command-from-scripts-directory
$currentPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
Easier usage
https://riptutorial.com/powershell/example/27231/-psscriptroot
#>
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

#Setting Netframework path variables
$NetFramework32 = "C:\Windows\Microsoft.NET\Framework"
$NetFramework64 = "C:\Windows\Microsoft.NET\Framework64"
$NetFrameworks = @("$netframework32", "$netframework64")

#Vul ID: V-7055	   	Rule ID: SV-7438r3_rule	   	STIG ID: APPNET0031
#Removing registry value
If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification") {
    Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
    Write-Output ".Net StrongName Verification Registry Removed"
}

#Getting Secure Machine.Configs
$SecureMachineConfigPath = ".\Files\secure.machine.config"
$SecureMachineConfig = [xml](Get-Content $SecureMachineConfigPath)

<#
Creating secure configuration Function. It needs to be called in the
two foreach loops as it has to touch every config file in each
.net framework version folder
#>
Function Set-SecureConfig {
    param (
        $VersionPath
    )
    <#
    #If you want to test this, create a test file and use below
    #$MachineConfigPath = ".\Files\sample.config"
    #Write-Output "Still using SAMPLE.config. Adjust comments at line $(Get-CurrentLine)"
    #Actual machine
    #$MachineConfigPath = "$VersionPath"
    #Sample/testing purposes line
    #>
    $MachineConfigPath = "$($DotNetVersion.FullName)\Config\Machine.config"
    $MachineConfig = [xml](Get-Content $MachineConfigPath)
    
    <#Apply Machine.conf Configurations
    #Pulled XML assistance from https://stackoverflow.com/questions/9944885/powershell-xml-importnode-from-different-file
    #Pulled more XML details from http://www.maxtblog.com/2012/11/add-from-one-xml-data-to-another-existing-xml-file/
    #>
    Write-Output "Begining work on $MachineConfigPath"
   
   <#
   #Pulling Secure.Machine.Config RUNTIME childnode and looking through its content and pulling the comment for comparison.
   # Do out. Automate each individual childnode for infinite nested. Currently only goes one deep
   #>
   $SecureChildNodes = $SecureMachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name
   $MachineChildNodes = $MachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name

   #Checking if each secure node is present in the XML file
   ForEach($SecureChildNode in $SecureChildNodes){
       #If it is not present, easy day. Add it in.
       If ($SecureChildNode -notin $MachineChildNodes){
            #Adding node from the secure.machine.config file and appending it to the XML file            
            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
            $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
            #Saving changes to XML file
            $MachineConfig.Save($MachineConfigPath)
        #If it is present... we have to check if the node contains the elements we want.
        } Else {
            #Going through each node in secure.machine.config for comparison
            $SecureElements = $SecureMachineConfig.configuration.$SecureChildNode | Get-Member | Where MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select -Expandproperty Name
            #Pull the Machine.config node and childnode and get the data properties for comparison
            $MachineElements = $MachineConfig.configuration.$SecureChildNode | Get-Member | Where MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select -Expandproperty Name

            #I feel like there has got to be a better way to do this as we're three loops deep
            foreach($SElement in $SecureElements){
                #Comparing VulID pulled earlier against comments/data properties.  If it's not present we will add it in
                If ($SElement -notin $MachineElements){
                    #Can this line be used to add an element somewhere
                    $NewNode = $MachineConfig.ImportNode(($SecureMachineConfig.configuration.$SecureChildNode.$SElement), $true)
                    $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                    #Saving changes to XML file
                    $MachineConfig.Save($MachineConfigPath)
                } Else {
                  $OldNode = $MachineConfig.SelectSingleNode("//$SElement")
                  $MachineConfig.configuration.$SecureChildNode.RemoveChild($OldNode) | Out-Null
                  $NewNode = $MachineConfig.ImportNode(($SecureMachineConfig.configuration.$SecureChildNode.$SElement), $true)
                  $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                  #Saving changes to XML file
                  $MachineConfig.Save($MachineConfigPath)
                }#End else
            }#Foreach Element within SecureElements
        }#Else end for an if statement checking if the desired childnode is in the parent file
   }#End of iterating through SecureChildNodes
   Write-Output "Merge Complete"
}


# .Net 32-Bit
ForEach ($DotNetVersion in (Get-ChildItem $netframework32 -Directory)) {
    Write-Output ".Net 32-Bit $DotNetVersion Is Installed"
    #Starting .net exe/API to pass configuration Arguments
    Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
    Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\SchUseStrongCrypto") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "$DotNetVersion" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
    }

    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config"
}

# .Net 64-Bit
ForEach ($DotNetVersion in (Get-ChildItem $netframework64 -Directory)) {  
    Write-Host ".Net 64-Bit $DotNetVersion Is Installed"
    #Starting .net exe/API to pass configuration Arguments
    Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
    Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
    }
    Else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\" -Name "$DotNetVersion" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
    }

    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config"
}

#Vul ID: V-30937	   	Rule ID: SV-40979r3_rule	   	STIG ID: APPNET0064	  
#FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 
