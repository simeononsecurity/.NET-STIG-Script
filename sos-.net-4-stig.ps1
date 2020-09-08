#SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
#https://github.com/simeononsecurity
#https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
#https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool

#Require elivation for script run
#Requires -RunAsAdministrator
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification"){
    Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
    Write-Host ".Net StrongName Verification Registry Removed"
}

# .Net 32-Bit
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v2.0.50727){
    Write-Host ".Net 32-Bit v2.0.50727 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v2.0.50727\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v2.0.50727\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v2.0.50727 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v3.0){
    Write-Host ".Net 32-Bit v3.0 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v3.0\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v3.0\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v3.0 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v3.5){
    Write-Host ".Net 32-Bit v3.5 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v3.5\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v3.5\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v3.5 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v4.0.30319){
    Write-Host ".Net 32-Bit v4.0.30319 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v4.0.30319\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v4.0.30319\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
    #Copy-Item -Path .\Files\machine.config -Destination C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config -Force 
}Else {
    Write-Host ".Net 32-Bit v4.0.30319 Is Not Installed"
}


# .Net 64-Bit
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v2.0.50727){
    Write-Host ".Net 64-Bit v2.0.50727 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v2.0.50727\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v2.0.50727\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v2.0.50727 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v3.0){
    Write-Host ".Net 64-Bit v3.0 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v3.0\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v3.0\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v3.0 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v3.5){
    Write-Host ".Net 64-Bit v3.5 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v3.5\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v3.5\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v3.5 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319){
    Write-Host ".Net 64-Bit v4.0.30319 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
    #Copy-Item -Path .\Files\machine.config -Destination C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config -Force 
}Else {
    Write-Host ".Net 64-Bit v4.0.30319 Is Not Installed"
}

FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 






