#SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
#https://github.com/simeononsecurity
#https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
#https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool

#Continue on error
$Global:ErrorActionPreference= 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

#Vul ID: V-7055	   	Rule ID: SV-7438r3_rule	   	STIG ID: APPNET0031
If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification"){
    Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
    Write-Host ".Net StrongName Verification Registry Removed"
}

#Powershell: Script Updates to Machine.config (updatemachineconfig.ps1)
#https://social.technet.microsoft.com/wiki/contents/articles/32048.powershell-script-updates-to-machine-config-updatemachineconfig-ps1.aspx
function CreateExtensionNode ([System.Xml.XmlDocument]$Global:xmlDoc, [string]$Global:name, [string]$Global:type)
{
    [System.Xml.XmlNode]$Global:node = $Global:xmlDoc.CreateElement("add");
    [System.Xml.XmlAttribute]$Global:attrName = $Global:xmlDoc.CreateAttribute("name");
    $Global:attrName.InnerText = $Global:name;
    [System.Xml.XmlAttribute]$Global:attrType = $Global:xmlDoc.CreateAttribute("type");
    $Global:attrType.InnerText = $Global:type;
    [void]$Global:node.Attributes.Append($Global:attrName);
    [void]$Global:node.Attributes.Append($Global:attrType);
    return $Global:node;
}
 
function MergeExtensionNode([string]$Global:extensionNodeName)
{
    [string]$Global:configPath = "/configuration/system.serviceModel/extensions/" + $Global:extensionNodeName;
    [System.Xml.XmlNode]$machineconfigExtnsNode = $machineconfig.SelectSingleNode($Global:configPath);
    [System.Xml.XmlNodeList]$Global:additionconfigExtnsNodes = $Global:additionconfig.SelectNodes($Global:configPath + "/*");
    if (($Global:additionconfigExtnsNodes -ne $Global:null) -and ($machineconfigExtnsNode -ne $Global:null))
    {
        Write-Output "  $Global:extensionNodeName"
        foreach ($Global:additionconfigNode in $Global:additionconfigExtnsNodes)
        {
            [System.Xml.XmlNode]$Global:newNode = CreateExtensionNode $machineconfig $Global:additionconfigNode.name $Global:additionconfigNode.type
            $Global:nodePath = $Global:configPath + "/add[@name='" + $Global:additionconfigNode.name + "']";
            [string]$Global:currNodename = $Global:additionconfigNode.name;
            # Check if node already exists in machine.config:
            $machineconfigCurrentNode = $machineconfig.SelectSingleNode($Global:nodePath);
            if ($machineconfigCurrentNode -ne $Global:null)
            {
                # It did indeed exist, replace it:
                [void]$machineconfigExtnsNode.ReplaceChild($Global:newNode, $machineconfigCurrentNode);
                Write-Output "    $Global:currNodename - replaced"
            }
            else
            {
                # Create it: (AppendChild adds the node last)
                [void]$machineconfigExtnsNode.InsertBefore($Global:newNode, $machineconfigExtnsNode.FirstChild);
                Write-Output "    $Global:currNodename - created"
            }
        }
    }
}
 
#change path to script location
#https://stackoverflow.com/questions/4724290/powershell-run-command-from-scripts-directory
$currentPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path

$Global:netframework32="C:\Windows\Microsoft.NET\Framework"
ForEach ($machineconfig in (Get-ChildItem -Recurse -Path $Global:netframework32 machine.config).FullName){
    $Global:machineconfigFile=$machineconfig
    $Global:additionconfigFile="$currentPath\Files\machine.config"
    if ([System.IO.File]::Exists($Global:machineconfigFile) -and [System.IO.File]::Exists($Global:additionconfigFile))
{
    Write-Output "" "Processing $Global:machineconfigFile with $Global:additionconfigFile";
    [System.Xml.XmlDocument]$machineconfig  = new-object System.Xml.XmlDocument;
    [System.Xml.XmlDocument]$Global:additionconfig = new-object System.Xml.XmlDocument;
    $machineconfig.Load($Global:machineconfigFile);
    $Global:additionconfig.Load($Global:additionconfigFile);
    if (($machineconfig -ne $Global:null) -and ($Global:additionconfig -ne $Global:null))
    {
        MergeExtensionNode "behaviorExtensions";
        MergeExtensionNode "bindingElementExtensions";
        # Overwrite machine.config with resulting document:
        $machineconfig.Save($Global:machineconfigFile);
        Write-Host "Successful Murge"
    }
    else
    {
        Write-Output "Some of the files could not be read, is not XML, or are empty.";
        Exit 3;
    }
}
else
{
    if ([System.IO.File]::Exists($Global:machineconfigFile) -eq $Global:false)
    {
        Write-Output "machineConfigFile does not exist, or is not readable.";
    }
    if ([System.IO.File]::Exists($Global:additionconfigFile -eq $Global:false))
    {
        Write-Output "additionconfigFile does not exist, or is not readable.";
    }
    Exit 3;
}
}
$Global:netframework64="C:\Windows\Microsoft.NET\Framework64"
ForEach ($machineconfig in (Get-ChildItem -Recurse -Path $Global:netframework64 machine.config).FullName){
    $Global:machineconfigFile=$machineconfig
    $Global:additionconfigFile="$currentPath\Files\machine.config"
    if ([System.IO.File]::Exists($Global:machineconfigFile) -and [System.IO.File]::Exists($Global:additionconfigFile))
{
    Write-Output "" "Processing $Global:machineconfigFile with $Global:additionconfigFile";
    [System.Xml.XmlDocument]$machineconfig  = new-object System.Xml.XmlDocument;
    [System.Xml.XmlDocument]$Global:additionconfig = new-object System.Xml.XmlDocument;
    $machineconfig.Load($Global:machineconfigFile);
    $Global:additionconfig.Load($Global:additionconfigFile);
    if (($machineconfig -ne $Global:null) -and ($Global:additionconfig -ne $Global:null))
    {
        MergeExtensionNode "behaviorExtensions";
        MergeExtensionNode "bindingElementExtensions";
        # Overwrite machine.config with resulting document:
        $machineconfig.Save($Global:machineconfigFile);
        Write-Host "Successful Murge"
    }
    else
    {
        Write-Output "Some of the files could not be read, is not XML, or are empty.";
        Exit 3;
    }
}
else
{
    if ([System.IO.File]::Exists($Global:machineconfigFile) -eq $Global:false)
    {
        Write-Output "machineConfigFile does not exist, or is not readable.";
    }
    if ([System.IO.File]::Exists($Global:additionconfigFile -eq $Global:false))
    {
        Write-Output "additionconfigFile does not exist, or is not readable.";
    }
    Exit 3;
}
}

# .Net 32-Bit
If (Test-Path -Path $Global:netframework32\v2.0.50727){
    Write-Host ".Net 32-Bit v2.0.50727 Is Installed"
    .\$Global:netframework32\v2.0.50727\caspol.exe -q -f -pp on 
    .\$Global:netframework32\v2.0.50727\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v2.0.50727 Is Not Installed"
}
If (Test-Path -Path $Global:netframework32\v3.0){
    Write-Host ".Net 32-Bit v3.0 Is Installed"
    .\$Global:netframework32\v3.0\caspol.exe -q -f -pp on 
    .\$Global:netframework32\v3.0\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v3.0 Is Not Installed"
}
If (Test-Path -Path $Global:netframework32\v3.5){
    Write-Host ".Net 32-Bit v3.5 Is Installed"
    .\$Global:netframework32\v3.5\caspol.exe -q -f -pp on 
    .\$Global:netframework32\v3.5\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v3.5 Is Not Installed"
}
If (Test-Path -Path $Global:netframework32\v4.0.30319){
    Write-Host ".Net 32-Bit v4.0.30319 Is Installed"
    .\$Global:netframework32\v4.0.30319\caspol.exe -q -f -pp on 
    .\$Global:netframework32\v4.0.30319\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
    #Copy-Item -Path .\Files\machine.config -Destination .\$Global:netframework32\v4.0.30319\Config -Force 
}Else {
    Write-Host ".Net 32-Bit v4.0.30319 Is Not Installed"
}


# .Net 64-Bit
If (Test-Path -Path $Global:netframework64\v2.0.50727){
    Write-Host ".Net 64-Bit v2.0.50727 Is Installed"
    .\$Global:netframework64\v2.0.50727\caspol.exe -q -f -pp on 
    .\$Global:netframework64\v2.0.50727\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v2.0.50727 Is Not Installed"
}
If (Test-Path -Path $Global:netframework64\v3.0){
    Write-Host ".Net 64-Bit v3.0 Is Installed"
    .\$Global:netframework64\v3.0\caspol.exe -q -f -pp on 
    .\$Global:netframework64\v3.0\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v3.0 Is Not Installed"
}
If (Test-Path -Path $Global:netframework64\v3.5){
    Write-Host ".Net 64-Bit v3.5 Is Installed"
    .\$Global:netframework64\v3.5\caspol.exe -q -f -pp on 
    .\$Global:netframework64\v4.0.30319\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v3.5 Is Not Installed"
}
If (Test-Path -Path $Global:netframework64\v4.0.30319){
    Write-Host ".Net 64-Bit v4.0.30319 Is Installed"
    .\$Global:netframework64\v4.0.30319\caspol.exe -q -f -pp on 
    .\$Global:netframework64\v4.0.30319\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063	  
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
    #Copy-Item -Path .\Files\machine.config -Destination .\$Global:netframework64\v4.0.30319\Config -Force 
}Else {
    Write-Host ".Net 64-Bit v4.0.30319 Is Not Installed"
}

#Vul ID: V-30937	   	Rule ID: SV-40979r3_rule	   	STIG ID: APPNET0064	  
#FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 







