#SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
#https://github.com/simeononsecurity
#https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
#https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool

#Continue on error
$ErrorActionPreference= 'silentlycontinue'

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
function CreateExtensionNode ([System.Xml.XmlDocument]$xmlDoc, [string]$name, [string]$type)
{
    [System.Xml.XmlNode]$node = $xmlDoc.CreateElement("add");
    [System.Xml.XmlAttribute]$attrName = $xmlDoc.CreateAttribute("name");
    $attrName.InnerText = $name;
    [System.Xml.XmlAttribute]$attrType = $xmlDoc.CreateAttribute("type");
    $attrType.InnerText = $type;
    [void]$node.Attributes.Append($attrName);
    [void]$node.Attributes.Append($attrType);
    return $node;
}
 
function MergeExtensionNode([string]$extensionNodeName)
{
    [string]$configPath = "/configuration/system.serviceModel/extensions/" + $extensionNodeName;
    [System.Xml.XmlNode]$machineconfigExtnsNode = $machineconfig.SelectSingleNode($configPath);
    [System.Xml.XmlNodeList]$additionconfigExtnsNodes = $additionconfig.SelectNodes($configPath + "/*");
    if (($additionconfigExtnsNodes -ne $null) -and ($machineconfigExtnsNode -ne $null))
    {
        Write-Output "  $extensionNodeName"
        foreach ($additionconfigNode in $additionconfigExtnsNodes)
        {
            [System.Xml.XmlNode]$newNode = CreateExtensionNode $machineconfig $additionconfigNode.name $additionconfigNode.type
            $nodePath = $configPath + "/add[@name='" + $additionconfigNode.name + "']";
            [string]$currNodename = $additionconfigNode.name;
            # Check if node already exists in machine.config:
            $machineconfigCurrentNode = $machineconfig.SelectSingleNode($nodePath);
            if ($machineconfigCurrentNode -ne $null)
            {
                # It did indeed exist, replace it:
                [void]$machineconfigExtnsNode.ReplaceChild($newNode, $machineconfigCurrentNode);
                Write-Output "    $currNodename - replaced"
            }
            else
            {
                # Create it: (AppendChild adds the node last)
                [void]$machineconfigExtnsNode.InsertBefore($newNode, $machineconfigExtnsNode.FirstChild);
                Write-Output "    $currNodename - created"
            }
        }
    }
}
 
#change path to script location
#https://stackoverflow.com/questions/4724290/powershell-run-command-from-scripts-directory
$currentPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path

$netframework32="C:\Windows\Microsoft.NET\Framework"
ForEach ($machineconfig in (Get-ChildItem -Recurse -Path $netframework32 machine.config).FullName){
    $machineconfigFile=$machineconfig
    $additionconfigFile="$currentPath\Files\machine.config"
    if ([System.IO.File]::Exists($machineconfigFile) -and [System.IO.File]::Exists($additionconfigFile))
{
    Write-Output "" "Processing $machineconfigFile with $additionconfigFile";
    [System.Xml.XmlDocument]$machineconfig  = new-object System.Xml.XmlDocument;
    [System.Xml.XmlDocument]$additionconfig = new-object System.Xml.XmlDocument;
    $machineconfig.Load($machineconfigFile);
    $additionconfig.Load($additionconfigFile);
    if (($machineconfig -ne $null) -and ($additionconfig -ne $null))
    {
        MergeExtensionNode "behaviorExtensions";
        MergeExtensionNode "bindingElementExtensions";
        # Overwrite machine.config with resulting document:
        $machineconfig.Save($machineconfigFile);
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
    if ([System.IO.File]::Exists($machineconfigFile) -eq $false)
    {
        Write-Output "machineConfigFile does not exist, or is not readable.";
    }
    if ([System.IO.File]::Exists($additionconfigFile -eq $false))
    {
        Write-Output "additionconfigFile does not exist, or is not readable.";
    }
    Exit 3;
}
}
$netframework64="C:\Windows\Microsoft.NET\Framework64"
ForEach ($machineconfig in (Get-ChildItem -Recurse -Path $netframework64 machine.config).FullName){
    $machineconfigFile=$machineconfig
    $additionconfigFile="$currentPath\Files\machine.config"
    if ([System.IO.File]::Exists($machineconfigFile) -and [System.IO.File]::Exists($additionconfigFile))
{
    Write-Output "" "Processing $machineconfigFile with $additionconfigFile";
    [System.Xml.XmlDocument]$machineconfig  = new-object System.Xml.XmlDocument;
    [System.Xml.XmlDocument]$additionconfig = new-object System.Xml.XmlDocument;
    $machineconfig.Load($machineconfigFile);
    $additionconfig.Load($additionconfigFile);
    if (($machineconfig -ne $null) -and ($additionconfig -ne $null))
    {
        MergeExtensionNode "behaviorExtensions";
        MergeExtensionNode "bindingElementExtensions";
        # Overwrite machine.config with resulting document:
        $machineconfig.Save($machineconfigFile);
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
    if ([System.IO.File]::Exists($machineconfigFile) -eq $false)
    {
        Write-Output "machineConfigFile does not exist, or is not readable.";
    }
    if ([System.IO.File]::Exists($additionconfigFile -eq $false))
    {
        Write-Output "additionconfigFile does not exist, or is not readable.";
    }
    Exit 3;
}
}

# .Net 32-Bit
ForEach ($dotnet32version in (Get-ChildItem $netframework32 | ?{ $_.PSIsContainer }).Name){
    Write-Host ".Net 32-Bit $dotnet32version Is Installed"
    .\$netframework32\$dotnet32version\caspol.exe -q -f -pp on 
    .\$netframework32\$dotnet32version\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$dotnet32version\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$dotnet32version\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$dotnet32version\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}
ForEach ($dotnet64version in (Get-ChildItem $netframework64 | ?{ $_.PSIsContainer }).Name){
    Write-Host ".Net 64-Bit $dotnet64version Is Installed"
    .\$netframework64\$dotnet64version\caspol.exe -q -f -pp on 
    .\$netframework64\$dotnet64version\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$dotnet64version\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$dotnet64version\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$dotnet64version\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}

#Vul ID: V-30937	   	Rule ID: SV-40979r3_rule	   	STIG ID: APPNET0064	  
#FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 







