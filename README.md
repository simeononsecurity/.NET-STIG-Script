# Automate the .NET Framework STIG

Applying the .NET STIG is definitely not straightforward. For many administrators it can take hours to fully implement on a single system. This script applies the required registry changes and modifies the machine.config file to implement FIPS and other controls as required.

**Work in Progress**

**DO NOT APPLY IN PRODUCTION**

## Notes:

This script can not and will not ever get the .NET stig to 100% compliance. 

Manual intervention is required for any .NET application or IIS Site.

## STIGS/SRGs Applied:

- [Microsoft .Net Framework 4 V1R9](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip)

## Sources:

- [Add from one XML data to another existing XML file](http://www.maxtblog.com/2012/11/add-from-one-xml-data-to-another-existing-xml-file/)
- [Caspol.exe (Code Access Security Policy Tool)](https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool)
- [Microsoft .NET Framework Documentation](https://docs.microsoft.com/en-us/dotnet/framework/)
- [PowerShell $PSScriptRoot](https://riptutorial.com/powershell/example/27231/-psscriptroot)
- [PowerShell: Run command from script's directory](https://stackoverflow.com/questions/4724290/powershell-run-command-from-scripts-directory)
- [Powershell XML importnode from different file](https://stackoverflow.com/questions/9944885/powershell-xml-importnode-from-different-file)

## Download the required files

You may download the required files from the [GitHub Repository](https://raw.githubusercontent.com/simeononsecurity/.NET-STIG-Script/)

## How to run the script

**The script may be lauched from the extracted GitHub download like this:**

```
.\sos-.net-4-stig.ps1
```
