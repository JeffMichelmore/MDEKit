# MDE Kit
<!-- TOC -->
## Objectives

MDE Kit's objective is to help automate and empower your investigation, detection, prevention, and response capabilities leveraging the MDE API.
MDE Kit leverages many of the available Microsoft Defender for Endpoint (MDE) APIs to take response actions on machines as well as create reports related to TVM data, alert data, antivirus data, and machine data. More details about each function can be found below.
Learn more about this project at my personal blog: [MDEKit PowerShell Module](https://securityoccupied.com/2023/07/11/mde-kit-a-powershell-module-for-microsoft-defender-for-endpoint)

## Contributing

If you wish to contribute to this project, first of all, thank you. MDEKit is simply a .psm1 containing all functions so contributing should be very straightforward. Please ensure to start by creating a fork of the repository, create a new branch, and ensure to test your changes locally before committing. Please ensure to update $ExportedFunctions to include your function and provide some description of your function as needed so it may be available to the Get-Help cmdlet.

## Setting Up
In order to begin using the MDEKit, you will need to follow the instructions found here: [Create an app to access Microsoft Defender for Endpoint without a user](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/exposed-apis-create-app-webapp?view=o365-worldwide) and add your tenant ID, application ID, and application secret into the corresponding variables of the Set-AccessToken function within the MDEKit.psm1. If you wish to handle authentication a different way, you are welcome to do that too! :~)

## Get-MdeKitHelp

This function will provide a brief description of MDEKit as well as a list of available functions. To learn more about each function, simply enter "Get-Help (function name)".

## Get-SecureConfigAssessment

Get-SecureConfigAssessment leverages the [Export secure configuration assessment per device](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-assessment-secure-config?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all security configuration assessment data per device. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return configuration data where the impact level is 9 or 10, you can enter "Get-SecureConfigAssessment -ConfigurationImpact 9,10". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-SoftwareInventoryAssessment

Get-SoftwareInventoryAssessment leverages the [Export software inventory assessment per device](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-assessment-software-inventory?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all software inventory assessment data per device. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return software inventory data where the software vendor is Microsoft, you can enter "Get-SoftwareInventoryAssessment -SoftwareVendor 'Microsoft'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-NonCpeSoftwareInventoryAssessment

Get-NonCpeSoftwareInventoryAssessment leverages the [Export non product code software inventory assessment per device](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-assessment-non-cpe-software-inventory?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all of the non-CPE software inventory data per device. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return non-CPE software inventory data where the vendor is Microsoft and the OS platform is Windows 11, you can enter "Get-NonCpeSoftwareInventoryAssessment -SoftwareVendor 'Microsoft' -OsPlatform 'Windows11'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-SoftwareVulnerabilitiesAssessment

Get-SoftwareVulnerabilitiesAssessment leverages the [Export software vulnerabilities assessment per device](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-assessment-software-vulnerabilities?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all of the software vulnerability assessment data. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return software vulnerabilities where the severity level is high and where exploitability level is exploit verified, you can enter "Get-SoftwareVulnerabilitiesAssessment -VulnerabilitySeverityLevel 'high' -ExploitabilityLevel 'ExploitIsVerified'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-Machines

Get-Machines leverages the [List Machines](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-machines?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all of the machine data. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return machines in the Domain Controllers device group, you can enter "Get-Machines -RbacGroupName 'Domain Controllers'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-Alerts

Get-Alerts leverages the [List Alerts](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-alerts?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all of the alert data. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return alerts related to a user named Darth Vader, you can enter "Get-Alerts -RelatedUser 'Darth Vader'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-AvInfo

Get-AvInfo leverages the [Export device antivirus health report](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/device-health-export-antivirus-health-report-api?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all of the AV data. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return AV info where the platform version is unknown or not up to date, you can enter "Get-AvInfo -AvIsPlatformUpToDate 'False','Unknown'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-Recommendations

Get-Recommendations leverages the [List All Recommendations](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-all-recommendations?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all of the TVM recommendation data. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return recommendations with a severity score of 10 and a remediation type of "uninstall", you can enter "Get-Recommendations -SeverityScore 10 -RemediationType 'Uninstall'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Get-Vulnerabilities

Get-Vulnerabilities leverages the [List All Vulnerabilities](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-all-vulnerabilities?view=o365-worldwide) API. Like all of the other "Get" functions in this module, you can run this without any parameters to get all of the TVM vulnerabilities data. Or you can specify any of the parameters found in the Properties table of the above documentation. For example, if you wish to only return vulnerabilities for a specific CVE, you can enter "Get-Vulnerabilities -id 'CVE-2023-20955'". Additionally, you can use the -Path or -P parameter to send output to a CSV file locally. You can also specify the -Quiet or -Q parameter if you wish to omit output to the PowerShell console.

## Show-MachineActionsMenu

Show-MachineActionsMenu leverages many of the response action APIs made available by MDE. These actions include:
- Collect investigation packages
- Isolate or unisolate machines
- Run live response
- Restrict or unrestrict applications
- Run antivirus scans
- Offboard machines
- Stop and quarantine files
- Cancel pending machine action

  Essentially this function is one which I previously wrote and blogged about and have reused in this module. To learn the ins and outs of this function, you can read that blog here: [Taking Actions on MDE Devices with PowerShell](https://securityoccupied.com/2023/06/15/taking-actions-on-mde-devices-via-powershell-and-mde-api/)

