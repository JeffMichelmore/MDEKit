@{
    # Module manifest file format version
    ModuleVersion = '1.0'

    # Module name (used for module autoloading)
    ModuleName = 'MDE Kit'

    # Author information
    Author = 'Jeffrey Michelmore'

    # Module description
    Description = "MDE Kit's objective is to help automate and empower your investigation, detection, prevention, and response capabilities leveraging the MDE API. MDE Kit leverages many of the available Microsoft Defender for Endpoint (MDE) APIs to take response actions on machines as well as create reports related to TVM data, alert data, antivirus data, and machine data."

    # Exported functions
    FunctionsToExport = @('Get-MdeKitHelp', 'Get-SecureConfigAssessment', 'Get-SoftwareInventoryAssessment', 'Get-NonCpeSoftwareInventoryAssessment', 'Get-SoftwareVulnerabilitiesAssessment', 'Get-Machines', 'Get-Alerts', 'Get-AvInfo', 'Get-Recommendations', 'Get-Vulnerabilities', 'Show-MachineActionsMenu')

    # Module GUID 
    GUID = '31f02ba1-264f-4c27-9c6c-df7df2fd6c37'

    # Module version-specific information
    HelpInfoURI = 'https://github.com/JeffMichelmore/MDEKit/blob/main/README.md'

    # Specify the root module (main .psm1 file)
    RootModule = 'MDEKit.psm1'
}