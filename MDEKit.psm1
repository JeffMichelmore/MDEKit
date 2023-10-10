<#
# PLEASE NOTE THAT I TAKE NO RESPONSIBILITY FOR THE RESULTS THIS SCRIPT MIGHT YIELD
# PLEASE USE AT YOUR DESCRETION, TEST, AND ENSURE IT FITS YOUR NEEDS

# Author: Jeff Michelmore
# Connect: https://www.linkedin.com/in/jeffrey-michelmore/
# Blog: https://securityoccupied.com/
#>

function Set-AccessToken {

    [String] $tenantId = '' ### Paste your tenant ID between the single quotes
    [string] $appId = '' ### Paste your Application ID between the single quotes
    [string] $appSecret = '' ### Paste your Application key between the single quotes

    # Creating token for MDE API
    $resourceAppIdUri = 'https://api.securitycenter.microsoft.com' 
    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $authBody = [Ordered] @{
        resource = "$resourceAppIdUri"
        client_id = "$appId"
        client_secret = "$appSecret"
        grant_type = 'client_credentials'
    }
    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    $script:token = $authResponse.access_token
}

function Get-SecureConfigAssessment {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-assessment-secure-config
    This Get-SecureConfigAssessment function allows for returning all security configurations and their statuses per-device in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property(ID)" column in the above documentation and can accept multiple values for each parameter.
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-SecureConfigAssessment -IsCompliant $False -ConfigurationImpact 8,9,10 -Path "C:\HighImpactConfigAssessment.csv" -Q
This example will return all security config assessments where the device is not compliant and the impact is an 8, 9, or 10..
It will return these results into a CSV named "C:\HighImpactConfigAssessment.csv" and it will not output the results to the console.
    
    #>

    [CmdletBinding()]
    param (
        [string[]]$ConfigurationCategory,
        [string[]]$ConfigurationId,
        [string[]]$ConfigurationImpact,
        [string[]]$ConfigurationName,
        [string[]]$ConfigurationSubcategory,
        [string[]]$DeviceId,
        [string[]]$DeviceName,
        [bool]$IsApplicable,
        [bool]$IsCompliant,
        [bool]$IsExpectedUserImpact,
        [string[]]$OSPlatform,
        [string[]]$RbacGroupName,
        [string[]]$RecommendationReference,
        [string[]]$Timestamp,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )

    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/machines/SecureConfigurationsAssessmentByMachine"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    if ($ConfigurationCategory) {
        $FilteredContent = $FilteredContent | Where-Object { $ConfigurationCategory -contains $_.ConfigurationCategory }
    }

    if ($ConfigurationId) {
        $FilteredContent = $FilteredContent | Where-Object { $ConfigurationId -contains $_.ConfigurationId }
    }

    if ($ConfigurationImpact) {
        $FilteredContent = $FilteredContent | Where-Object { $ConfigurationImpact -contains $_.ConfigurationImpact }
    }

    if ($ConfigurationName) {
        $FilteredContent = $FilteredContent | Where-Object { $ConfigurationName -contains $_.ConfigurationName }
    }

    if ($ConfigurationSubcategory) {
        $FilteredContent = $FilteredContent | Where-Object { $ConfigurationSubcategory -contains $_.ConfigurationSubcategory }
    }

    if ($DeviceId) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceId -contains $_.DeviceId }
    }

    if ($DeviceName) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceName -contains $_.DeviceName }
    }

    if ($IsApplicable) {
        $FilteredContent = $FilteredContent | Where-Object { $IsApplicable -eq $_.IsApplicable }
    }

    if ($IsCompliant) {
        $FilteredContent = $FilteredContent | Where-Object { $IsCompliant -eq $_.IsCompliant }
    }

    if ($IsExpectedUserImpact) {
        $FilteredContent = $FilteredContent | Where-Object { $IsExpectedUserImpact -eq $_.IsExpectedUserImpact }
    }

    if ($OSPlatform) {
        $FilteredContent = $FilteredContent | Where-Object { $OSPlatform -contains $_.OSPlatform }
    }

    if ($RbacGroupName) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupName -contains $_.RbacGroupName }
    }

    if ($RecommendationReference) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendationReference -contains $_.RecommendationReference }
    }

    if ($Timestamp) {
        $FilteredContent = $FilteredContent | Where-Object { $Timestamp -contains $_.Timestamp }
    }

    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent
}

function Get-SoftwareInventoryAssessment {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-assessment-software-inventory
    This Get-SoftwareInventoryAssessment function allows for returning all installed software that hs a Common Platform Enumeration (CPE) and their statuses per-device in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property(ID)" column in the above documentation and can accept multiple values for each parameter.
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-SoftwareInventoryAssessment -SoftwareVendor "Microsoft" -OsPlatform "Windows10","Windows11" -Path "C:\SoftwareInventoryAssessment.csv" -Q
This example will return all Microsoft software with known CPE on Windows 10 and Windows 11 device.
It will return these results into a CSV named "C:\SoftwareInventoryAssessment.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$DeviceId,
        [string[]]$DeviceName,
        [string[]]$DiskPaths,
        [string[]]$EndOfSupportDate,
        [string[]]$EndOfSupportStatus,
        [int[]]$NumberOfWeaknesses,
        [string[]]$OSPlatform,
        [string[]]$RbacGroupName,
        [string[]]$RegistryPaths,
        [string[]]$SoftwareFirstSeenTimestamp,
        [string[]]$SoftwareName,
        [string[]]$SoftwareVendor,
        [string[]]$SoftwareVersion,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )

    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/machines/SoftwareInventoryByMachine"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    if ($DeviceId) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceId -contains $_.DeviceId }
    }

    if ($DeviceName) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceName -contains $_.DeviceName }
    }

    if ($DiskPaths) {
        $FilteredContent = $FilteredContent | Where-Object { $DiskPaths -contains $_.DiskPaths }
    }

    if ($EndOfSupportDate) {
        $FilteredContent = $FilteredContent | Where-Object { $EndOfSupportDate -eq $_.EndOfSupportDate }
    }

    if ($EndOfSupportStatus) {
        $FilteredContent = $FilteredContent | Where-Object { $EndOfSupportStatus -eq $_.EndOfSupportStatus }
    }

    if ($NumberOfWeaknesses) {
        $FilteredContent = $FilteredContent | Where-Object { $NumberOfWeaknesses -eq $_.NumberOfWeaknesses }
    }

    if ($OSPlatform) {
        $FilteredContent = $FilteredContent | Where-Object { $OSPlatform -contains $_.OSPlatform }
    }

    if ($RbacGroupName) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupName -contains $_.RbacGroupName }
    }

    if ($RegistryPaths) {
        $FilteredContent = $FilteredContent | Where-Object { $RegistryPaths -contains $_.RegistryPaths }
    }

    if ($SoftwareFirstSeenTimestamp) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareFirstSeenTimestamp -contains $_.SoftwareFirstSeenTimestamp }
    }

    if ($SoftwareName) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareName -contains $_.SoftwareName }
    }

    if ($SoftwareVendor) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareVendor -contains $_.SoftwareVendor }
    }

    if ($SoftwareVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareVersion -contains $_.SoftwareVersion }
    }

    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent
}

function Get-NonCpeSoftwareInventoryAssessment {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-assessment-non-cpe-software-inventory
    This Get-NonCpeSoftwareInventoryAssessment function allows for returning all installed software that does not have a Common Platform Enumeration (CPE) and their statuses per-device in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property(ID)" column in the above documentation and can accept multiple values for each parameter.
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-NonCpeSoftwareInventoryAssessment -SoftwareVendor "Microsoft" -OsPlatform "Windows10","Windows11" -Path "C:\NonCpeSoftwareInventory.csv" -Q
This example will return all Microsoft software which does not have a known CPE on Windows 10 and 11 devices.
It will return these results into a CSV named "C:\NonCpeSoftwareInventory.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$DeviceId,
        [string[]]$DeviceName,
        [string[]]$OSPlatform,
        [string[]]$RbacGroupName,
        [string[]]$RbacGroupId,
        [string[]]$SoftwareLastSeenTimestamp,
        [string[]]$SoftwareName,
        [string[]]$SoftwareVendor,
        [string[]]$SoftwareVersion,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )

    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/machines/SoftwareInventoryNoProductCodeByMachine"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    if ($DeviceId) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceId -contains $_.DeviceId }
    }

    if ($DeviceName) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceName -contains $_.DeviceName }
    }

    if ($OSPlatform) {
        $FilteredContent = $FilteredContent | Where-Object { $OSPlatform -contains $_.OSPlatform }
    }

    if ($RbacGroupName) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupName -contains $_.RbacGroupName }
    }

    if ($RbacGroupId) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupId -contains $_.RbacGroupId }
    }

    if ($SoftwareLastSeenTimestamp) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareLastSeenTimestamp -contains $_.SoftwareLastSeenTimestamp }
    }

    if ($SoftwareName) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareName -contains $_.SoftwareName }
    }

    if ($SoftwareVendor) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareVendor -contains $_.SoftwareVendor }
    }

    if ($SoftwareVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareVersion -contains $_.SoftwareVersion }
    }

    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent
}

function Get-SoftwareVulnerabilitiesAssessment {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-assessment-software-vulnerabilities
    This Get-SoftwareVulnerabilitiesAssessment function allows for returning all known software vulnerabilities and their details per-device in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property(ID)" column in the above documentation and can accept multiple values for each parameter.
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-SoftwareVulnerabilitiesAssessment -VulnerabilitySeverityLevel "high" -ExploitabilityLevel "ExploitIsVerified" -Path "C:\SoftwareVulnerabilities.csv" -Q
This example will return all security config assessments where the device is not compliant and the impact is an 8, 9, or 10..
It will return these results into a CSV named "C:\SoftwareVulnerabilities.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$CveId,
        [string[]]$CvssScore,
        [string[]]$DeviceId,
        [string[]]$DeviceName,
        [string[]]$DiskPaths,
        [string[]]$ExploitabilityLevel,
        [string[]]$FirstSeenTimeStamp,
        [string[]]$Id,
        [string[]]$LastSeenTimestamp,
        [string[]]$OSPlatform,
        [string[]]$RbacGroupName,
        [string[]]$RecommendationReference,
        [string[]]$RecommendedSecurityUpdate,
        [string[]]$RecommendedSecurityUpdateId,
        [string[]]$RegistryPaths,
        [bool]$SecurityUpdateAvailable,
        [string[]]$SoftwareName,
        [string[]]$SoftwareVendor,
        [string[]]$SoftwareVersion,
        [string[]]$VulnerabilitySeverityLevel,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )

    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    
    if ($CveId) {
        $FilteredContent = $FilteredContent | Where-Object { $CveId -contains $_.CveId }
    }
    
    if ($CvssScore) {
        $FilteredContent = $FilteredContent | Where-Object { $CvssScore -contains $_.CvssScore }
    }
    
    if ($DeviceId) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceId -contains $_.DeviceId }
    }
    
    if ($DeviceName) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceName -contains $_.DeviceName }
    }
    
    if ($DiskPaths) {
        $FilteredContent = $FilteredContent | Where-Object { $DiskPaths -contains $_.DiskPath }
    }
    
    if ($ExploitabilityLevel) {
        $FilteredContent = $FilteredContent | Where-Object { $ExploitabilityLevel -contains $_.ExploitabilityLevel }
    }
    
    if ($FirstSeenTimeStamp) {
        $FilteredContent = $FilteredContent | Where-Object { $FirstSeenTimeStamp -contains $_.FirstSeenTimeStamp }
    }
    
    if ($Id) {
        $FilteredContent = $FilteredContent | Where-Object { $Id -contains $_.Id }
    }
    
    if ($LastSeenTimestamp) {
        $FilteredContent = $FilteredContent | Where-Object { $LastSeenTimestamp -contains $_.LastSeenTimestamp }
    }
    
    if ($OSPlatform) {
        $FilteredContent = $FilteredContent | Where-Object { $OSPlatform -contains $_.OSPlatform }
    }
    
    if ($RbacGroupName) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupName -contains $_.RbacGroupName }
    }
    
    if ($RecommendationReference) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendationReference -contains $_.RecommendationReference }
    }
    
    if ($RecommendedSecurityUpdate) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendedSecurityUpdate -contains $_.RecommendedSecurityUpdate }
    }
    
    if ($RecommendedSecurityUpdateId) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendedSecurityUpdateId -contains $_.RecommendedSecurityUpdateId }
    }
    
    if ($RegistryPaths) {
        $FilteredContent = $FilteredContent | Where-Object { $RegistryPaths -contains $_.RegistryPath }
    }
    
    if ($SecurityUpdateAvailable) {
        $FilteredContent = $FilteredContent | Where-Object { $SecurityUpdateAvailable -eq $_.SecurityUpdateAvailable }
    }
    
    if ($SoftwareName) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareName -contains $_.SoftwareName }
    }

    if ($SoftwareVendor) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareVendor -contains $_.SoftwareVendor }
    }

    if ($SoftwareVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $SoftwareVersion -contains $_.SoftwareVersion }
    }

    if ($VulnerabilitySeverityLevel) {
        $FilteredContent = $FilteredContent | Where-Object { $VulnerabilitySeverityLevel -contains $_.VulnerabilitySeverityLevel }
    }

    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent
}

Function Get-Machines {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machines
    This Get-Machines function allows for returning all known software vulnerabilities and their details per-device in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property" column of the Machine methods and properties API documentation found here: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/machine?view=o365-worldwide#properties 
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-Machines -ExposureLevel High -RbacGroupname "Domain Controllers" -Path "C:\HighExposureDCs.csv" -Q
This example will return all machines and their details where the exposure level is high and the machine is part of the "Domain Controllers" device group.
It will return these results into a CSV named "C:\HighExposureDCs.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$Id,
        [string[]]$ComputerDnsName,
        [string[]]$FirstSeen,
        [string[]]$LastSeen,
        [string[]]$OsPlatform,
        [string[]]$OnboardingStatus,
        [string[]]$OsProcessor,
        [string[]]$Version,
        [string[]]$OsBuild,
        [string[]]$LastIpAddress,
        [string[]]$LastExternalIpAddress,
        [string[]]$HealthStatus,
        [string[]]$RbacGroupName,
        [string[]]$RbacGroupId,
        [string[]]$RiskScore,
        [string[]]$AadDeviceId,
        [string[]]$MachineTags,
        [string[]]$ExposureLevel,
        [string[]]$DeviceValue,
        [string[]]$IpAddresses,
        [string[]]$OsArchitecture,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )
    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/machines"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    
    if ($Id) {
        $FilteredContent = $FilteredContent | Where-Object { $Id -contains $_.Id }
    }
    
    if ($ComputerDnsName) {
        $FilteredContent = $FilteredContent | Where-Object { $ComputerDnsName -contains $_.ComputerDnsName }
    }
    
    if ($FirstSeen) {
        $FilteredContent = $FilteredContent | Where-Object { $FirstSeen -contains $_.FirstSeen }
    }
    
    if ($LastSeen) {
        $FilteredContent = $FilteredContent | Where-Object { $LastSeen -contains $_.LastSeen }
    }
    
    if ($OsPlatform) {
        $FilteredContent = $FilteredContent | Where-Object { $OsPlatform -contains $_.OsPlatform }
    }
    
    if ($OnboardingStatus) {
        $FilteredContent = $FilteredContent | Where-Object { $OnboardingStatus -contains $_.OnboardingStatus }
    }
    
    if ($OsProcessor) {
        $FilteredContent = $FilteredContent | Where-Object { $OsProcessor -contains $_.OsProcessor }
    }
    
    if ($Version) {
        $FilteredContent = $FilteredContent | Where-Object { $Version -contains $_.Version }
    }
    
    if ($OsBuild) {
        $FilteredContent = $FilteredContent | Where-Object { $OsBuild -contains $_.OsBuild }
    }
    
    if ($LastIpAddress) {
        $FilteredContent = $FilteredContent | Where-Object { $LastIpAddress -contains $_.LastIpAddress }
    }
    
    if ($LastExternalIpAddress) {
        $FilteredContent = $FilteredContent | Where-Object { $LastExternalIpAddress -contains $_.LastExternalIpAddress }
    }
    
    if ($HealthStatus) {
        $FilteredContent = $FilteredContent | Where-Object { $HealthStatus -contains $_.HealthStatus }
    }
    
    if ($RbacGroupName) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupName -contains $_.RbacGroupName }
    }
    
    if ($RbacGroupId) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupId -contains $_.RbacGroupId }
    }
    
    if ($RiskScore) {
        $FilteredContent = $FilteredContent | Where-Object { $RiskScore -contains $_.RiskScore }
    }
    
    if ($AadDeviceId) {
        $FilteredContent = $FilteredContent | Where-Object { $AadDeviceId -contains $_.AadDeviceId }
    }
    
    if ($MachineTags) {
        $FilteredContent = $FilteredContent | Where-Object { $MachineTags -contains $_.MachineTags }
    }

    if ($ExposureLevel) {
        $FilteredContent = $FilteredContent | Where-Object { $ExposureLevel -contains $_.ExposureLevel }
    }

    if ($DeviceValue) {
        $FilteredContent = $FilteredContent | Where-Object { $DeviceValue -contains $_.DeviceValue }
    }

    if ($IpAddresses) {
        $FilteredContent = $FilteredContent | Where-Object { $IpAddresses -contains $_.IpAddresses }
    }

    if ($OsArchitecture) {
        $FilteredContent = $FilteredContent | Where-Object { $OsArchitecture -contains $_.OsArchitecture }
    }

    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent

}
Set-Alias -Name "Get-Devices" -Value "Get-Machines"

Function Get-Alerts {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-alerts?view=o365-worldwide
    This Get-Alerts function allows for returning all MDE alerts and their details in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property" column of the Machine methods and properties API documentation found here: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/alerts?view=o365-worldwide#properties
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-Alerts -RelatedUser "Bob Dylan" -Determination "True Positive" -Path "C:\BobsAlerts.csv" -Q
This example will return all alerts where the related user is Bob Dylan and the determination of the alert was True Positive.
It will return these results into a CSV named "C:\BobsAlerts.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$Id,
        [string[]]$title,
        [string[]]$description,
        [string[]]$alertCreationTime,
        [string[]]$lastEventTime,
        [string[]]$firstEventTime,
        [string[]]$lastUpdateTime,
        [string[]]$resolvedTime,
        [string[]]$incidentId,
        [string[]]$investigationId,
        [string[]]$investigationState,
        [string[]]$assignedTo,
        [string[]]$RbacGroupName,
        [string[]]$mitreTechniques,
        [string[]]$RelatedUser,
        [string[]]$Severity,
        [string[]]$Status,
        [string[]]$Classification,
        [string[]]$Determination,
        [string[]]$Category,
        [string[]]$DetectionSource,
        [string[]]$ThreatFamilyName,
        [string[]]$ThreatName,
        [string[]]$MachineId,
        [string[]]$ComputerDnsName,
        [string[]]$AadTenantId,
        [string[]]$DetectorId,
        [string[]]$comments,
        [string[]]$Evidence,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )
    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/alerts"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    
    if ($Id) {
        $FilteredContent = $FilteredContent | Where-Object { $Id -contains $_.Id }
    }
    
    if ($Title) {
        $FilteredContent = $FilteredContent | Where-Object { $Title -contains $_.Title }
    }
    
    if ($description) {
        $FilteredContent = $FilteredContent | Where-Object { $description -contains $_.description }
    }
    
    if ($alertCreationTime) {
        $FilteredContent = $FilteredContent | Where-Object { $alertCreationTime -contains $_.alertCreationTime }
    }
    
    if ($lastEventTime) {
        $FilteredContent = $FilteredContent | Where-Object { $lastEventTime -contains $_.lastEventTime }
    }
    
    if ($firsteventTime) {
        $FilteredContent = $FilteredContent | Where-Object { $firstEventTime -contains $_.firstEventTime }
    }
    
    if ($resolvedTime) {
        $FilteredContent = $FilteredContent | Where-Object { $resolvedTime -contains $_.resolvedTime }
    }
    
    if ($incidentId) {
        $FilteredContent = $FilteredContent | Where-Object { $incidentId -contains $_.incidentId }
    }
    
    if ($investigationId) {
        $FilteredContent = $FilteredContent | Where-Object { $investigationId -contains $_.investigationId }
    }
    
    if ($investigationState) {
        $FilteredContent = $FilteredContent | Where-Object { $investigationState -contains $_.investigationState }
    }
    
    if ($assignedTo) {
        $FilteredContent = $FilteredContent | Where-Object { $assignedTo -contains $_.assignedTo }
    }
    
    if ($RbacGroupName) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupName -contains $_.RbacGroupName }
    }
    
    if ($lastUpdateTime) {
        $FilteredContent = $FilteredContent | Where-Object { $lastUpdateTime -contains $_.lastUpdateTime }
    }
    
    if ($mitreTechniques) {
        $FilteredContent = $FilteredContent | Where-Object { $mitreTechniques -contains $_.mitreTechniques }
    }
    
    if ($RelatedUser) {
        $FilteredContent = $FilteredContent | Where-Object { $RelatedUser -contains $_.RelatedUser }
    }
    
    if ($Severity) {
        $FilteredContent = $FilteredContent | Where-Object { $Severity -contains $_.Severity }
    }
    
    if ($Status) {
        $FilteredContent = $FilteredContent | Where-Object { $Status -contains $_.Status }
    }

    if ($Classification) {
        $FilteredContent = $FilteredContent | Where-Object { $Classification -contains $_.Classification }
    }

    if ($Determination) {
        $FilteredContent = $FilteredContent | Where-Object { $Determinaion -contains $_.Determination }
    }

    if ($Category) {
        $FilteredContent = $FilteredContent | Where-Object { $Category -contains $_.Category }
    }

    if ($DetectionSource) {
        $FilteredContent = $FilteredContent | Where-Object { $DetectionSource -contains $_.DetectionSource }
    }

    if ($ThreatFamilyName) {
        $FilteredContent = $FilteredContent | Where-Object { $ThreatFamilyName -contains $_.ThreatFamilyName }
    }

    if ($ThreatName) {
        $FilteredContent = $FilteredContent | Where-Object { $ThreatName -contains $_.ThreatName }
    }

    if ($MachineId) {
        $FilteredContent = $FilteredContent | Where-Object { $MachineId -contains $_.MachineId }
    }

    if ($ComputerDnsName) {
        $FilteredContent = $FilteredContent | Where-Object { $ComputerDnsName -contains $_.ComputerDnsName }
    }

    if ($AadTenantId) {
        $FilteredContent = $FilteredContent | Where-Object { $AadTenantId -contains $_.AadTenantId }
    }

    if ($DetectorId) {
        $FilteredContent = $FilteredContent | Where-Object { $DetectorId -contains $_.DetectorId }
    }

    if ($Comments) {
        $FilteredContent = $FilteredContent | Where-Object { $comments -contains $_.comments }
    }

    if ($Evidence) {
        $FilteredContent = $FilteredContent | Where-Object { $Evidence -contains $_.Evidence }
    }


    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent

}

Function Get-AvInfo {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-health-export-antivirus-health-report-api?view=o365-worldwide
    This Get-AvInfo function retrieves a list of Microsoft Defender Antivirus device health details in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property" column of the Machine methods and properties API documentation found here: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-health-api-methods-properties?view=o365-worldwide#13-export-device-antivirus-health-details-api-properties-json-response
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-AvInfo -AvIsPlatformUpToDate "False","Unknown" -Path "C:\OutdatedAvDevices.csv" -Q
This example will list all machines and their antivirus health info where the platform is out of date or unknown.
It will return these results into a CSV named "C:\OutdatedAvDevices.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$Id,
        [string[]]$AvEngineUpdateTime,
        [string[]]$AvEngineVersion,
        [string[]]$AvIsEngineUpToDate,
        [string[]]$AvIsPlatformUpToDate,
        [string[]]$AvIsSignatureUpToDate,
        [string[]]$AvMode,
        [string[]]$AvPlatformVersion,
        [string[]]$AvSignaturePublishTime,
        [string[]]$AvSignatureUpdateTime,
        [string[]]$AvSignatureVersion,
        [string[]]$ComputerDnsName,
        [string[]]$RbacGroupName,
        [string[]]$DataRefreshTimestamp,
        [string[]]$FullScanError,
        [string[]]$FullScanResult,
        [string[]]$FullScanTime,
        [string[]]$LastSeenTime,
        [string[]]$OsKind,
        [string[]]$OsPlatform,
        [string[]]$OsVersion,
        [string[]]$QuickScanError,
        [string[]]$QuickScanResult,
        [string[]]$MachineId,
        [string[]]$QuickScanTime,
        [string[]]$RbacGroupId,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )
    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/deviceavinfo"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    
    if ($Id) {
        $FilteredContent = $FilteredContent | Where-Object { $Id -contains $_.Id }
    }
    
    if ($AvEngineUpdateTime) {
        $FilteredContent = $FilteredContent | Where-Object { $AvEngineUpdateTime -contains $_.AvEngineUpdateTime }
    }
    
    if ($AvEngineVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $AvEngineVersion -contains $_.AvEngineVersion }
    }
    
    if ($AvIsEngineUpToDate) {
        $FilteredContent = $FilteredContent | Where-Object { $AvIsEngineUpToDate -contains $_.AvIsEngineUpToDate }
    }
    
    if ($AvIsPlatformUpToDate) {
        $FilteredContent = $FilteredContent | Where-Object { $AvIsPlatformUpToDate -contains $_.AvIsPlatformUpToDate }
    }
    
    if ($AvIsSignatureUpToDate) {
        $FilteredContent = $FilteredContent | Where-Object { $AvIsSignatureUpToDate -contains $_.AvIsSignatureUpToDate }
    }
    
    if ($AvMode) {
        $FilteredContent = $FilteredContent | Where-Object { $AvMode -contains $_.AvMode }
    }
    
    if ($AvPlatformVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $AvPlatformVersion -contains $_.AvPlatformVersion }
    }
    
    if ($AvSignaturePublishTime) {
        $FilteredContent = $FilteredContent | Where-Object { $AvSignaturePublishTime -contains $_.AvSignaturePublishTime }
    }
    
    if ($AvSignatureUpdateTime) {
        $FilteredContent = $FilteredContent | Where-Object { $AvSignatureUpdateTime -contains $_.AvSignatureUpdateTime }
    }
    
    if ($AvSignatureVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $AvSignatureVersion -contains $_.AvSignatureVersion }
    }
    
    if ($RbacGroupName) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupName -contains $_.RbacGroupName }
    }
    
    if ($DataRefreshTimestamp) {
        $FilteredContent = $FilteredContent | Where-Object { $DataRefreshTimestamp -contains $_.DataRefreshTimestamp }
    }
    
    if ($FullScanError) {
        $FilteredContent = $FilteredContent | Where-Object { $FullScanError -contains $_.FullScanError }
    }
    
    if ($FullScanResult) {
        $FilteredContent = $FilteredContent | Where-Object { $FullScanResult -contains $_.FullScanResult }
    }
    
    if ($FullScanTime) {
        $FilteredContent = $FilteredContent | Where-Object { $FullScanTime -contains $_.FullScanTime }
    }
    
    if ($LastSeenTime) {
        $FilteredContent = $FilteredContent | Where-Object { $LastSeenTime -contains $_.LastSeenTime }
    }

    if ($OsKind) {
        $FilteredContent = $FilteredContent | Where-Object { $OsKind -contains $_.OsKind }
    }

    if ($OsPlatform) {
        $FilteredContent = $FilteredContent | Where-Object { $OsPlatform -contains $_.OsPlatform }
    }

    if ($OsVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $OsVersion -contains $_.OsVersion }
    }

    if ($QuickScanError) {
        $FilteredContent = $FilteredContent | Where-Object { $QuickScanError -contains $_.QuickScanError }
    }

    if ($QuickScanResult) {
        $FilteredContent = $FilteredContent | Where-Object { $QuickScanResult -contains $_.QuickScanResult }
    }

    if ($QuickScanTime) {
        $FilteredContent = $FilteredContent | Where-Object { $QuickScanTime -contains $_.QuickScanTime }
    }

    if ($MachineId) {
        $FilteredContent = $FilteredContent | Where-Object { $MachineId -contains $_.MachineId }
    }

    if ($ComputerDnsName) {
        $FilteredContent = $FilteredContent | Where-Object { $ComputerDnsName -contains $_.ComputerDnsName }
    }

    if ($RbacGroupId) {
        $FilteredContent = $FilteredContent | Where-Object { $RbacGroupId -contains $_.RbacGroupId }
    }

    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent

}

Function Get-Recommendations {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-all-recommendations?view=o365-worldwide
    This Get-Recommendations function retrieves a list of all security recommendations affecting the organization in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property" column of the Machine methods and properties API documentation found here: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/recommendation?view=o365-worldwide#properties 
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-Recommendations -SeverityScore 10 -RemediationType "Uninstall" -Path "C:\HighSevRecommendations.csv" -Q
This example will list all security recommendations where the severity score is 10 and the remediation type is uninstall.
It will return these results into a CSV named "C:\HighSevRecommendations.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$Id,
        [string[]]$ProductName,
        [string[]]$RecommendationName,
        [int[]]$Weaknesses,
        [string[]]$Vendor,
        [string[]]$RecommendedVersion,
        [string[]]$RecommendedProgram,
        [string[]]$RecommendedVendor,
        [string[]]$RecommendationCategory,
        [string[]]$SubCategory,
        [int[]]$SeverityScore,
        [string[]]$PublicExploit,
        [string[]]$ActiveAlert,
        [string[]]$AssociatedThreats,
        [string[]]$RemediationType,
        [string[]]$Status,
        [int[]]$ConfigScoreImpact,
        [int[]]$ExposureImpact,
        [int[]]$TotalMachineCount,
        [int[]]$ExposedMachinesCount,
        [int[]]$NonProductivityImpactedAssets,
        [string[]]$RelatedComponent,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )
    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/recommendations"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    
    if ($Id) {
        $FilteredContent = $FilteredContent | Where-Object { $Id -contains $_.Id }
    }
    
    if ($ProductName) {
        $FilteredContent = $FilteredContent | Where-Object { $ProductName -contains $_.ProductName }
    }
    
    if ($RecommendationName) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendationName -contains $_.RecommendationName }
    }
    
    if ($Weaknesses) {
        $FilteredContent = $FilteredContent | Where-Object { $Weaknesses -contains $_.Weaknesses }
    }
    
    if ($Vendor) {
        $FilteredContent = $FilteredContent | Where-Object { $Vendor -contains $_.Vendor }
    }
    
    if ($RecommendedVersion) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendedVersion -contains $_.RecommendedVersion }
    }
    
    if ($RecommendedProgram) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendedProgram -contains $_.RecommendedProgram }
    }
    
    if ($RecommendedVendor) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendedVendor -contains $_.RecommendedVendor }
    }
    
    if ($RecommendationCategory) {
        $FilteredContent = $FilteredContent | Where-Object { $RecommendationCategory -contains $_.RecommendationCategory }
    }
    
    if ($SubCategory) {
        $FilteredContent = $FilteredContent | Where-Object { $SubCategory -contains $_.SubCategory }
    }
    
    if ($SeverityScore) {
        $FilteredContent = $FilteredContent | Where-Object { $SeverityScore -contains $_.SeverityScore }
    }
    
    if ($PublicExploit) {
        $FilteredContent = $FilteredContent | Where-Object { $PublicExploit -contains $_.PublicExploit }
    }
    
    if ($ActiveAlert) {
        $FilteredContent = $FilteredContent | Where-Object { $ActiveAlert -contains $_.ActiveAlert }
    }
    
    if ($AssociatedThreats) {
        $FilteredContent = $FilteredContent | Where-Object { $AssociatedThreats -contains $_.AssociatedThreats }
    }
    
    if ($RemediationType) {
        $FilteredContent = $FilteredContent | Where-Object { $RemediationType -contains $_.RemediationType }
    }
    
    if ($Status) {
        $FilteredContent = $FilteredContent | Where-Object { $Status -contains $_.Status }
    }
    
    if ($ConfigScoreImpact) {
        $FilteredContent = $FilteredContent | Where-Object { $ConfigScoreImpact -contains $_.ConfigScoreImpact }
    }

    if ($ExposureImpact) {
        $FilteredContent = $FilteredContent | Where-Object { $ExposureImpact -contains $_.ExposureImpact }
    }

    if ($TotalMachineCount) {
        $FilteredContent = $FilteredContent | Where-Object { $TotalMachineCount -contains $_.TotalMachineCount }
    }

    if ($ExposedMachinesCount) {
        $FilteredContent = $FilteredContent | Where-Object { $ExposedMachinesCount -contains $_.ExposedMachinesCount }
    }

    if ($NonProductivityImpactedAssets) {
        $FilteredContent = $FilteredContent | Where-Object { $NonProductivityImpactedAssets -contains $_.NonProductivityImpactedAssets }
    }

    if ($RelatedComponent) {
        $FilteredContent = $FilteredContent | Where-Object { $RelatedComponent -contains $_.RelatedComponent }
    }

    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent

}

Function Get-Vulnerabilities {
    <#
    .SYNOPSIS
    Using https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-all-vulnerabilities?view=o365-worldwide
    This Get-Vulnerabilities function retrieves a list of all security vulnerabilities affecting the organization in JSON format to either the PowerShell console or specified CSV file or both.

    .DESCRIPTION
    It can accept parameters for any of the values in the "Property" column of the Machine methods and properties API documentation found here: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/vulnerability?view=o365-worldwide#properties
It can also accept the -Path (-P) parameter to specify an output path to a CSV file and the -Quiet (-Q) parameter to prevent output into the PowerShell console.

    .PARAMETER ParameterName
    Description of the function parameter.
    This section can be repeated for each parameter.

    .EXAMPLE
    Get-Vulnerabilities -id "CVE-2023-20955" -Path "C:\Cve-2023-20955.csv" -Q
This example will list details about vulnerabilities where the id is CVE-2023-20955.
It will return these results into a CSV named "C:\Cve-2023-20955.csv" and it will not output the results to the console.
    
    #>
    [CmdletBinding()]
    param (
        [string[]]$Id,
        [string[]]$Name,
        [string[]]$Description,
        [string[]]$Severity,
        [int[]]$CvssV3,
        [int[]]$ExposedMachines,
        [string[]]$PublishedOn,
        [string[]]$UpdatedOn,
        [string[]]$PublicExploit,
        [string[]]$ExploitVerified,
        [string[]]$ExploitInKit,
        [string[]]$ExploitTypes,
        [string[]]$ExploitUris,
        [alias("P")]
        [string]$Path,
        [alias("Q")]
        [switch]$Quiet
        
    )
    Set-AccessToken
    $Url = "https://api.securitycenter.microsoft.com/api/vulnerabilities"
    $headers = @{
        Authorization = "Bearer $token"
    }
    $WebRequest = Invoke-WebRequest -Method Get -Uri $Url -Headers $headers
    $Content = $WebRequest.Content | ConvertFrom-Json

    $FilteredContent = $Content.Value

    
    if ($Id) {
        $FilteredContent = $FilteredContent | Where-Object { $Id -contains $_.Id }
    }
    
    if ($Name) {
        $FilteredContent = $FilteredContent | Where-Object { $Name -contains $_.Name }
    }
    
    if ($Description) {
        $FilteredContent = $FilteredContent | Where-Object { $Description -contains $_.Description }
    }
    
    if ($Severity) {
        $FilteredContent = $FilteredContent | Where-Object { $Severity -contains $_.Severity }
    }
    
    if ($CvssV3) {
        $FilteredContent = $FilteredContent | Where-Object { $CvssV3 -contains $_.CvssV3 }
    }
    
    if ($ExposedMachines) {
        $FilteredContent = $FilteredContent | Where-Object { $ExposedMachines -contains $_.ExposedMachines }
    }
    
    if ($PublishedOn) {
        $FilteredContent = $FilteredContent | Where-Object { $PublishedOn -contains $_.PublishedOn }
    }
    
    if ($UpdatedOn) {
        $FilteredContent = $FilteredContent | Where-Object { $UpdatedOn -contains $_.UpdatedOn }
    }
    
    if ($PublicExploit) {
        $FilteredContent = $FilteredContent | Where-Object { $PublicExploit -contains $_.PublicExploit }
    }
    
    if ($ExploitVerified) {
        $FilteredContent = $FilteredContent | Where-Object { $ExploitVerified -contains $_.ExploitVerified }
    }
    
    if ($ExploitInKit) {
        $FilteredContent = $FilteredContent | Where-Object { $ExploitInKit -contains $_.ExploitInKit }
    }
    
    if ($ExploitTypes) {
        $FilteredContent = $FilteredContent | Where-Object { $ExploitTypes -contains $_.ExploitTypes }
    }
    
    if ($ExploitUris) {
        $FilteredContent = $FilteredContent | Where-Object { $ExploitUris -contains $_.ExploitUris }
    }
    
    if ($Path) {
        $Path = $Path -replace '"',''
        # Ensure $MachinesOutputFile has .csv extension
        $Path = [System.IO.Path]::ChangeExtension($Path, ".csv")
        $FilteredContent | Export-Csv -Path $Path -NoTypeInformation -Force 
        if ($?) {
            Write-Host "Successfully created $Path" -ForegroundColor Yellow
            Invoke-Item -Path $Path
        } else {
            Write-Host "Failed to create $Path" -ForegroundColor Red
        }
    }
    if ($Quiet){
        Return
    }
    $FilteredContent

}

Function Set-DeviceInputQuantity {
    param([ref]$breakFlag)
    <# 
    # OBJECTIVE:
    Set-DeviceInputQuantity is a function used internally by this module in scenarios where a user can provide a csv of machines as input for specific machine action API calls
    #>
    $script:CsvDeviceIDs = $null 
    Write-Host "Type 'y' to enter a CSV of devices or 'n' to enter a single device ID."
    $script:MultipleInputChoice = Read-Host 
    switch($MultipleInputChoice)
    {
        'n'{
            # User input a single machine ID
            $UserInput = Read-Host "Enter a Machine ID"
            $Script:UserChosenMachineID = $UserInput
        }

        'y'{
            # User input a CSV of machine IDs
            Write-Host "Enter full file path to input CSV." -ForegroundColor Yellow
            Write-Host "Ensure there is a column titled 'Device ID' or 'id' in the CSV file."
            $script:CsvInputPath = Read-Host 
            $script:CsvInputPath = $Script:CsvInputPath -replace '"',''
            $script:CsvDevicesObject = $null
            $script:CsvDevicesObject = Import-Csv $script:CsvInputPath
            
            # Checking CSV headers for "id" or "Device ID" value and creating list of Device IDs based on those values
            If($CsvDevicesObject.'Device ID' -ne $null){
                [System.Collections.ArrayList]$Script:UserChosenMachineIds = $CsvDevicesObject.'Device ID'
            }
            elseif ($CsvDevicesObject.id -ne $null) {
                [System.Collections.ArrayList]$Script:UserChosenMachineIds = $CsvDevicesObject.id
            }
            if ($CsvDevicesObject -eq $null) {
                Write-Host "Could not find any column titled 'Device Id' or 'id' in supplied CSV. Please add one of those two column titles and try again."
                $breakFlag.Value = $True
            }
            
        }

    }

}

Function Show-Menu {
    <# 
    # OBJECTIVE:
    Show-Menu is a function used internally by this module to present the Machine Actions menu
    #>
    # Display Main Menu
    Write-Host "============== Machine Actions ==============" -ForeGroundColor Yellow
    Write-Host "1: Press '1' Collect Investigation Package"
    Write-Host "2: Press '2' Isolate or Unisolate Machine"
    Write-Host "3: Press '3' Run Live Response"
    Write-Host "4: Press '4' Restrict or Unrestrict Applications"
    Write-Host "5: Press '5' Run Antivirus Scan"
    Write-Host "6: Press '6' Offboard Machine"
    Write-Host "7: Press '7' Stop and Quarantine File"
    Write-Host "8: Press '8' Cancel a Machine Action"
    Write-Host "Q: Press 'Q' to Quit"
    Write-Host "`n"
    # Get User Input for Machine Action Choice
    $Script:MachineActionSelection = Read-Host "Please make a selection" 
    }

Function Show-MachineActionsMenu {
        <#
    .SYNOPSIS
    Using many of the machine action APIs https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/machineaction?view=o365-worldwide
    This Show-MachineActionsMenu function displays a menu from which users can choose a number of different machine actions to take in bulk or upon single devices.
    These actions include collecting investigation packages, isolating devices, live response, restricting applications, running AV scans, offboarding from MDE, and more.

    .DESCRIPTION
    Further details about the capabilities of this menu can be found in my blog here: https://wordpress.com/post/securityoccupied.com/492

    .EXAMPLE
    There are no parameters for this function. Simply run "Show-MachineActionsMenu" and a menu will be displayed allowing you to choose a machine action to take.
    
    #>
    [CmdletBinding()]
    param()
    Set-AccessToken
    
do
{
    $breakFlag = $false
    Show-Menu
    switch ($MachineActionSelection)
    {
    '1'{
        # Collects Investigation Package from Device(s)
        # Investigation package API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/collect-investigation-package?view=o365-worldwide
        $PackageCollectionWebRequest = $null
        Write-Host "Collect Investigation Package." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $comment = Read-Host 
        $body = @"
    {
"Comment": "$comment"
    }
"@

        switch($MultipleInputChoice){
            'n'{
                # User chose to input a single device ID
                $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineId/collectInvestigationPackage"
                $PackageCollectionWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body 
                $PackageCollectionWebRequest | ConvertFrom-Json
            }
            'y'{
                # User chose to input a CSV of device IDs
                foreach($i in $UserChosenMachineIds){
                    $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/collectInvestigationPackage"
                    $PackageCollectionWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                    $PackageCollectionWebRequest | ConvertFrom-Json
                }
            }
        }

    }
    '2'{
        # Isolate/Unisolate Machines
        # Isolation API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine?view=o365-worldwide
        # Unisolation API public doc:  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unisolate-machine?view=o365-worldwide
        $DeviceIsolationWebRequest = $null
        Write-Host 'Isolate/Unisolate Device(s)' -ForegroundColor Yellow    
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }

        # Get user input for isolate/unisolate then set comment and headers
        Write-Host "Type 'I' to isolate or 'U' to unisolate." -ForegroundColor Yellow
        $IsolateOrUnisolateSelection = Read-Host
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host 
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }

        # Check if user is inputing CSV or single Machine ID
        switch ($MultipleInputChoice){
            'n'{
                # User entering single Machine ID
                # Check if user is isolating or unisolating
                switch($IsolateOrUnisolateSelection){
                    'i'{
                        # User chose to isolate
                        # For isolation, user must input isolation type (full/selective)
                        Write-Host "Please enter isolation type. Allowed values are: 'Full' or 'Selective'." -ForegroundColor Yellow
                        $IsolationType = Read-Host 
                        $body = @"
                        {
                            "Comment": "$comment",
                            "IsolationType": "$IsolationType"
                        }
"@
                        $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/isolate"
                        $DeviceIsolationWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body
                        $DeviceIsolationWebRequest | ConvertFrom-Json
                    }
                    'u'{
                        # User chose to unisolate
                        $body = @"
                        {
                            "Comment": "$comment"
                        }
"@           
                        $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/unisolate"
                        $DeviceIsolationWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body
                        $DeviceIsolationWebRequest | ConvertFrom-Json
                    }
                }
            }
            'y'{
                # User entering CSV of machine IDs
                switch($IsolateOrUnisolateSelection){
                    'i'{
                        # User chose to isolate
                        # For isolation, user must input isolation type (full/selective)
                        Write-Host "Please enter isolation type. Allowed values are: 'Full' or 'Selective'." -ForegroundColor Yellow
                        $IsolationType = Read-Host 
                        $body = @"
                        {
                            "Comment": "$comment",
                            "IsolationType": "$IsolationType"
                        }
"@
                        foreach($i in $UserChosenMachineIds){
                            $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/isolate"
                            $PackageIsolationWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                            $PackageIsolationWebRequest | ConvertFrom-Json
                        }
                    }                    
                    'u'{
                        # User chose to unisolate
                        $body = @"
                        {
                            "Comment": "$comment"
                        }
"@
                        foreach($i in $UserChosenMachineIds){
                        $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/unisolate"
                        $DeviceIsolationWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body
                        $DeviceIsolationWebRequest | ConvertFrom-Json
                        }
                        
                    }
                }
            }
        }


    }
    '3'{
        # Live Response
        # Live Response API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide
        $LiveResponseWebRequest = $null
        Write-Host 'Live Response' -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a command. Allowed values are 'PutFile', 'RunScript', or 'GetFile'" -ForegroundColor Yellow
        $commands = Read-Host 
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $comment = Read-Host 
        
        switch($script:commands){
            'PutFile'   {
                Write-Host 'PutFile' -ForegroundColor Yellow
                $script:PutFilePath = Read-Host "Please enter file path of library file to put."
                $script:body = @"
                {
                "Commands":[
                {
                    "type":"$commands",
                    "params":[
                        {
                            "key":"FileName",
                            "value":"$PutFilePath"
                        }
                    ]
                }
                ],
                "Comment":"$comment"
                }
"@
       }
       'RunScript'{
           Write-Host 'RunScript' -ForegroundColor Yellow
           $script:ScriptName = Read-Host "Please enter the script name."
           #$script:LiveResponseArgs = Read-Host "Please enter any parameters to pass to the script (leave blank if there are none)." #Omitting Arguments key for now
       $script:body = @"
       {
       "Commands":[
        {
           "type":"$commands",
           "params":[
               {
                   "key":"ScriptName",
                   "value":"$ScriptName"
                }
            ]   
       }
       ],
       "Comment":"$comment"
        }
       
"@    
       
       }
       'GetFile'{
           Write-Host 'GetFile' -ForegroundColor Yellow
           $script:GetFilePath = Read-Host "Please enter the file path and name to get."
           $script:body = @"
           {
       "Commands":[
        {
           "type":"$commands",
           "params":[
               {
                   "key":"Path",
                   "value":"$GetFilePath"
                }
            ]
        }
       ],
       "Comment":"$comment"
        }
"@
        }
    }

    switch($MultipleInputChoice){
        'n'{ 
            # User entering single machine ID
            $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/runliveresponse"
            $LiveResponseWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body 
            $LiveResponseWebRequest | ConvertFrom-Json    
        }
        'y'{ 
            # User entering CSV of machine IDs       
            foreach($i in $UserChosenMachineIds){
                $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/runliveresponse"
                $LiveResponseWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                $LiveResponseWebRequest | ConvertFrom-Json             
            }    
        }
     }


    }
    '4'{
        # Restricts/Unrestricts App Execution
        # Restrict App API Public Doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/restrict-code-execution?view=o365-worldwide
        # Remove Restriction API Public Doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unrestrict-code-execution?view=o365-worldwide
        $RestrictAppsWebRequest = $null
        Write-Host "Restrict/Unrestrict execution of non-Microsoft signed applications." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Type 'R' to Restrict or 'U' to Unrestrict." -ForegroundColor Yellow
        $RestrictOrUnrestrict = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host 
        $body = @"
                        {
    "Comment": "$comment"
                        }
"@
            switch($MultipleInputChoice){
                'n'{
                    # User entering single machine ID
                    switch($RestrictOrUnrestrict){
                        'r'{
                            # User chose to restrict
                            $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/restrictCodeExecution"
                            $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                            $RestrictAppsWebRequest | ConvertFrom-Json
                        }
                        'u'{
                            # User chose to unrestrict
                            $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/unrestrictCodeExecution"
                            $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                            $RestrictAppsWebRequest | ConvertFrom-Json
                        }
                    }

                }
                'y'{
                    # User entering CSV of machine IDs
                    switch($RestrictOrUnrestrict){
                        'r'{
                            # User chose to restrict
                            foreach($i in $UserChosenMachineIds){
                                $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/restrictCodeExecution"
                                $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                                $RestrictAppsWebRequest | ConvertFrom-Json
                            }
                            
                        }
                        'u'{
                            # User chose to unrestrict
                            foreach($i in $UserChosenMachineIds){
                                $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/unrestrictCodeExecution"
                                $RestrictAppsWebRequest = Invoke-WebRequest -Method Post -URI $url -Headers $headers -Body $body
                                $RestrictAppsWebRequest | ConvertFrom-Json
                            }
                        }
                    }
                }
            }

    }
    '5'{
        # Runs an AV scan
        # AV Scan API Public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-av-scan?view=o365-worldwide
        $AVScanWebRequest = $null
        Write-Host "Run Antivirus Scan." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Type 'F' for Full scan or 'Q' for Quick scan."
        $ScanType = Read-Host
        If($ScanType.ToLower() -eq 'f'){$ScanType = 'Full'}
        If($ScanType.ToLower() -eq 'q'){$ScanType = 'Quick'}
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        $body = @"
        {
            "Comment": "$Comment",
            "ScanType": "$ScanType"
        }
"@
        switch($MultipleInputChoice){
            'n'{
                # User entering single machine ID
                $URL = "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/runAntiVirusScan"
                $AVScanWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
                $AVScanWebRequest | ConvertFrom-Json
            }
            'y'{
                # User entering CSV of machine IDs
                foreach($i in $UserChosenMachineIds){
                    $URL = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/runAntiVirusScan"
                    $AVScanWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
                    $AVScanWebRequest | ConvertFrom-Json
                }
            }
        }
    }
    '6'{
        # Offboards devices
        # Offboarding API Public Doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/offboard-machine-api?view=o365-worldwide
        $OffboardWebRequest = $null
        Write-Host "Offboard Machines." -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        $body = @"
        "Comment": "$comment"
"@
switch($MultipleInputChoice){
    'n'{
        # User entering single machine ID
      $URL =  "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/offboard"
      $OffboardWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
      $OffboardWebRequest | ConvertFrom-Json
    }
    'y'{
        # User entering CSV of machine IDs
        foreach($i in $UserChosenMachineIds){
      $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/offboard"
      $OffboardWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
      $OffboardWebRequest | ConvertFrom-Json
        }
    }
}

    }
    '7'{
        # Stop and Quarantine a file
        # Stop and Quarantine API Public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/stop-and-quarantine-file?view=o365-worldwide
        $StopFileWebRequest = $null
        Write-Host "Stop & Quarantine File" -ForegroundColor Yellow
        Set-DeviceInputQuantity([ref]$breakFlag)
        if ($breakFlag) {
            break
        }
        Write-Host "Please enter the SHA1 of the file to stop and quarantine." -ForegroundColor Yellow
        $sha1 = Read-Host
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $Comment = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        $body = @"
        "Comment": "$comment",
        "Sha1": "$Sha1"
"@
switch($MultipleInputChoice){
    'n'{
        $URL =  "https://api.securitycenter.microsoft.com/api/machines/$UserChosenMachineID/StopandQuarantineFile"
        $StopFileWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
        $StopFileWebRequest | ConvertFrom-Json
    }
    'y'{
        foreach($i in $UserChosenMachineIds){
            $url = "https://api.securitycenter.microsoft.com/api/machines/" + $i + "/StopandQuarantineFile"
            $StopFileWebRequest = Invoke-WebRequest -Method Post -URI $URL -Headers $headers -body $body
            $StopFileWebRequest | ConvertFrom-Json
        }
    }
}


    }
    '8'{    
        # Cancels a pending machine action
        # Cancel action API public doc: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/cancel-machine-action?view=o365-worldwide
        $CancelActionWebRequest = $null
        Write-Host "Cancel a pending machine action." -ForegroundColor Yellow
        Write-Host "Enter Machine Action ID" -ForegroundColor Yellow
        $MachineActionID = Read-Host
        $Headers = @{
            'Content-Type' = 'application/json'
            Accept = 'application/json'
            Authorization = "Bearer $token"
        }
        Write-Host "Please enter a comment" -ForegroundColor Yellow
        $comment = Read-Host
        $body = @"
        {
    "Comment": "$comment"
        }
"@
    
        $URL = "https://api.securitycenter.microsoft.com/api/machineactions/$MachineActionID/cancel"
        $CancelActionWebRequest = Invoke-WebRequest -Method Post -Uri $URL -Headers $headers -Body $body 
        $CancelActionWebRequest | ConvertFrom-Json    
    }
}

}
until ($MachineActionSelection -eq 'q')

}
Set-Alias -Name "Show-DeviceActionsMenu" -Value "Show-MachineActionsMenu"

Function Get-MdeKitHelp {
    [CmdletBinding()]
    $ExportedFunctions = 'Get-SecureConfigAssessment', 'Get-SoftwareInventoryAssessment', 'Get-NonCpeSoftwareInventoryAssessment', 'Get-SoftwareVulnerabilitiesAssessment', 'Get-Machines', 'Get-Alerts', 'Get-AvInfo', 'Get-Recommendations', 'Get-Vulnerabilities', 'Show-MachineActionsMenu'
    Write-Host "_______________________________________" -ForegroundColor Green
    Write-Host @"     
 __  __  _____   ______   _  __ _  _        
|  \/  ||  __ \ |  ____| | |/ /(_)| |      
| \  / || |  | || |__    | ' /  _ | |_    
| |\/| || |  | ||  __|   |  <  | || __|   
| |  | || |__| || |____  | . \ | || |_    
|_|  |_||_____/ |______| |_|\_\|_| \__|                                     
"@ -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host "MDE Kit's objective is to help automate and empower your investigation, detection, prevention, and response capabilities leveraging the MDE API."
Write-Host "Feel free to comment on the blog and/or connect with me on LinkedIn if you have any questions"
Write-Host "Learn more about this project at https://securityoccupied.com/2023/07/11/mde-kit-a-powershell-module-for-microsoft-defender-for-endpoint"
Write-Host "https://www.linkedin.com/in/jeffrey-michelmore/"
Write-Host "`r"
Write-Host "For detailed help with each of the functions of this module, type `"Get-Help <Insert function name>`""
Write-Host "Available function names can be found below."
Write-Host "`r"
$ExportedFunctions
Write-Host "=======================================" -ForegroundColor Yellow
}

Export-ModuleMember -Function 'Get-MdeKitHelp', 'Get-SecureConfigAssessment', 'Get-SoftwareInventoryAssessment', 'Get-NonCpeSoftwareInventoryAssessment', 'Get-SoftwareVulnerabilitiesAssessment', 'Get-Machines', 'Get-Alerts', 'Get-AvInfo', 'Get-Recommendations', 'Get-Vulnerabilities', 'Show-MachineActionsMenu'
