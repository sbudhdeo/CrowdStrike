<#
		Title: CrowdStrike Unmanaged Asset Report Generator
		Created: 2023-09-18
		Author: Samir Budhdeo
		Version 1.2
	
		This PowerShell script is designed to generate a comprehensive report of unmanaged assets using the 
		CrowdStrike Falcon API. The report includes information such as hostnames, IP addresses, last seen 
		timestamps, system manufacturers, and discoverer platform names.
				
		Features:

		Module Dependency Check: The script begins by checking for the presence of required PowerShell 
		modules, PSFalcon and PSWriteHTML. If any of these modules are missing, the script offers to 
		install them automatically.

		Authentication: It securely obtains an access token from CrowdStrike by providing API credentials 
		(Client ID and Client Secret) and handles the authorization required for API requests.

		Data Retrieval: The script utilizes the access token to make API requests to CrowdStrike to 
		retrieve unmanaged asset data based on defined filter criteria.

		Data Transformation: It processes the retrieved data, including filtering out certain IP ranges, 
		formatting dates, and converting array data in the "discoverer_platform_names" column into a 
		comma-separated string.

		Data Presentation: The script outputs the processed data as a formatted table to the console, 
		making it easily viewable during script execution.  Comment it out if you don't want it, lined
		123 and 126.

		CSV Export: It exports the processed data to a CSV file with a filename containing the report 
		name and the current date.

		Dynamic HTML Report: The script generates a dynamic HTML report from the CSV data, ensuring 
		that it can be easily shared and viewed in a web browser. The HTML report provides a 
		user-friendly presentation of the asset information.

		Feedback: The script provides feedback to the user by displaying the paths where the CSV and 
		HTML reports are saved.

		Prerequisites:

			PowerShell modules PSFalcon and PSWriteHTML must be installed. The script offers to install 
			them if they are missing.
			API credentials (Client ID and Client Secret) for CrowdStrike Falcon.
			A valid configuration file (CrowdStrikeConfig.json) containing additional configuration details.

		Usage:

			Ensure that the required modules are installed.
			Update the API credentials in the script ($ClientId and $ClientSecret).
			Customize the filter criteria to suit your requirements.
			Execute the script to generate the report.
#>

# Define all required modules
$modules = 'PSFalcon', 'PSWriteHTML'
$installed = @((Get-Module $modules -ListAvailable).Name | Select-Object -Unique)

# Infer which ones *aren't* installed.
$notInstalled = Compare-Object $modules $installed -PassThru
if ($notInstalled) { # At least one module is missing.
  $promptText = @"
  The following modules aren't currently installed:
        $notInstalled
  Would you like to install them now?
"@
  $choice = $host.UI.PromptForChoice('Missing modules', $promptText, ('&Yes', '&No'), 0)
 if ($choice -ne 0) { Write-Warning 'Aborted.'; exit 1 }
  # Install the missing modules now.
  Install-Module -Scope CurrentUser $notInstalled
}

# Define your API credentials
$ClientId = ""
$ClientSecret = ""
$OAuthTokenUrl = "https://api.crowdstrike.com/oauth2/token"

$ReportName = "csUnmanagedAssets"
$HTMLReportTitle = "CrowdStrike Unmanaged Asset Report"
$Date = Get-Date -format yyyyMMdd
$scriptRoot = "C:\Scripts\Crowdstrike\"
$htmlFile = $scriptRoot + $ReportName + "_" + $Date + ".html"
$csvFile = $scriptRoot + $ReportName + "_" + $Date + ".csv" # Define the CSV file path

# Define the body of the request to obtain the access token
$body = @{
    "client_id"     = $ClientId
    "client_secret" = $ClientSecret
    "scope"         = "oauth2:write"
    "grant_type"    = "client_credentials"
}

# Send the request to obtain the access token
$response = Invoke-RestMethod -Uri $OAuthTokenUrl -Method POST -Body $body

# Extract the access token from the response
$accessToken = $response.access_token

# Set the Authorization header with the access token
$headers = @{
    "Authorization" = "Bearer $accessToken"
}

# Load the configuration from the JSON file
$configuration = Get-Content -Raw -Path "CrowdStrikeConfig.json" | ConvertFrom-Json

# Get the access token
$token = Request-FalconToken -ClientId $configuration.ClientId -ClientSecret $configuration.ClientSecret

# Define the filter criteria
$Filter = "entity_type:'unmanaged'"

# Fetch FalconAsset data
$HostData = Get-FalconAsset -Filter $Filter -Detailed

# Select the desired properties
$SelectedProperties = $HostData | Where-Object { ($_.current_local_ip -notlike '169.254*') -and ($_.current_local_ip -notlike '192.168*') } | Select-Object Hostname, current_local_ip, last_seen_timestamp, system_manufacturer, discoverer_platform_names

# Sort by hostname
$SortedData = $SelectedProperties | Sort-Object hostname

# Format the data as a table
#$FormattedTable = $SortedData | Format-Table -AutoSize

# Output the formatted table
#$FormattedTable

# Join the elements of the discoverer_platform_names array into a single string
# Convert the timestamp to yyyy-MM-dd format
$SortedData = $SortedData | ForEach-Object {
    $_.last_seen_timestamp = [datetime]::Parse($_.last_seen_timestamp).ToString('yyyy-MM-dd')
    $_.discoverer_platform_names = $_.discoverer_platform_names -join ', '
    $_
}

# Export the data to a CSV file
$SortedData | Export-Csv -Path $csvFile -NoTypeInformation

#---------------------------------------------------------------------------------
# Build Dynamic HTML from the CSV date
#---------------------------------------------------------------------------------
$MyDynTable = Import-CSV $csvFile
$MyDynTable | Sort-Object ({ $_."last_seen_timestamp"}) | Out-HtmlView -FilePath $htmlFile -PreventShowHTML

# Display a message indicating the CSV file path
Write-Host "CSV report saved to: $csvFile"

# Display a message indicating the HTML file path
Write-Host "HTML report saved to: $htmlFile"
