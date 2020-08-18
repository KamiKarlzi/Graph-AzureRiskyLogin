# Azure AD OAuth Application Token for Graph API
# Get OAuth token for a AAD Application (returned as $token)

# Azure Application (client) ID, tenant ID and secret
$clientId = ""
$tenantId = ""
$clientSecret = ""

# Construct URI
$Uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Construct Body
$Body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

# Get OAuth 2.0 Token
$tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing

# Access Token
$token = ($tokenRequest.Content | ConvertFrom-Json).access_token

# ----------------------------------------------------------------------------------------------------------------------------------------------
# Graph API call in PowerShell using obtained OAuth token
# Results limited to 1000 records

Import-Module Emailimo

$HostName = ($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN).ToUpper()
$User = ($env:USERNAME).ToUpper()

$MailFrom = ""
$MailTo = ""
$MailSubject = "Azure Risky Logins"
$SMTPRelay = "" # Onsite SMTP Relay
$SMTPPort = 25
$LoginDomain = "" # Your domain e.g. @whatever.com
$HomeCountryCode = "" # Country Code e.g. GB for Great Britain
$IPsToIgnore = @("") # Array of IPs to not report on, each IP in seperate quotes then seperated by comma  

if ((get-date).DayOfWeek -eq 'Monday') {
    $DaysBack = 3
} 
else {
    $DaysBack = 1
}
$TempDate = (Get-Date).AddDays(-$DaysBack)
$StartDate = $TempDate.tostring("yyyy-MM-dd")

# Specify the URI to call and method
$Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime gt $StartDate and status/errorCode eq 0"
$method = "GET"

# Run Graph API query 
$Query = Invoke-RestMethod -Method $method -Uri $Uri -ContentType "application/json" -Headers @{Authorization = "Bearer $token"} -ErrorAction Stop -UseBasicParsing
$Values = $Query.Value

# Handle Throttling
while ($Query."@odata.nextLink") {
    $Uri = $Query."@odata.nextLink"
    try {
        $Query = Invoke-RestMethod -Method $method -Uri $Uri -ContentType "application/json" -Headers @{Authorization = "Bearer $token"} -ErrorAction Stop -UseBasicParsing
        $Values += $Query.Value
    }
    catch {
        Start-Sleep -Seconds 30
    }
}

$RiskyLogins = @()
foreach ($Login in $Values) { 
    if ($Login.Location.countryOrRegion -ne $HomeCountryCode -and $Login.Location.countryOrRegion -ne $null -and $Login.deviceDetail.isManaged -ne $true -and $Login.userPrincipalName.split('@')[1] -eq $LoginDomain -and $Login.ipAddress -notin $IPsToIgnore) {
        $RiskyLogin = New-Object System.Object
        $RiskyLogin | Add-Member -Type NoteProperty -Name TimeStamp -Value $Login.createdDateTime.replace('T',' ').split('.')[0]
        $RiskyLogin | Add-Member -Type NoteProperty -Name UserID -Value $Login.UserPrincipalName
        $RiskyLogin | Add-Member -Type NoteProperty -Name IP -Value $Login.ipAddress
        $RiskyLogin | Add-Member -Type NoteProperty -Name OS -Value $Login.deviceDetail.OperatingSystem
        $RiskyLogin | Add-Member -Type NoteProperty -Name Application -Value $Login.deviceDetail.Browser
        $RiskyLogin | Add-Member -Type NoteProperty -Name City -Value $Login.Location.City 
        $RiskyLogin | Add-Member -Type NoteProperty -Name Region -Value $Login.Location.State
        $RiskyLogin | Add-Member -Type NoteProperty -Name Country -Value $Login.Location.countryOrRegion
        $RiskyLogins += $RiskyLogin
    }
}

if ($RiskyLogins) {
    Email {
        EmailHeader {
            EmailFrom -Address $MailFrom
            EmailTo -Addresses $MailTo
            EmailServer -Server $SMTPRelay -Port $SMTPPort
            EmailSubject -Subject $MailSubject
        }
        EmailBody -FontFamily 'Segoe UI' -Size 15 {
            EmailText -Text $MailSubject -FontWeight Bold
            EmailText -LineBreak
            EmailTable -DataTable $RiskyLogins -HideFooter
        } 
        EmailText -LineBreak
        EmailTextBox -FontSize 8 -Color Gray { "Email Sent From: $HostName By: $User" }
    }
}
