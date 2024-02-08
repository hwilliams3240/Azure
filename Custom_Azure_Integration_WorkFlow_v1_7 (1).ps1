###### AzureAD Enforcement Actions - Change Group & Revoke Sessions From WorkFlow
###### Ross Penny 11th Oct 2023
###### Chris Moran 7 August 2023
###### 1.7 Improved error handling
###### 1.6 Added debug logging
###### 1.2 Added inputs to use Workflow Varible
###### 1.3 Added AD lookup to grab email from UPN
###### 1.4 Added code to update Identity Detection
###### 1.5 Updated Notes
###### 1.6 Added logging...


######################
###### Prereq's ######
######################

        ###### Setup

        #1. Create a new app registration in the Azure portal. Note the client ID. 
        #2. Generate Secret. Note the secret. 
        #3. Add user.readwrite.all, group.readwrite.all, directory.readwrite.all permissions and grant admin approval. 
        #4. Create a new group in AzureAD that you will use to apply a more restritve conditional access policy. This script will move the user into that group following a detection. 

   #### Log Output ####
    # Stop if running
    $ErrorActionPreference="SilentlyContinue"
    Stop-Transcript | out-null
    
    # Start
    $ErrorActionPreference = "Continue"
    Start-Transcript -path "C:\cs_script_output.txt" | out-null

        function parse ([string]$Inputs) {
    	$Param = if ($Inputs) { try { $Inputs | ConvertFrom-Json } catch { throw $_ }} 		   		else { [PSCustomObject]@{} }
    	switch ($Param) {
        	{ !$_.id } { throw "Missing required parameter 'Name'." }
            { !$_.Name } { throw "Missing required parameter 'Name'." }
    	}
    	$param
		}
		$param = parse $args[0]
        $name = $Param.name
        $id = $Param.id 
        $userFromDetection = "$id" 
        $resttimeout = "10" 

        ###### What customer would add to the custom HTTP call/FaaS function
        $groupID = "" ### This is the group we want to move the user into in AzureAD
        $clientid = "" ### ClientID for app registration generated generated above
        $clientSecret = "" ### ClientSecret generated above
        $tenantId = "" ### AzureAD tenant ID (portal.azure.com -> Azure Active Directory -> Top of Landing Page)


################################
##### Running the Workflow #####
################################

write-host "Info from RTR is:`n$id`n$name`n$userFromDetection"

if (-not($groupID -or $clientid -or $clientSecret -or $tenantId)) {
    Write-Host "Group, Client ID, Secret or tenant ID is not set..."
    throw "Group, Client ID, Secret or tenant ID is not set..."
}
write-host "Info from Script preqreqs is:`nGroupID: $groupID`nClientID: $clientid`nClientSecret: 'DEFINED'`nTenantID: $tenantId"


        ##### STEP 1: Get an OAuth Token for AzureAD #####

        $body = @{
            'client_id'     = $clientid
            'client_secret' = $clientSecret
            'grant_type'    = "client_credentials"
            'scope' = ".default"
        }

        $AuthZURL= "https://login.microsoftonline.com/" + "$tenantId" + "/oauth2/v2.0/token"
        write-host "Making call to get token, URL is $AuthZURL"
        try {
        $global:AuthZToken = Invoke-RestMethod -Method post -Uri $AuthZURL -Body $body -timeout $resttimeout
        }
        catch {
            $lasterror = $error[0].Exception | Select-Object Message
            Write-Host "cannot get token, error is:`n$lasterror"
            throw "Stopping, see error above."
        }

        $global:headers = @{ "Authorization" = "Bearer $($AuthZToken.access_token)"; "Content-Type" = "application/json" } ### Parsing access_token to a variable we can use as a header for subsequent calls. 
        write-host "Got Token, header is set."


##### STEP 2: Get the AzureAD oject ID for the user #####

        $getUserIdUrl = "https://graph.microsoft.com/v1.0/users/" + ($userFromDetection)
        write-host "Trying to get Azure user id...url is`n$getUserIdUrl"

        try {
        $global:getUserId = Invoke-RestMethod -Method Get -Uri $getUserIdUrl -header $headers -timeout $resttimeout
        }
        catch{
            $lasterror = $error[0].Exception | Select-Object Message
            write-host "cannot get user id, error is:`n$lasterror"
            throw "Stopping, see error above."
        }

        if ($getUserId) {
            $azureId = $getUserId.id
  		if ($azureId) {
            $userURL = "https://graph.microsoft.com/v1.0/directoryObjects/" + $azureId ### Setting a URL for the user profile which is required in the group modification step
            } 
              else {
                throw "Failed to get User ID..."
                   } 
}
            
            $userURL = "https://graph.microsoft.com/v1.0/directoryObjects/" + $azureId ### Setting a URL for the user profile which is required in the group modification step
            
        ### Revoke the Users AzureAD sessions

        $revokeSessionURL = "https://graph.microsoft.com/v1.0/users/" + $azureId + "/revokeSignInSessions"
        write-host "Trying to revoke sessions...URL is `n$revokeSessionURL"

        try {
        $global:RevokeSessionRequest = Invoke-RestMethod -Method POST -Uri $revokeSessionURL -header $headers -timeout $resttimeout
        }
        catch {
            $lasterror = $error[0].Exception | Select-Object Message
            write-host "cannot revoke sessions, error is:`n$lasterror"
            throw "Stopping, see error above."
        }
        
        if ($RevokeSessionRequest) {

            if ($RevokeSessionRequest.value -eq $true) {
            
            $RevokeUserTokenStatus = "Successfully revoked user sessions"
            }
            else {
                $RevokeUserTokenStatus = "Failed to revoke sessions"  
            }
        }
        else {
                $RevokeUserTokenStatus = "Failed to get User ID" 
        }



        ### Change the user group 
        $changeGroupURL = "https://graph.microsoft.com/v1.0/groups/" + $groupID + "/members/`$ref"
        write-host "Trying to change user group...URL is `n$changeGroupURL"

        $postBody = @{
            "@odata.id" = $UserURL
        } | ConvertTo-Json

        try {
        $global:changeGroupRequest = Invoke-RestMethod -Method POST -body $postBody -Uri $changeGroupURL -header $headers -timeout $resttimeout 
        $AddUsertoGroupStatus = "User Successfully Added to Group"
        }
        catch {
                if ($_.Exception.Response.StatusCode.value__ -eq "400") {
                    $AddUsertoGroupStatus = "User is already in the Group"
                }
                else {
                $AddUsertoGroupStatus = "Failed to put user in Group"
                $lasterror = $error[0].Exception | Select-Object Message
                write-host "cannot change group, error is:`n$lasterror"
                }
        }

        write-host "Script Completed Run:`nAddUsertoGroupStatus: $AddUsertoGroupStatus`nRevokeUserTokenStatus: $RevokeUserTokenStatus"


    
######Create Output to update Identity Detection

                       
        $Out = [PSCustomObject]@{
        Name = "$name" 
        Id = "$id" 
        RevokeUserTokenStatus = "$RevokeUserTokenStatus"
        AddusertoGroupStatus =  "$AddUsertoGroupStatus"
        }
        
        $Out | ConvertTo-Json -Compress 


Stop-Transcript | out-null