#Plan: Gets a list over servers that supports Best Practice Analyzer (Server 2016 R2) through AD Computers
#Send each object or a specific object through the analyer 
#and report back results in a CSV file, all information!!!
#
# [x] Checks if the Hostname is resolveable, otherwise its skipped
# [x] Check whats the operatinsystem version is, must be 2016 or higher
# [x] Then Grabs all the features installed
# [X] Runs BPA through each feature and Saves the logs in $sourcepath Folder
# [x] Timestamps and logging of the results and summery
# [x] Check if BPA has been ran before
# [] get IP from get-adcomputer if the host does not response from hostname 
# [x] get-windowsfeature check if its allowed and return a warning if Ip cannot beused
    <#
    Get-WindowsFeature : The WinRM client cannot process the request. Default authentication may be used with an IP address under the following conditions: the transport i
    s HTTPS or the destination is in the TrustedHosts list, and explicit credentials are provided. Use winrm.cmd to configure TrustedHosts. Note that computers in the Trus
    tedHosts list might not be authenticated. For more information on how to set TrustedHosts run the following command: winrm help config.
    #>
# [x] Checks Results for Severity errors
# [x] Seperate Folder for each date
# [x] Compile Severity results to a csv
# [x] New and updated results from priority list
# [] Open in HTML
# [x] Wide screening test
#
# Pass through CSV file with Server names. names get checked if they are 2016 or never, if it is not, it is skipped
# Win Server 2012 supports BPA too, but needs to be installed manually
#
# Laget av H�vard Sigvartsen
# Ideen var Richard Lian
# Olav f�r kredit for å ikke ta godteriet fra resten av gjengen (Inside joke som Richard ikke komme til � huske)


#prerequisite
$time = (Get-Date).ToString("yyyy-MM-dd")
$BPAScan = 0
$sourcepath = "C:\ATEA\BPA4000\$time" # Source Path, duh....
$SummaryPathCSV = "$sourcepath\$Time-BPA_summary_Results.csv" # Sumamry Results of getting the BPA
$StatusSummaryTextPath = "$sourcepath\$Time-BPA_summary_Results.txt" # Summary Results of running the script
if (test-path -path $sourcepath) {} else { New-Item -ItemType "directory" -Path "$sourcepath" } # Test if the source path exists, if not make it, files will go there
if (test-path -path $sourcepath\$Time-BPA-Priority.csv) {remove-Item -path $sourcepath\$Time-BPA-Priority.csv} # Deletes the old priority file, so it doesn't "add" more errors at the end of the script

#TimeStamp
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

# Main Meny
clear-host
$UserInputValid = 0
While ($UserInputValid -eq 0) {
    # Should the user mistype something, they can try again without going through the meny
    Write-Output "NUM NUM NUM i like CSV file's!"
    Write-Output "This program should be ran from a Relay/Managment Server"
    Write-Output "This program will scan all roles thats currently running the server and create logs in the $sourcepath Folder"
    Write-Output "Win Server 2016 has BPA (Microsoft Best Practice Analyzer) built inn, it supports 2012 too, but BPA needs to be installed manually"
    Write-Output ""
    Write-Output "1. Get results from a specific Server through manual Input (Single)"
    Write-Output "2. Get results Through from a specific Server CSV)" 
    Write-Output "3. Scan all roles installed and get results from a specific Server through manual input (Single)"
    Write-Output "4. Scan all roles installed and get results from a specific Server through CSV"
    Write-Output ""
    Write-Output "IMPORTANT: The Server(s) needs to allow PowerShell remotely from the User that is running this script"
    Write-Output "Results are stored in C:\ATEA\BPA4000"
    Write-Output ""
    $UserChoice = Read-Host "What would you like to do?"
    Switch ($UserChoice) {
        # Prevents invalid inputs, and let the user retry
        1 { $UserInputValid = 1; Break }   
        2 { $UserInputValid = 1; Break }
        3 { $UserInputValid = 1; Break }
        4 { $UserInputValid = 1; Break }
        default { $UserInputValid = 0; Clear-Host Write-Output; "That was not a valid input"; Write-Output "" }
    }
}

# Validating user Input 
$UserInputValid = 0
While ($UserInputValid -eq 0) {
    # Should the user mistype something, they can try again without going through the meny
    If ($UserChoice -eq 1) {
        # Option 1 ###########################
        $ServerName = Read-Host "Input the Server Name"
        if (Test-Connection $ServerName -Quiet -count 1 -ErrorAction stop) {
            # redundant, but ensures that the server is indeed valid before continuing
            # online ===
            $UserInputValid = 1
        }
        else {
            # offline ===
        
            Write-Output "$ServerName Is Either Offline, not found or invalid"
        } 
    }
    ElseIf ($UserChoice -eq 2) {
        # Option 2 ###########################
        $UserSourceCVSPath = Read-Host "Input the CSV file Path (No Quotes!!!)"
        if (test-path -path "$UserSourceCVSPath" -Include "*.csv") {
            # File Path valid
            $ServerName = get-content $UserSourceCVSPath
            $UserInputValid = 1
        }
        else {
            # File Path INVALID
            Write-Output "File Path Invalid or Wrong File property"
        }
    }
    ElseIf ($UserChoice -eq 3) {
        # Option 3 ###########################
        $ServerName = Read-Host "Input the Server Name"
        if (Test-Connection $ServerName -Quiet -count 1 -ErrorAction stop) {
            # redundant, but ensures that the server is indeed valid before continuing
            # online === 
            $BPAScan = 1
            $UserInputValid = 1
        }
        else {
            # offline ===
            Write-Output "$ServerName Is Either Offline, not found or invalid"
        } 
    }
    ElseIf ($UserChoice -eq 4) {
        # Option 4 ###########################
        $UserSourceCVSPath = Read-Host "Input the CSV file Path (No Quotes!!!)"
        if (test-path -path "$UserSourceCVSPath" -Include "*.csv") {
            # File Path VALID
            $BPAScan = 1
            $ServerName = get-content $UserSourceCVSPath
            $UserInputValid = 1
        }
        else {
            # File Path INVALID
            Write-Output "File Path Invalid or Wrong File property"
        }
    }
}


#The important bit (new and hopefully improved)
write-output ""
foreach ($ServerName in $ServerName) {
    # Validating that the server can be reached  
    if (Test-Connection -Computername $ServerName -Quiet -count 1 ) {
        # If its online
        Write-Output "$(Get-TimeStamp) $ServerName is online" | Out-File $StatusSummaryTextPath -Append
        #Check the Windows Version, 2008 is probably the oldest one and realistic to meet, anything newer than 2012 has comes with it pre installed
        $ServerTest = Get-WmiObject -class Win32_OperatingSystem -ComputerName $ServerName | select-object Caption
        Write-Output "$(Get-TimeStamp) Checking Windows Version on $ServerName" | Out-File $StatusSummaryTextPath -Append
        Write-Output "$(Get-TimeStamp) Checking Windows Version on $ServerName"
        if ($ServerTest -notlike "*2008*" -and "*2012*") {
            #Grabs all the roles installed
            Write-Output "$(Get-TimeStamp) Passed, current version is $($ServerTest.Caption)" | Out-File $StatusSummaryTextPath -Append
            Write-Output "$(Get-TimeStamp) Passed, current version is $($ServerTest.Caption)"
            try  # foreach loop, try block should be inside, but if the Get-WindowsFeatures doesnt work on IP anyway, then there is no point running on that server and should be skipped
            {$WindowsFeatures = Get-WindowsFeature -ComputerName $ServerName -ErrorAction stop | Where-Object { $_.Installed -and $_.FeatureType -eq "Role" } | Select-Object Name, Installstate
            foreach ($WindowsFeatures in $WindowsFeatures) {
                # For each feature
                $BPAResultPath = "$sourcepath\$Time-$ServerName-$($WindowsFeatures.name)-BPAResults.csv" # Path for saving 
                Write-Output "$(Get-TimeStamp) Currently Checking: $($WindowsFeatures.name)" | Out-File $StatusSummaryTextPath -Append
                write-output "$(Get-TimeStamp) Currently Checking: $($WindowsFeatures.name)"
                switch ($($WindowsFeatures.Name)) {
                    # Grabs BPA results on computername remotely and post the results locally
                    # if what is found matches the list, it will be added as a Module ID on the Invoke-BPAmodel Command
                    # I Tried with parameterized ModelID, but it needs to be passed due Invoke-Command, using PSSession will solve and complicate this, but im lazy.
                    AD-Certificate { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/CertificateServices" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/CertificateServices" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/CertificateServices" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    } 
                    AD-Domain-Services { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/DirectoryServices" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/DirectoryServices" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/DirectoryServices" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    ADFS-Federation { Write-Output "$(Get-TimeStamp) $WindowsFeatures Was not found mentioned BPA Documentation or during testing at time" | Out-File $StatusSummaryTextPath -Append } 
                    ADLDS {
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/LightweightDirectoryServices" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/LightweightDirectoryServices" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/LightweightDirectoryServices" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    ADRMS {
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/RightsManagementServices" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/RightsManagementServices" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/RightsManagementServices" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    DeviceHealthAttestationService { Write-Output "$(Get-TimeStamp) $WindowsFeatures Was not found mentioned BPA Documentation or during testing at time" | Out-File $StatusSummaryTextPath -Append }
                    DHCP {
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/DHCPServer" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/DHCPServer" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/DHCPServer" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    DNS { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/DNSServer" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/DNSServer" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/DNSServer" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }                                               
                    Fax { Write-Output "$(Get-TimeStamp) $WindowsFeatures Was not found mentioned BPA Documentation or during testing at time" | Out-File $StatusSummaryTextPath -Append }
                    FileAndStorage-Services { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/FileServices" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/FileServices" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/FileServices" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    HostGuardianServiceRole { Write-Output "$(Get-TimeStamp) $WindowsFeatures Was not found mentioned BPA Documentation or during testing at time" | Out-File $StatusSummaryTextPath -Append }
                    Hyper-V {
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/Hyper-V" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/Hyper-V" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/Hyper-V" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    NPAS {
                        # Network Policy and Access Services
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/NPAS" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/NPAS" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/NPAS" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    } 
                    Print-Services { Write-Output "$(Get-TimeStamp) $WindowsFeatures Was not found mentioned BPA Documentation or during testing at time" | Out-File $StatusSummaryTextPath -Append }
                    RemoteAccess { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/RemoteAccessServer" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/RemoteAccessServer" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/RemoteAccessServer" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    Remote-Desktop-Services { Write-Output "$(Get-TimeStamp) $WindowsFeatures Was not found mentioned BPA Documentation or during testing at time" | Out-File $StatusSummaryTextPath -Append }
                    VolumeActivation { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/VolumeActivation" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/VolumeActivation" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/VolumeActivation" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    Web-Server { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/WebServer" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/WebServer" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/WebServer" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    WDS { Write-Output "$(Get-TimeStamp) $WindowsFeatures Was not found mentioned BPA Documentation or during testing at time" | Out-File $StatusSummaryTextPath -Append }
                    UpdateServices { 
                        If ($BPAScan -eq 1) { Invoke-Command -ComputerName $ServerName -ScriptBlock { Invoke-BPAModel -modelId "Microsoft/Windows/UpdateServices" } | export-CSV $SummaryPathCSV -Append } else {}
                        Invoke-Command -ComputerName $ServerName -ScriptBlock {if ((Get-BpaModel -ModelId "Microsoft/Windows/UpdateServices" ).LastScanTime -eq "Never") 
                            {Write-Output "BPA has not been run on this Server"} else {Get-BpaModel -modelId "Microsoft/Windows/UpdateServices" | Get-BPAResult}} | export-CSV $BPAResultPath 
                    }
                    # should it find anything thats not in the list
                    Default { write-output "$(Get-TimeStamp) $($WindowsFeatures.name) was not found on the list" | export-CSV $SummaryPathCSV -Append; write-output "$(Get-TimeStamp) $($WindowsFeatures.name) was not found on the list" }
                } # Switch block
                # Severity "error" gets compiled into a csv file 
                write-output "$(Get-TimeStamp) Checking for Errors reported from $($WindowsFeatures.name)"
                write-output "$(Get-TimeStamp) Checking for Errors reported from $($WindowsFeatures.name)" | Out-File $StatusSummaryTextPath -Append
                 if (test-path -path $BPAResultPath) { # Check if BPA was ran on the server,
                    $search = (Get-Content -path $BPAResultPath | Select-String -Pattern "Length").Matches.Success
                    if ($search) { # If the Content like "length" is found, it means it failed, because text to CSV makes no sense and "Length is not used in the result"
                        write-output "$(Get-TimeStamp) BPA Scan has not been ran on this server before"
                        write-output "$(Get-TimeStamp) BPA Scan has not been ran on this server before" | Out-File $StatusSummaryTextPath -Append
                    } else {
                        # check if there is content like "Error" and save it to a seperate CSV
                        $search = (Get-Content -path $BPAResultPath | Select-String -Pattern "Error").Matches.Success
                        if ($search) {
                            Import-CSV -path $BPAResultPath | Select-Object ComputerName, Severity, ModelId | Where-Object Severity -eq Error | export-CSV "$sourcepath\$Time-BPA-Priority.csv" -Append
                            # "1 or more" is kinda lazy, but get gets the point accross
                            Write-Output "$(Get-TimeStamp) 1 or more error was found in $ServerName at $($WindowsFeatures.name)" | Out-File $StatusSummaryTextPath -Append 
                            write-host "$(Get-TimeStamp) 1 or more error was found in $ServerName at $($WindowsFeatures.name)" -ForegroundColor White -BackgroundColor red 
                        } else {
                            write-output "$(Get-TimeStamp) None found"
                            write-output "$(Get-TimeStamp) None found" | Out-File $StatusSummaryTextPath -Append
                        }
                    }
                }
            } # foreach loop, try block should be inside, but if the Get-WindowsFeatures doesnt work on IP anyway, then there is no point running on that server and should be skipped
            } # note to self: From try block... wayyy too many brackets... is this how it feels to work at the dentist?
            Catch [Exception] {write-output "$(Get-TimeStamp) Default authentication may be used with an IP address under the following condition: destination is in the TrustedHosts" | Out-file $StatusSummaryTextPath -Append;
                                write-output "$(Get-TimeStamp) $ServerName Does not support IP Authentication to access Windows Features, check Summary for more information"}
            Catch {write-output "$(Get-TimeStamp) A different error happened, $_" | Out-file $StatusSummaryTextPath -Append}            
        } else {
            #if the server is older than 2016
            Write-Output "$(Get-TimeStamp) Server $ServerName is not compatible With BPA" | Out-File $StatusSummaryTextPath -Append
            Write-Output "$(Get-TimeStamp) Server $ServerName is not compatible With BPA" 
        }
        Write-Output "" | Out-File $StatusSummaryTextPath -Append
    } else {
        # If there is no connection 
        write-output "$(Get-TimeStamp) $ServerName's IP or Hostname invalid, or there was no response" | Out-File $StatusSummaryTextPath -Append
        Write-Output "" | Out-File $StatusSummaryTextPath -Append
        write-output "$(Get-TimeStamp) $ServerName's IP or Hostname invalid, or there was no response"
    }
    Write-Output "$(Get-TimeStamp) Finished" | Out-File $StatusSummaryTextPath -Append 
    Write-Output "$(Get-TimeStamp) Finished" 
    Write-Output "" #Spacer, adds +100 in look
}

#Notifier 
if (test-path -path $sourcepath\$Time-BPA-Priority.csv) {
    # If it exists
    # get the count, and show the path to the list of the errors that needed to be checked
    $NumberOfErrors = (Import-CSV -path $sourcepath\$Time-BPA-Priority.csv |  Measure-Object | select-object).count
    if ($NumberOfErrors -gt 0) {
        write-host "There are Currently $NumberOfErrors, Check $sourcepath\$Time-BPA-Priority.csv to view what servers" -ForegroundColor White -BackgroundColor red 
    } else {
        write-output "$(Get-TimeStamp) There was no severity with the label errors during this scan"
    }
}

# Finish
write-output "The Scan is completed"
Pause
Start-Process $sourcepath
