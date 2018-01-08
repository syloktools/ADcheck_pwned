$borg = @"
    ___________
   /-/_"/-/_/-/|   - - - - - ----  ______
  /"-/-_"/-_//||    - - - - ----  (_   __) .-""""-.
 /__________/|/|     - - - - ----   ) (___/        '.
 |"|_'='-]:+|/||    -- - - -- --   (   ___          :
 |-+-|.|_'-"||//    - - - -------  _) (__ \        .'
 |[".[:!+-'=|//     - - ------ -- (______) '-....-'
 |='!+|-:]|-|/
  ----------
  
"@

#Check AD for valid email address

function Get-EmailAddress
{
    [CmdletBinding()]
    param
    (
        [string[]]$EmailAddress
    )
    
    process
    {       
        foreach ($address in $EmailAddress)
        {
            if(Get-ADObject -Properties mail, proxyAddresses -Filter "mail -like '*$address*' -or proxyAddresses -like '*$address*'")
            {"$address" | Out-File -FilePath $output_path -Append}
            Else{}
            
        }
        
    }
}

#Array to store results and sets custom objects. 
$haveibeenpwnedResults = @()

#Inputs to script
$path_to_file = Read-Host -Prompt 'Input path to text file of compromised email addresses'

#valid emails are appended to this file
$output_path = Read-Host -Prompt 'Input path to place the list of valid email addresses, for example: c:\scripts\validemails.txt... '  

#Location of results
$rootpath = $output_path | split-path -parent   

#Querying ActiveDirectory against list of email addresses.
Write-Host 'Querying Active Directory, this could take a moment....   '
$EmailAddress = Get-Content -Path $path_to_file  
Get-EmailAddress $EmailAddress

#API call to haveibeenpwned below
$ValidAddresses = Get-Content -Path $output_path  

Write-Host "Neural Network Activating....."
Write-Host 'Querying haveibeenpwned.com for additional information, please wait....   '

foreach ($address in $ValidAddresses)
{
    try
    {
    $url = "https://haveibeenpwned.com/api/v2/breachedaccount/$address"
    $outputjson = "$rootpath\$address.json"
    Invoke-RestMethod -Uri $url -Outfile $outputjson
    $jsonresults = (Get-Content $outputjson -Raw | ConvertFrom-Json) | Select Name,Domain,BreachDate,ModifiedDate,Description
        foreach($results in $jsonresults)
        {
            $haveibeenpwned = New-Object psobject
            $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Email Address" -Value $address
            $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Name" -Value $results.Name 
            $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Domain" -Value $results.Domain
            $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Breach Date" -Value $results.BreachDate
            $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Modified Date" -Value $results.ModifiedDate
            $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Description" -Value $results.Description
            $haveibeenpwnedResults += $haveibeenpwned
            
        }
    Remove-Item -path "$rootpath\$address.json"  #cleans up created json file.
    }
    catch
    {
    $haveibeenpwned = New-Object psobject
    $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Email Address" -Value ($address + " has not been pwned")
    $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Name" -value $null
    $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Domain" -value $null
    $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Breach Date" -value $null
    $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Modified Date" -value $null
    $haveibeenpwned | Add-Member -MemberType NoteProperty -Name "Description" -value $null
    $haveibeenpwnedResults += $haveibeenpwned
    }
     
    sleep -m 1505
}
    
        

$outputfilename = $(get-date -f yyyyMMdd) + "_" + $env:USERNAME + "_" + "pwnedReport"
$haveibeenpwnedResults | export-csv $rootpath\$outputfilename.csv -encoding ASCII -NoTypeInformation
Invoke-Item -path "$rootpath\$outputfilename.csv"
Write-Host "CSV files have been assimilated."
write-host $borg

