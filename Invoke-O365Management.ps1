#requires -version 4
#requires -runasadministrator

<#
.SYNOPSIS
  Allows user management in regards to mail and O365
 
.DESCRIPTION
  This script provides a simple CLI that guides various administrative tasks in regards
  to mail in a O365 environment, including new user creation, distribution group management,
  and UPN changes.
 
.OUTPUTS
  Outputs a log file in the current directory of the script.
 
.NOTES
  Version:        1.0
  Author:         teekayzed
  Creation Date:  08/28/2014
  Purpose/Change: Initial script development
  
  Version:        1.1
  Author:         teekayzed
  Creation Date:  08/29/2014
  Purpose/Change: Initial script debugging

  Version:        1.2
  Author:         teekayzed
  Creation Date:  09/02/2014
  Purpose/Change: Tweaked menu display for Add-DistroMember function
  
  Version:        1.3
  Author:         teekayzed
  Creation Date:  09/25/2014
  Purpose/Change: Bypassing of new user creation after gathering info fixed. Moved the new user values after input logging to the
                  new user creation function.  This way it wont get written to the logs if the user is not created.
  
  Version:        1.4
  Author:         teekayzed
  Creation Date:  11/24/2014
  Purpose/Change: Logging was no longer gathering new user information. Modified logging to ensure capturing of the randomly
                  created password. Changed the password prompt and logic to ensure that it would create a valid random
                  password if the first random generation failed to meet complexity.

  Version:        1.5
  Author:         teekayzed
  Creation Date:  01/13/2015
  Purpose/Change: Issues with UPN being lost as the user account is DirSync'd over time. Added additional logging, forced DirSync
                  after user creation, and mailbox creation.
  #>
 
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
 
#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"
 
#Dot Source required Function Libraries
. .\Logging_Functions.ps1
 
#----------------------------------------------------------[Declarations]----------------------------------------------------------
 
#Script Version
$sScriptVersion = "1.5"
 
#Log File Info
$sLogPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$scriptName = $MyInvocation.MyCommand.Name
$scriptName = $scriptName.TrimEnd(".ps1")
$sLogDate = get-date -f dd-MM-yyyy_HH_mm_ss
$sLogName = $scriptName + "_" + $sLogDate + ".log"
$sLogFile = $sLogPath + "\" + $sLogName
 
#-----------------------------------------------------------[Functions]------------------------------------------------------------
 

<# Function <FunctionName>{

  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "<description of what is going on>..."
  }
  
  Process{
    Try{
      <code goes here>
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Completed Successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
    }
  }
}
#>
Function Log-Start{
  <#
  .SYNOPSIS
    Creates log file

  .DESCRIPTION
    Creates log file with path and name that is passed. Checks if log file exists, and if it does deletes it and creates a new one.
    Once created, writes initial logging data

  .PARAMETER LogPath
    Mandatory. Path of where log is to be created. Example: C:\Windows\Temp

  .PARAMETER LogName
    Mandatory. Name of log file to be created. Example: Test_Script.log
      
  .PARAMETER ScriptVersion
    Mandatory. Version of the running script which will be written in the log. Example: 1.5

  .INPUTS
    Parameters above

  .OUTPUTS
    Log file created

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development

    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support

  .EXAMPLE
    Log-Start -LogPath "C:\Windows\Temp" -LogName "Test_Script.log" -ScriptVersion "1.5"
  #>
    
  [CmdletBinding()]
  
  Param (
    [Parameter(Mandatory=$true)][string]$LogPath, 
    [Parameter(Mandatory=$true)][string]$LogName, 
    [Parameter(Mandatory=$true)][string]$ScriptVersion
  )
  
  Process{
    $sFullPath = $LogPath + "\" + $LogName
    
    #Check if file exists and delete if it does
    If((Test-Path -Path $sFullPath)){
      Remove-Item -Path $sFullPath -Force
    }
    
    #Create file and start logging
    New-Item -Path $LogPath -Value $LogName -ItemType File
    
    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value ""
    Add-Content -Path $sFullPath -Value "Running script version [$ScriptVersion]."
    Add-Content -Path $sFullPath -Value ""
    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value ""
  
    #Write to screen for debug mode
    Write-Debug "***************************************************************************************************"
    Write-Debug "Started processing at [$([DateTime]::Now)]."
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
    Write-Debug "Running script version [$ScriptVersion]."
    Write-Debug ""
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
  }
}
Function Log-Write{
  <#
  .SYNOPSIS
    Writes to a log file

  .DESCRIPTION
    Appends a new line to the end of the specified log file
  
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
  
  .PARAMETER LineValue
    Mandatory. The string that you want to write to the log
      
  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development
  
    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support

  .EXAMPLE
    Log-Write -LogPath "C:\Windows\Temp\Test_Script.log" -LineValue "This is a new line which I am appending to the end of the log file."
  #>
  
  [CmdletBinding()]
  
  Param (
    [Parameter(Mandatory=$true)][string]$LogPath, 
    [Parameter(Mandatory=$true)][string]$LineValue
  )
  
  Process{
    Add-Content -Path $LogPath -Value $LineValue
  
    #Write to screen for debug mode
    Write-Debug $LineValue
  }
}
Function Log-Error{
  <#
  .SYNOPSIS
    Writes an error to a log file

  .DESCRIPTION
    Writes the passed error to a new line at the end of the specified log file
  
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
  
  .PARAMETER ErrorDesc
    Mandatory. The description of the error you want to pass (use $_.Exception)
  
  .PARAMETER ExitGracefully
    Mandatory. Boolean. If set to True, runs Log-Finish and then exits script

  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development
    
    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support. Added -ExitGracefully parameter functionality

  .EXAMPLE
    Log-Error -LogPath "C:\Windows\Temp\Test_Script.log" -ErrorDesc $_.Exception -ExitGracefully $True
  #>
  
  [CmdletBinding()]
  
  Param (
    [Parameter(Mandatory=$true)][string]$LogPath, 
    [Parameter(Mandatory=$true)][string]$ErrorDesc, 
    [Parameter(Mandatory=$true)][boolean]$ExitGracefully
  )
  
  Process{
    Add-Content -Path $LogPath -Value "Error: An error has occurred [$ErrorDesc]."
  
    #Write to screen for debug mode
    Write-Debug "Error: An error has occurred [$ErrorDesc]."
    
    #If $ExitGracefully = True then run Log-Finish and exit script
    If ($ExitGracefully -eq $True){
      Log-Finish -LogPath $LogPath
      Breaåk
    }
  }
}
Function Log-Finish{
  <#
  .SYNOPSIS
    Write closing logging data & exit

  .DESCRIPTION
    Writes finishing logging data to specified log and then exits the calling script
  
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write finishing data to. Example: C:\Windows\Temp\Test_Script.log

  .PARAMETER NoExit
    Optional. If this is set to True, then the function will not exit the calling script, so that further execution can occur
  
  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development
    
    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support
  
    Version:        1.2
    Author:         Luca Sturlese
    Creation Date:  01/08/12
    Purpose/Change: Added option to not exit calling script if required (via optional parameter)

  .EXAMPLE
    Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log"

.EXAMPLE
    Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log" -NoExit $True
  #>
  
  [CmdletBinding()]
  
  Param (
    [Parameter(Mandatory=$true)][string]$LogPath, 
    [Parameter(Mandatory=$false)][string]$NoExit
  )
  
  Process{
    Add-Content -Path $LogPath -Value ""
    Add-Content -Path $LogPath -Value "***************************************************************************************************"
    Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
    Add-Content -Path $LogPath -Value "***************************************************************************************************"
  
    #Write to screen for debug mode
    Write-Debug ""
    Write-Debug "***************************************************************************************************"
    Write-Debug "Finished processing at [$([DateTime]::Now)]."
    Write-Debug "***************************************************************************************************"
  
    #Exit calling script if NoExit has not been specified or is set to False
    If(!($NoExit) -or ($NoExit -eq $False)){
      Exit
    }    
  }
}
Function Log-Email{
  <#
  .SYNOPSIS
    Emails log file to list of recipients

  .DESCRIPTION
    Emails the contents of the specified log file to a list of recipients
  
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to email. Example: C:\Windows\Temp\Test_Script.log
  
  .PARAMETER EmailFrom
    Mandatory. The email addresses of who you want to send the email from. Example: "admin@9to5IT.com"

  .PARAMETER EmailTo
    Mandatory. The email addresses of where to send the email to. Seperate multiple emails by ",". Example: "admin@9to5IT.com, test@test.com"
  
  .PARAMETER EmailSubject
    Mandatory. The subject of the email you want to send. Example: "Cool Script - [" + (Get-Date).ToShortDateString() + "]"

  .INPUTS
    Parameters above

  .OUTPUTS
    Email sent to the list of addresses specified

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  05.10.12
    Purpose/Change: Initial function development

  .EXAMPLE
    Log-Email -LogPath "C:\Windows\Temp\Test_Script.log" -EmailFrom "admin@9to5IT.com" -EmailTo "admin@9to5IT.com, test@test.com" -EmailSubject "Cool Script - [" + (Get-Date).ToShortDateString() + "]"
  #>
  
  [CmdletBinding()]
  
  Param (
    [Parameter(Mandatory=$true)][string]$LogPath, 
    [Parameter(Mandatory=$true)][string]$EmailFrom, 
    [Parameter(Mandatory=$true)][string]$EmailTo, 
    [Parameter(Mandatory=$true)][string]$EmailSubject
  )
  
  Process{
    Try{
      $sBody = (Get-Content $LogPath | out-string)
      
      #Create SMTP object and send email
      $sSmtpServer = "smtp.yourserver"
      $oSmtp = new-object Net.Mail.SmtpClient($sSmtpServer)
      $oSmtp.Send($EmailFrom, $EmailTo, $EmailSubject, $sBody)
      Exit 0
    }
    
    Catch{
      Exit 1
    } 
  }
}
Function Display-MainMenu {
  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Starting main menu function..."
  }
  
  Process{
    Try{
          $menuDisplay += "`r`n"
          $menuDisplay += "=====================================`r`n"
          $menuDisplay += "              Main Menu              `r`n"
          $menuDisplay += "=====================================`r`n"
          $menuDisplay += "[0] User Management`r`n"
          $menuDisplay += "[1] Distribution Group Management`r`n"
          $menuDisplay += "`r`n[50] Force a DirSync`r`n`r`n"
          $menuDisplay += "[99] EXIT `r`n"
          Write-Host $menuDisplay
          $menuSelection = Read-Host "Please enter your selection "
          $menuSelection = $menuSelection.Trim()

          switch ($menuSelection) {
            0 {
                Log-Write -LogPath $sLogFile -LineValue "Entering user menu."
                Display-UserMenu
                Break
              }
            1 {
                Log-Write -LogPath $sLogFile -LineValue "Entering distribution group menu."
                Display-DistroMenu
                Break
              }
            50 {
                Force-DirSync
               }
            99 {
                Log-Write -LogPath $sLogFile -LineValue "Exiting script."
                Exit
               }
          }
            
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Main menu function completed successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
    }
  }
}
Function Display-UserMenu {
  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Starting function for the user management menu..."
  }
  
  Process{
    Try{
          $menuDisplay += "`r`n"
          $menuDisplay += "=====================================`r`n"
          $menuDisplay += "         User Management Menu        `r`n"
          $menuDisplay += "=====================================`r`n"
          $menuDisplay += "[0] Create a new user`r`n"
          $menuDisplay += "[1] Get information on existing user`r`n"
          $menuDisplay += "[2] Add existing user to distro`r`n"
          $menuDisplay += "[3] Changer UPN of existing user`r`n"
          $menuDisplay += "[4] Change primary SMTP of user`r`n"
          $menuDisplay += "[5] Add SMTP alias to existing user`r`n"
          $menuDisplay += "`r`n`r`n"
          $menuDisplay += "[99] Return to main menu `r`n"
          Write-Host $menuDisplay
          $menuSelection = Read-Host "Please enter your selection "
          [int]$menuSelection = $menuSelection.Trim()

          switch ($menuSelection) {
            0 {
                Log-Write -LogPath $sLogFile -LineValue "Creating a new user..."
                Add-DomainUser
                Break
              }
            1 {
                Log-Write -LogPath $sLogFile -LineValue "Getting information on an existing user..."
                $menu1Input = Read-Host "Please enter the username to retrieve info "
                $menu1Input = $menu1Input.Trim()
                Get-UserInfo -userName $menu1Input
                Break
              }
            2 {
                Log-Write -LogPath $sLogFile -LineValue "Adding a user to a distribution group..."
                Add-DistroMember
                Break
              }
            3 {
                Log-Write -LogPath $sLogFile -LineValue "Changing a user's UPN..."
                $menu3Input = Read-Host "Please enter the username whose UPN will be changed "
                $menu3Input = $menu3Input.Trim()
                Change-UPN -userName $menu3Input
                Break
              }
            4 {
                Log-Write -LogPath $sLogFile -LineValue "Changing a user's default SMTP address..."
                $menu4Input = Read-Host "Please enter the username to change their default SMTP address "
                $menu4Input = $menu4Input.Trim()
                Set-UserPrimarySMTP -userName $menu4Input
                Break
              }
            5 {
                Log-Write -LogPath $sLogFile -LineValue "Adding an SMTP alias to an existing user..."
                $menu5Input = Read-Host "Please enter the username to add an SMTP alias "
                $menu5Input = $menu5Input.Trim()
                Add-UserSMTPAlias -userName $menu5Input
                Break
              }
            99 {
                Log-Write -LogPath $sLogFile -LineValue "Returning to main menu..."
                Display-MainMenu
                Break
               }
            default {
                        Display-UserMenu
                    }
          }
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Completed function for user management successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Display-DistroMenu {
  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Starting function for distribution group management..."
  }
  
  Process{
    Try{
          $menuDisplay += "`r`n"
          $menuDisplay += "=====================================`r`n"
          $menuDisplay += "        Distro Management Menu       `r`n"
          $menuDisplay += "=====================================`r`n"
          $menuDisplay += "[0] Add existing user to group`r`n"
          $menuDisplay += "[1] Create a new Distribution Group`r`n"
          $menuDisplay += "`r`n`r`n"
          $menuDisplay += "[99] Return to main menu `r`n"
          Write-Host $menuDisplay
          $menuSelection = Read-Host "Please enter your selection "
          [int]$menuSelection = $menuSelection.Trim()

          switch ($menuSelection) {
            0 {
                Log-Write -LogPath $sLogFile -LineValue "Adding a user to a distribution group..."
                Add-DistroMember
                Break
              }
            1 {
                Log-Write -LogPath $sLogFile -LineValue "Creating a new distribution group..."
                Add-DistroGroup
                Break
              }
            99 {
                Log-Write -LogPath $sLogFile -LineValue "Returning to main menu..."
                Display-MainMenu
                Break
               }
            default {
                        Display-DistroMenu
                    }
          }
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Function for distro management's menu completed successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Get-NewUserInfo {

  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Getting new user information..."
  }
  
  Process{
    Try{
        $menuItems = 0
        $menuDisplay += "`r`n"

        #Exclude OUs that a new user WONT be added to
        #in the following format within the $validOUs
        #variable:
        #  Name -ne 'OU NAME HERE' -and
        #  Name -ne 'SECOND OU HERE'
        $validOUs = Get-ADObject -Filter {
            ObjectClass -eq 'organizationalUnit' -and
            Name -ne 'Domain Controllers' -and
            Name -ne 'Microsoft Exchange Security Groups' -and
            Name -ne 'Exchange Servers' -and
            Name -ne 'UserComputers' -and
            Name -ne 'ADFS Servers' -and
            Name -ne 'OU NAME HERE' -and
            Name -ne 'SECOND OU HERE'
        } | Sort-Object -Property Name | Select-Object Name,DistinguishedName

        ForEach($validOU in $validOUs) {
            $ouName = $validOU.Name
            $menuDisplay += "[$menuItems] $ouName`r`n"
            $menuItems += 1
        }        
        Write-Host $menuDisplay
        $menuSelection = Read-Host "Please select the OU for the new user "
        [int]$menuSelection = $menuSelection.Trim()
        if($menuSelection -le $menuItems) {
            $selectedOU = $validOUs[$menuSelection].DistinguishedName
        } else {
            Write-Host "`r`nInvalid entry.  `r`n"
            $menuSelection = Read-Host "Please select the OU for the new user "
            [int]$menuSelection = $menuSelection.Trim()
        }
        Log-Write -LogPath $sLogFile -LineValue "Selected OU for new user: $selectedOU"
        
        Clear-Variable menuDisplay,menuItems
        $userGivenName = Read-Host "Please enter the user's First Name " #i.e. "John"
        $userGivenName = $userGivenName.Trim()
        $userSurName = Read-Host "Please enter the user's Last Name " #i.e. "Doe"
        $userSurName = $userSurName.Trim()
        $userName = $userGivenName + $userSurName #i.e. "JohnDoe"
        $userEmail = Read-Host "Please enter the user's primary e-mail address (johndoe@domain.com) "
        $userEmail = $userEmail.Trim()
        $userUPN = $userEmail
        
        Try {
            do {
                $userManager = Read-Host "Please enter the username of the new user's manager "
                $userManager = $userManager.Trim()
                $userManager = Get-ADUser $userManager
            } until ($? -eq $True)
        }
        Catch {
            Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $False
        }

        $managerName = $userManager.Name
        #Get user password. If no user input, do loop until valid random is created
        $userPassword = Read-Host "Please enter the new user's password(Or press enter for a random password) "
        $userPassword = $userPassword.Trim()
        $isValid = Validate-Password -password $userPassword
        if(!$userPassword) {
            do {
                $userPassword = Get-RandomString -length 8 -numbers -letters
                $isValid = Validate-Password -password $userPassword
            } while ($isValid -eq $False)
        } else {
            if($isValid -eq $False) {
                do {
                    $userPassword = Read-Host "Invalid Password.`r`nPlease enter the new user's password "
                    $userPassword = $userPassword.Trim()
                    $isValid = Validate-Password -password $userPassword
                } while ($isValid -eq $False)
            }
        }

<#        do {
            if(!$userPassword) {
                $userPassword = Get-RandomString -length 8 -numbers -letters
                $isValid = Validate-Password -password $userPassword
            } else {
                $isValid = Validate-Password -password $userPassword
            }
        } while ($isValid -eq $False)
#>

        

        $menuDisplay += "`r`n"
        $menuDisplay += "You have entered the following information, please verify validity: `r`n"
        $menuDisplay += "First Name:   $userGivenName `r`n"
        $menuDisplay += "Last Name:    $userSurName `r`n"
        $menuDisplay += "Username:     $userName `r`n"
        $menuDisplay += "Primary SMTP: $userEmail `r`n"
        $menuDisplay += "O365 login:   $userUPN `r`n"
        $menuDisplay += "Manager:      $managerName`r`n"
        Write-Host $menuDisplay
        $validInput = Read-Host "Please answer [Y]es or [N]o, is the above information correct?"
        $validInput = $validInput.Trim()
        If($validInput -like "Y") {
            $newUserInfo = $userName,$userPassword,$userGivenName,$userSurName,$userEmail,$userUPN,$userManager,$selectedOU
            return $newUserInfo
        } else { Get-NewUserInfo }

    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $False
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Completed function for getting new user information successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
    }
  }
}
Function Get-UserInfo {
  Param(    
    [Parameter(Mandatory=$true)][string]$userName
  )
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Retrieving information for $username..."
  }
  
  Process{
    Try{
      $userInfo = Get-ADUser $userName -Properties * | Select Name,Enabled,SamAccountName,CanonicalName,mail,mailNickname,PasswordLastSet,PasswordExpired,PasswordNeverExpires,LastBadPasswordAttempt
      $name = $userInfo.Name
      $enabled = $userInfo.Enabled
      $SamAccountName = $userInfo.SamAccountName
      $OUPath = $userInfo.CanonicalName
      $email = $userInfo.mail
      $emailAlias = $userInfo.mailNickname
      $passwordlastset = $userInfo.PasswordLastSet
      $PasswordExpired = $userInfo.PasswordExpired
      $PasswordNeverExpires = $userInfo.PasswordNeverExpires
      $LastBadAttempt = $userInfo.LastBadPasswordAttempt

      $menuDisplay += "`r`n"
      $menuDisplay += "Name                      : $name`r`n"
      $menuDisplay += "Account Enabled           : $enabled`r`n"
      $menuDisplay += "Username                  : $SamAccountName`r`n"
      $menuDisplay += "Object Path               : $OUPath`r`n"
      $menuDisplay += "Primary SMTP Address      : $email`r`n"
      $menuDisplay += "E-Mail Alias              : $emailAlias`r`n"
      $menuDisplay += "Password Last Set         : $passwordlastset`r`n"
      $menuDisplay += "Password Expired          : $PasswordExpired`r`n"
      $menuDisplay += "Password Never Expires    : $PasswordNeverExpires`r`n"
      $menuDisplay += "Last Bad Password Attempt : $LastBadAttempt`r`n"
      $menuDisplay += "`r`n"

      Write-Host $menuDisplay
      Log-Write -LogPath $sLogFile -LineValue $menuDisplay

      Pause
    }
    
    Catch{
      Log-Write -LogPath $sLogFile -LineValue "$username is an invalid username. Returning to main menu."
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Retrieved user information successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Add-DomainUser {
  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Creating a new user..."
  }

  Process{
    Try{
      # $newUserInfo array positions
      # [0] $userName
      # [1] $userPassword
      # [2] $userGivenName
      # [3] $userSurName
      # [4] $userEmail
      # [5] $userUPN
      # [6] $userManager
      # [7] $selectedOU
      $newUserInfo = Get-NewUserInfo
    #Lines below for converting array into individual strings for writing to log.
    #Previous implementation just used the array elements, which for some reason entered the full arrow on each line
      $newFullName = $newUserInfo[2] + " " + $newUserInfo[3]
      $userName = $newUserInfo[0]
      $userPassword = $newUserInfo[1]
      $userGivenName = $newUserInfo[2]
      $userSurName = $newUserInfo[3]
      $userEmail = $newUserInfo[4]
      $userUPN = $newUserInfo[5]
      $userManager = $newUserInfo[6]
      $selectedOU = $newUserInfo[7]
    #Creating new user
      New-ADUser -SamAccountName $newUserInfo[0] -AccountPassword (ConvertTo-SecureString -AsPlainText $newUserInfo[1] -Force) -GivenName $newUserInfo[2] -Surname $newUserInfo[3] -EmailAddress $newuserInfo[4] -UserPrincipalName $newUserInfo[5] -Path $newUserInfo[7] -Manager $newUserInfo[6] -Name $newFullName -Enabled $True
      Write-Host "New user created. Starting DirSync operations.`r`n"
      Force-DirSync
      Write-Host "First DirSync operation completed. Starting 2nd DirSync.`r`n"
      Force-DirSync
      Write-Host "Please login to https://outlook.com/example.com and assign a license`r`nto the new user before continuing.`r`n" -ForegroundColor Yellow
      pause
      Write-Host "`r`nAdmin input indicates license has been assigned to new user. `r`nStarting DirSync operations." -ForegroundColor Green
      Log-Write -LogPath $sLogFile -LineValue "Admin input indicates license has been assigned to new user: $userName"
      Force-DirSync
      Write-Host "First DirSync operation completed. Starting 2nd DirSync.`r`n"
      Force-DirSync
    #Writing to log
      Log-Write -LogPath $sLogFile -LineValue "User input has been validated, values contained below:`r`n"
      Log-Write -LogPath $sLogFile -LineValue "     Username:     $userName"
      Log-Write -LogPath $sLogFile -LineValue "     Password:     $userPassword"
      Log-Write -LogPath $sLogFile -LineValue "     First Name:   $userGivenName"
      Log-Write -LogPath $sLogFile -LineValue "     Last Name:    $UserSurName"
      Log-Write -LogPath $sLogFile -LineValue "     Email:        $userEmail"
      Log-Write -LogPath $sLogFile -LineValue "     UPN:          $userUPN"
      Log-Write -LogPath $sLogFile -LineValue "     Manager:      $userManager"
      Log-Write -LogPath $sLogFile -LineValue "     Selected OU:  $selectedOU"
      Write-Host "New user created: $newFullName in .\$($newUserInfo[7])"
      Log-Write -LogPath $sLogFile -LineValue "New user created: $newFullName in .\$($newUserInfo[7])"
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "New User Successfully Created..."
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
    
  }
}
Function Add-DistroMember {
  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Adding an existing user to an existing distribution group..."
  }
  
  Process{
    Try{
      $menuItems = 0
      $menuDisplay += "`r`n"
      $distroGroups = Get-ADGroup -Filter {GroupCategory -eq 'distribution'} | Sort-Object -Property Name | Select-Object Name,DistinguishedName

      ForEach($distroGroup in $distroGroups) {
        $groupName = $distroGroup.Name
        $menuDisplay += "[$menuItems] $groupName`r`n"
        $menuItems += 1
      }

      Write-Host $menuDisplay
      $menuSelection = Read-Host "Please select the distribution group to receive a new member"
      [int]$menuSelection = $menuSelection.Trim()
      if($menuSelection -le $menuItems) {
        $selectedGroup = $distroGroups[$menuSelection].Name
        Log-Write -LogPath $sLogFile -LineValue "Selected distribution group: $selectedGroup"
      } else {
        Write-Host "`r`nInvalid entry.  `r`n"
        $menuSelection = Read-Host "Please select the distribution group to receive a new member"
        [int]$menuSelection = $menuSelection.Trim()
      }
      Clear-Variable menuDisplay,menuItems
      Try {
        do {
            $userToAdd = Read-Host "Please enter the user to be added to the $selectedGroup group"
            $userToAdd = (Get-ADUser $userToAdd).SamAccountName
        } until ($? -eq $True)
      }
      Catch {
        Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $False
      }
      $menuDisplay += "`r`n"
      $menuDisplay += "Please verify that you are adding`r`n"
      $menuDisplay += "     $userToAdd `r`n"
      $menuDisplay += "to the following group`r`n"
      $menuDisplay += "     $selectedGroup`r`n"
      Write-Host $menuDisplay
      Clear-Variable $menuDisplay
      $confirmation = Read-Host "Is the above information correct?`r`nPlease answer [Y]es or [N]o"
      If($confirmation -like "Y") {
        Log-Write -LogPath $sLogFile -LineValue "Adding $userToAdd to the $selectedGroup group."
        Add-ADGroupMember $selectedGroup $userToAdd
      } else {
        Break
      }

    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "User addition to distribution group completed successfully..."
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Add-DistroGroup {
  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Starting creation of new distribution group..."
  }
  
  Process{
    Try{
        $distroName = Read-Host "Please enter the name for the distribution group "
        $distroAlias = Read-Host "Please enter the alias for the new group "
        $distroAddress = Read-Host "Please enter the primary SMTP address for the new group "

        Try {
            do {
                $distroManager = Read-Host "Please enter the username of the new distribution group manager "
                $distroManager = Get-ADUser $distroManager
            } until ($? -eq $True)
        }
        Catch {
            Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $False
        }
        $managerName = $distroManager.Name

        $menuDisplay += "`r`n"
        $menuDisplay += "Please verify the following information is correct before creating a new distribution group:`r`n"
        $menuDisplay += "    Distro Name: $distroName`r`n"
        $menuDisplay += "    Alias:        $distroAlias`r`n"
        $menuDisplay += "    SMTP Address: $distroAddress`r`n"
        $menuDisplay += "    Distro Manager: $managerName`r`n"
        $menuDisplay += "`r`n"
        $menuDisplay += "Is the above information correct?`r`n"
        $menuDisplay += "`r`n"
        Write-Host $menuDisplay
        $distroConfirmation = Read-Host "Please answer [Y]es or [N]o "
        #Modify the -Path "" with the appropriate path for your environ
        if($distroConfirmation -like "y") {
            New-ADGroup -Path "OU=Distribution Groups,OU=Users,DC=domain,DC=local" -Name $distroName -DisplayName $distroName -ManagedBy $distroManager -OtherAttributes @{'mail'=$distroAddress; 'mailNickname'=$distroAlias} -GroupScope Universal -GroupCategory Distribution
            Log-Write -LogPath $sLogFile -LineValue "Distribution group created: $distroName"
        } else {
            Display-MainMenu
        }
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $False
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Creation of new distribution group completed Successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Change-UPN {
  Param(
      [Parameter(Mandatory=$true)][string]$userName
  )
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Starting process to change a $userName UPN..."
  }
  
  Process{
    Try{
    $user = Get-ADUser $userName -Properties *
    $newUPN = Read-Host "Please enter the NEW UPN  "
    Set-ADUser -Identity $user.SamAccountName -replace @{UserPrincipalName=$newEMail}           #Replaces the mail attribute with the new mail address and sets the UPN to @actualdomain.com
    Log-Write -LogPath $sLogFile -LineValue "Changed UPN for $userName `r`n Starting DirSync process"
    $oldUPN = $user.userPrincipalName           #This will be used to reset the UPN to default: "username@actualdomain.com"
    $defaultUPN = $user.mailNickname + "@MSFTAnnoying.onmicrosoft.com"           #This will be used to reset the UPN to default: "username@MSFTAnnoying.onmicrosoft.com" 
    Connect-MsolService
    Set-MsolUserPrincipalName -UserPrincipalName $oldUPN -NewUserPrincipalName $defaultUPN           #Set UPN from current to default (from:"username@actualdomain.com" to:"username@MSFTAnnoying.onmicrosoft.com")
    Force-DirSync
    Start-Countdown -Seconds 300 -Message "Waiting for 5 minutes before attempting to DirSync again"
    #Start-Sleep -s 300           #Sleeps for 5 minutes
    Force-DirSync


    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "User's UPN has been changed successfully..."
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Set-UserPrimarySMTP{
  Param(
    [Parameter(Mandatory=$true)][string]$userName
  )
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Changing primary SMTP address for $userName"
  }
  
  Process{
    Try{
        $user = Get-ADUser $userName -Properties *
        $proxys = (Get-ADUser $user.SamAccountName -properties proxyAddresses).proxyAddresses           #Gets current proxy settings
        $proxys = $proxys -replace 'SMTP:','smtp:'           #replaces default smtp address (noted by "SMTP:") to an alias (noted by "smtp:")
        $newDefaultSMTP = Read-Host "Please enter the new PRIMARY SMTP address (i.e. johndoe@company.com)  "
        $newDefaultSMTP = "SMTP:" + $newEMail           #This will be the new primary SMTP address: "SMTP:username@newdomain.com"
        
        $message += "`r`n"
        $message += "Replacing the current default SMTP address for`r`n"
        $message += "$userName `r`n"
        $message += "with `r`n"
        $message += "$newDefaultSMTP `r`n"
        $message += "`r`nIs this correct?`r`n`r`n"
        $userResponse = Read-Host "Please answer [Y]es or [N]o "
        if ($userResponse -like "Y") {
            Set-ADUser -Identity $user.SamAccountName -add @{proxyAddresses=$newDefaultSMTP}           #Adds the NEW primary SMTP address ("SMTP:username@newdomain.com")
        } else {
            Display-MainMenu
        }
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Changed primary SMTP address for $userName to $newDefaultSMTP"
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Add-UserSMTPAlias{
  Param(
      [Parameter(Mandatory=$true)][string]$userName
  )
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "Adding an SMTP alias to $userName"
  }
  
  Process{
    Try{
      $user = Get-ADUser $userName -Properties *
      $newSMTPAlias = Read-Host "Please enter an alias to add to $userName "

      $message += "`r`n"
      $message += "Please confirm the following information: `r`n"
      $message += "Adding the alias `r`n"
      $message += "$newSMTPAlias `r`n"
      $message += "to`r`n"
      $message += "$userName`r`n"
      $message += "`r`n Is the above information correct? `r`n`r`n"
      Write-Host $message
      $userResponse = Read-Host "Please answer [Y]es or [N]o "
      if($userResponse -like "Y") {
        $newSMTPAlias = "smtp:" + $newSMTPAlias
        Set-ADUser -Identity $user.SamAccountName -add @{proxyAddresses=$newSMTPAlias}
      } else {
        Display-MainMenu
      }
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Added SMTP alias ( $newSMTPAlias ) to $userName"
      Log-Write -LogPath $sLogFile -LineValue " "
      Display-MainMenu
    }
  }
}
Function Force-DirSync {
    $DirSyncStart = Get-Date -Format g

        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -psconsolefile "C:\Program Files\Windows Azure Active Directory Sync\DirSyncConfigShell.psc1" -command "Start-OnlineCoexistenceSync"           #Forces DirSync

    do {
	    $completed = Get-EventLog -LogName Application -Source "Directory Synchronization" | Where {$_.eventID -eq 0 -and $_.Message.Contains("Deleting run history that is older than ") -and $_.TimeGenerated -gt $DirSyncStart} | FL -Property *
	    $errors = Get-EventLog -LogName Application -Source "Directory Synchronization" | Where {$_.eventID -eq 0 -and $_.Message.Contains("The Management Agent 'Windows Azure Active Directory Connector' reported  errors on execution.") -and $_.TimeGenerated -gt $DirSyncStart} | FL -Property *
    } while (!$completed)
    
    if(!$errors) {
        Log-Write -LogPath $sLogFile -LineValue "DirSync completed with no warnings."
        Write-Host "DirSync Completed with no errors."
    } else {
        Log-Write -LogPath $sLogFile -LineValue "DirSync completed with warnings."
        Write-Host "DirSync completed with warnings."
    }
}
Function Validate-Password{

    param(
        [string]$password = $(throw "Please specify password"),
        [int]$minLength=8,
        [int]$numUpper = 1,
        [int]$numLower = 1,
        [int]$numNumbers = 1, 
        [int]$numSpecial = 0
    )


    $upper = [regex]"[A-Z]"
    $lower = [regex]"[a-z]"
    $number = [regex]"[0-9]"
    #Special is "none of the above"
    $special = [regex]"[^a-zA-Z0-9]"

    # Check the length.
    if($password.length -lt $minLength) {$false; return}

    # Check for minimum number of occurrences.
    if($upper.Matches($password).Count -lt $numUpper ) {return $false}
    if($lower.Matches($password).Count -lt $numLower ) {return $false}
    if($number.Matches($password).Count -lt $numNumbers ) {return $false}
    if($special.Matches($password).Count -lt $numSpecial ) {return $false}

    # Passed all checks.
    return $true
}
Function Get-RandomString(){
<#
    NAME
        Get-RandomString

    SYNOPSIS
        The Get-RandomString cmdlet creates a random string. 
        You can specify the length as well as whether or not letters/numbers/symbols are included.

    DESCRIPTION
        Get-RandomString is useful for a number of use cases. These include random passwords
        
    SYNTAX 
        Get-RandomString [-length <number>] [-letters] [-numbers] [-punctuation]

    USAGE
        Calling Get-RandomString with no arguments returns an 8 character random string containing numbers, letters, and symbols.
        You can specify length by calling the -length parameter
            i.e. Get-RandomPassword -length 8
        If you wish to specify what types of characters, they can be specified with the -letters -numbers -punctuation switches.
        If any of these switches are specified then those are the only character sets that will be used.
            i.e.
                Get-RandomString -length 8 -numbers
                    05326974
                Get-RandomString -length 15 -letters
                    EonIZLstqkgMfWd
                Get-RandomString -length 10 -punctuation -letters -numbers
                    COQSA1@pi6
                Get-RandomString -numbers
                    06921485
                Get-RandomString -letters
                    YlMJnbOs
                Get-RandomString -punctuation
                    $.?#!+@*
                Get-RandomString -numbers -letters
                    80uc1V5e
                Get-RandomString -length 15 -numbers -punctuation
                    0?%*195!62.$873
#>

    param([int]$length, 
            [switch]$punctuation,
            [switch]$numbers,
            [switch]$letters
            )
    #If no length is specified, defaults to 8 characters long
    if(!$length) { $length = 8 }
    #If no character set is specified it utilizes the entire character set of numbers, letters, and symbols
    if(!$punctuation -and !$numbers -and !$letters) { $input = 33..33 + 35..38 + 42..43 + 46..46 + 63..64 + 48..57 + 65..90 + 97..122 }
    #If a character set is specified it adds the specified character set to the input parameter
    if($punctuation) { $input += 33..33 + 35..38 + 42..43 + 46..46 + 63..64 }
    if($numbers) { $input += 48..57 }
    if($letters) { $input += 65..90 + 97..122 }

  #  $characters = 65..90 + 97..122

    # Thanks to
    # http://blogs.technet.com/b/heyscriptingguy/archive/2012/01/07/use-powershell-to-choose-a-specific-number-of-random-letters.aspx
    $string = get-random -count $length `
     -input ($input) |   #     -input ($punc + $digits + $letters) |
            % -begin { $aa = $null } `
            -process {$aa += [char]$_} `
            -end {$aa}
    return $string
}
Function Start-Countdown {   <#
    .SYNOPSIS
        Provide a graphical countdown if you need to pause a script for a period of time
    .PARAMETER Seconds
        Time, in seconds, that the function will pause
    .PARAMETER Messge
        Message you want displayed while waiting
    .EXAMPLE
        Start-Countdown -Seconds 30 -Message Please wait while Active Directory replicates data...
    .NOTES
        Author:            Martin Pugh
        Twitter:           @thesurlyadm1n
        Spiceworks:        Martin9700
        Blog:              www.thesurlyadmin.com
       
        Changelog:
           2.0             New release uses Write-Progress for graphical display while couting
                           down.
           1.0             Initial Release
    .LINK
        http://community.spiceworks.com/scripts/show/1712-start-countdown
    #>
    Param(
        [Int32]$Seconds = 10,
        [string]$Message = "Pausing for 10 seconds..."
    )
    ForEach ($Count in (1..$Seconds))
    {   Write-Progress -Id 1 -Activity $Message -Status "Waiting for $Seconds seconds, $($Seconds - $Count) left" -PercentComplete (($Count / $Seconds) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Id 1 -Activity $Message -Status "Completed" -PercentComplete 100 -Completed
} 
#-----------------------------------------------------------[Execution]------------------------------------------------------------
 
Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
Display-MainMenu
Log-Finish -LogPath $sLogFile
