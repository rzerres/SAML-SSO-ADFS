# Reference to work found at
# - https://github.com/auth0/adfs-auth0/blob/master/adfs.ps1
# - https://rephlex.de/blog/2018/04/05/how-to-connect-nextcloud-to-active-directory-using-ad-fs-without-losing-your-mind


function Load-Module {
    [CmdletBinding()]
    
    param(
        [parameter(Mandatory = $true)]
        [string] $module
    )

    process {
        # If module is imported say that and do nothing
        if (Get-Module | Where-Object {$PSItem.Name -eq $module}) {
            write-verbose "Module $module is already imported."
        }
        else {
            # If module is not imported, but available on disk then import
            if (Get-Module -ListAvailable | Where-Object {$PSItem.Name -eq $module}) {
                Import-Module $module -Verbose
            }
            else {
                # If module is not imported, not available on disk, but is in online gallery then install and import
                if (Find-Module -Name $module | Where-Object {$PSItem.Name -eq $module}) {
                    Install-Module -Name $module -Force -Verbose -Scope CurrentUser
                    Import-Module $module -Verbose
                }
                else {
                    # If module is not imported, not available and not in online gallery then abort
                    write-verbose "Module $module not imported, not available and not in online gallery, exiting."
                    return $false
                }
            }
        }
    }
}

function Set-ServiceDependency {
    [CmdletBinding()]
    
    param(
        [parameter(Mandatory = $false)]
        [string] $ServerName,
        [parameter(Mandatory = $false)]
        [string] $ServiceName

    )

    begin {
        # check if running as Admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
            return 1;
        }
    }
        
    process {
        ### Set service  dependencies
        if ($ServerName -eq $null) {
            $ServerName = "localhost"
        }

        if ($ServiceName -eq $null) {
            # Microsoft-Schlüsselverteilungsdienst
            $ServiceName = "KdsSvc"
        }

        Get-Service -ComputerName $ServerName -Name $ServiceName
        # on a DC, start it right after network gets redy
        #$command = 'sc.exe \\' + $ServerName + ' qtriggerinfo ' + $ServiceName + ''
        #iex $command
        $command = 'sc.exe \\' + $ServerName + ' triggerinfo ' + $ServiceName + ' start/networkon'
        iex $comman
    }
}

function Test-AdfsFarmInstallation-nextcloud {
    [CmdletBinding()]
    
    param(
        [parameter(Mandatory = $true)]
        [String] $FederationServiceName,
        [parameter(Mandatory = $true)]
        [String] $AdfsCertificateName,
        [parameter(Mandatory = $true)]
        [PSCredential] $Credential
    )

    begin {
        # check if running as Admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
            return $false;
        }
        
        Load-Module ActiveDirectory
        Load-Module ADFS

        $ADFSNetBIOSName = (Get-ADDomain).NetBIOSName
    }

    process {
        # Communication Thumbprint (e.g a LetsEncrypt Certificate)
        $ThumbprintCommunication = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $PSItem.Subject -match "CN=$AdfsCertificateName" }).Thumbprint
        if ( $ThumbprintCommunication -ne $null) {
            Write-Verbose "`tTest-AdfsFarmInstallation `
                -CertificateThumbprint:`"$ThumbprintCommunication`" `
                -FederationServiceName:`"$FederationServiceName`" ``
                -ServiceAccountCredential:`"$Credential`" `
                `n" -verbose
            Test-AdfsFarmInstallation `
                -CertificateThumbprint $ThumbprintCommunication `
                -FederationServiceName $FederationServiceName `
                -ServiceAccountCredential $Credential
        } else {
            Write-Output "No valid Thumbprint for '$AdfsCertificateName' found."
        }
    }
}

function Install-AdfsFarm-nextcloud {
    [CmdletBinding()]
    
    param(
        [parameter(Mandatory = $true)]
        [String] $FederationServiceName,
        [parameter(Mandatory = $true)]
        [String] $FederationServerName,
        [parameter(Mandatory = $false)]
        [String] $FederationServiceDisplayName,
        [parameter(Mandatory = $true)]
        [String] $AdfsCertificateName,
        [parameter(Mandatory = $false)]
        [String] $GroupServiceAccountIdentifier,
        [parameter(Mandatory = $true)]
        [PSCredential] $Credential,
        [parameter(Mandatory = $false)]
        [boolean] $Force = $True
    )

    begin {
        # check if running as Admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
            return 1;
        }

        Load-Module ActiveDirectory

        $ADFSNetBIOSName = (Get-ADDomain).NetBIOSName
    }

    process {
    
        if (!$FederationServiceDisplayName) {
            $FederationServiceDisplayName = "AD Federation-Service"
        }
        if (!$GroupServiceAccountIdentifier) {
            $GroupServiceAccountIdentifier = "$ADFSNetBIOSName\ADFSservice"
        }
        
         
        # Communication Thumbprint (e.g a LetsEncrypt Cert)
        $Condition = {$PSItem.Subject -match "CN=$AdfsCertificateName"}
        $ThumbprintCommunication = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object $Condition ).Thumbprint

        # Signing Thumbprint (e.g a SelfSigned Cert)
        $Condition = {$PSItem.Subject -match "CN=$FederationServerName"}
        $ThumbprintSigning = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object $Condition ).Thumbprint
        
        # Decryption Thumbprint (e.g. a SelfSigned Cert)
        $Condition = {$PSItem.Subject -match "CN=$FederationServerName"}
        $ThumbprintDecryption = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object $Condition ).Thumbprint

        # We need to quote "`$"
        if ( $ThumbprintCommunication -ne $null) {
            Write-Verbose "`tInstall-AdfsFarm `
                -FederationServiceName:`"$FederationServiceName`" `
                -FederationServerName:`"$FederationServerName`" `
                -FederationServiceDisplayName:`"$FederationServiceDisplayName`" `
                -GroupServiceAccountIdentifier:`"$GroupServiceAccountIdentifier```$`" `
                -CertificateThumbprint:`"$ThumbprintCommunication`" `
                -SigningCertificateThumbprint:`"$ThumbprintSigning`" `
                -DecrytionCertificatThumbprint:`"$ThumbprintDecryption`" `
                `n"
            Write-Output Install-AdfsFarm `
                -CertificateThumbprint $ThumbprintCommunication `
                -Credential $Credential `
                -FederationServiceName $FederationServiceName `
                -FederationServerName $FederationServerName `
                -FederationServiceDisplayName $FederationServiceDisplayName `
                -GroupServiceAccountIdentifier $GroupServiceAccountIdentifier```$ `
                #-SigningCertificateThumbprint $ThumbprintSigning `
                #-DecrytionCertificatThumbprint $ThumbprintDecryption `
        } else {
            Write-Output "No valid Thumbprint for '$AdfsCertificateName' found."
        }
    }
}

function Install-WindowsFeature-AdfsFederation {
    [CmdletBinding()]
    
    param(
        [parameter(Mandatory = $false)]
        [boolean] $ForceUninstall
    )

    begin {
        # check if running as Admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
            return 1;
        }
    }

    process {
        if ($(Get-WindowsFeature -Name Windows-Internal-Database -ErrorAction SilentlyContinue).Installed -eq $False) {
            Write-Verbose "`tThis installation does rely on Windows-Internal-Database (WID).`n"
            # ADFS-Federation using a SQL-Server needs to be implemented manualy
            Install-WindowsFeature -Name Windows-Internal-Database
            # If ADFS-Federation is on an Domain-Controller, take care of correct service dependencies
            Set-ServiceDependency -ServerName $ADFSFederationServerName
        } else {
            Write-Verbose "`tWindows-Internal-Databaes (WID) already installed.`n"
        }
        
        if ($(Get-WindowsFeature -Name ADFS-Federation -ErrorAction SilentlyContinue).Installed -eq $False) {
            Install-WindowsFeature -Name ADFS-Federation
        } else {
            # test-environment
            If ($ForceUninstall) {
                Write-Verbose "`tAn active Feature installation of 'ADFS-Federation' is found.`n"
                Write-Verbose "`tForcing a reinstallation:`n" `
                    "`t1) call: 'Uninstall-WindowsFeature-AdfsFederation -ForceRestart $true -Verbose'`n" `
                    "`t   after the uninstall-process is finished, the system will reboot`n" ` 
                    "`t2) restart the installation`n"
            }
        }
    }
}

function Uninstall-WindowsFeature-AdfsFederation {
    [CmdletBinding()]
    
    param(
        [parameter(Mandatory = $false)]
        [boolean] $ForceRestart,
        [parameter(Mandatory = $false)]
        [boolean] $CleanupWID,
        [parameter(Mandatory = $false)]
        [string] $ServerName = "localhost"
  )

    begin {
        # check if running as Admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
            return 1;
        }
        Load-Module ADFS
    }

    process {
        if ($(Get-WindowsFeature -Name ADFS-Federation -ErrorAction SilentlyContinue).Installed -eq $false) {
            Write-Verbose "`tWindows-Feature ADFS-Federation is not installed. Nothing to do.`n"
        } Else {
            Stop-Service -Name ADFSsrv 
            Uninstall-WindowsFeature -Name ADFS-Federation
            If ($CleanupWID) {
                Write-Verbose "`tRemove Windows-Feature ADFS-Federation`n"
                Uninstall-WindowsFeature -Name ADFS-Federation
                Stop-Service -Name 'MSSQL$MICROSOFT##WID'
                # Delete ADFS SQL-Instances
                Remove-Item -Name $env:SystemRoot\WID\Data\ADFS*
                Start-Service -Name 'MSSQL$MICROSOFT##WID'
            }
            If ($ForceRestart) {
                Restart-Computer -ComputerName $ServerName -Timeout 0
            }
        }
    }
}

function Enable-Adfs-IdpInitiatedSignonPage {
    [CmdletBinding()]
    
    param(
        [parameter(Mandatory = $false)]
        [string] $ServerName = "localhost"
  )

    begin {
        # check if running as Admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
            return 1;
        }
        Load-Module ADFS
    }

    process {
        # on Win2016 disabled per default
        if ($(Get-AdfsProperties).IdpInitiatedSignonPage -eq $false) {
            Set-AdfsPropertie -EnableIdpInitiatedSignonPage $true
        }
    }
}

function Create-AdfsTrust-nextcloud {
    [CmdletBinding()]
    
    param(
        # FQDN for your netcloud server is required. E.g.: https://nextcloud.domain.org:8443")
        [parameter(Mandatory = $true)]
        [string] $NextCloudFQDN = "localhost",
        # Display-Name for the nextcloud Trust shown in the ADFS-MMC 
        [parameter(Mandatory = $true)]
        [string] $AdfsPartyTrustName
  )

    begin {
        # check if running as Admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
            return 1;
        }
        Load-Module ADFS
    }

    process {
        ### Check for working ADFS Powershell Environment
        if ((Get-Command Set-ADFSRelyingPartyTrust -ErrorAction SilentlyContinue) -eq $null) {
            # check if ADFS snapin exists in the machine
            if ( (Get-PSSnapin -Name Microsoft.Adfs.Powershell -Registered -ErrorAction SilentlyContinue) -eq $null ) {
                Write-Error "This PowerShell script requires the Microsoft.Adfs.Powershell Snap-In. Try executing it from an ADFS server"
                return;
            }

            # check if ADFSP snapin is already loaded, if not load it
            if ( (Get-PSSnapin -Name Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue) -eq $null ) {
                Write-Verbose "Adding Microsoft.Adfs.Powershell Snapin"
                Add-PSSnapin Microsoft.Adfs.Powershell
            }
        }

        ###  Construct needed ADFS reference-settings for nextcloud
        $ADFSPartyTrustEndpointURI = "https://$NextCloudFQDN/apps/user_saml/saml/acs"
        $ADFSPartyTrustIdentifierURI = "https://$NextCloudFQDN/apps/user_saml/saml/metadata"
        $ADFSPartyTrustNameEndpoint = New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $ADFSPartyTrustEndpointURI -IsDefault $true 

        $RPT = Get-AdfsRelyingPartyTrust -Name $ADFSPartyTrustName -Verbose
        If ($RPT) {
            Write-Verbose "`tRemove existing ADFSPartyTrustName '$ADFSPartyTrustName'`n"
            Remove-AdfsRelyingPartyTrust -TargetName $ADFSPartyTrustName -Verbose
        }


        #Write-Verbose "`tCreate new ADFSPartyTrustName '$ADFSPartyTrustName'`n" -ForegroundColor "gray" -NoNewline
        Write-Verbose "`tCreate new ADFSPartyTrustName '$ADFSPartyTrustName'`n"
        Add-AdfsRelyingPartyTrust -Identifier $ADFSPartyTrustIdentifierURI `
            -Name $ADFSPartyTrustName -ProtocolProfile SAML -Verbose `
            -Notes "This is a trust for nextcloud instance at $NextCloudFQDN"


	Add-AdfsRelyingPartyTrust - -IssuanceTransformRules $Rule -AccessControlPolicyName "Permit everyone" -AutoUpdateEnabled $true -MonitoringEnabled $true

        Write-Verbose "`tDisable CertificateRevocationChecks`n"
        Set-AdfsRelyingPartyTrust -TargetName $ADFSPartyTrustName `
            -EncryptionCertificateRevocationCheck None `
            -SigningCertificateRevocationCheck None

        Write-Verbose "`tSet new Endpoint '$ADFSPartyTrustEndpointURI'`n"
        #Set-AdfsRelyingPartyTrust -TargetName $ADFSPartyTrustName -Identifier $ADFSPartyTrustIdentifierURI
        #$ADFSPartyTrustNameEndpoint = New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $ADFSPartyTrustEndpoint -IsDefault $true
        Set-AdfsRelyingPartyTrust -TargetName $ADFSPartyTrustName `
            -SamlEndpoint $ADFSPartyTrustNameEndpoint -Verbose

        # transform-rules (as here-strings)
        # Refernece: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831504(v=ws.11)
        $rules = @'
@RuleName = "sAMAccountName - Namens-ID"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"),
 query = ";sAMAccountName;{0}", param = c.Value);

@RuleName = "AD Attribute - Vorname, Nachname, Namens-ID"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
  "sAMAccountName"),
  query = ";givenName,sn,sAMAccountName;{0}", param = c.Value);

@RuleName = "Erweiterte AD-Attribute"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
  "sAMAccountName", 
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  "http://schemas.xmlsoap.org/claims/CommonName"),
  query = ";givenName,sn,sAMAccountName,userPrincipalName,displayName;{0}", param = c.Value);
'@
        #@RuleName = "Store: ActiveDirectory -> Enable-Adfs-IdpInitiatedSignonPageMail (ldap attribute: mail), Name (ldap attribute: userPrincipalName), GivenName (ldap attribute: givenName), Surname (ldap attribute: sn)" 
        #c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
        # => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", 
        #   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", 
        #   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", 
        #   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", 
        #   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"), query = ";mail,displayName,userPrincipalName,givenName,sn;{0}", param = c.Value);

        Write-Verbose "Adding Claim Rules"
        Set-ADFSRelyingPartyTrust –TargetName $ADFSPartyTrustName `
            -IssuanceTransformRules $rules

        # Authorization Rules
        $authRules = '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
        Write-Verbose "Adding Issuance Authorization Rules: $authRules"
        $rSet = New-ADFSClaimRuleSet –ClaimRule $authRules
        Set-ADFSRelyingPartyTrust –TargetName $ADFSPartyTrustName `
            –IssuanceAuthorizationRules $rSet.ClaimRulesString
            -MetadataUrl https://$NextCloudFQDN/FederationMetadata/2007-06/FederationMetadata.xml `
            -AutoUpdateEnabled $true `
            -MonitoringEnabled $true
 
            # only in 2016: -AccessControlPolicyName "Permit everyone"
    }
}


###
# Parameters
###

$Credential = Get-Credential

# FQDN's need a valid certificate (e.g using LetsEncrypt service)
$NextCloudFQDN ="amcloud.am-koeln.am-architekten.de:8443"
$AdfsFederationServiceName = "www.am-koeln.am-architekten.de"
$AdfsFederationServerName = "amdc.am-koeln.am-architekten.de"
$AdfsPartyTrustName = "nextcloud Service"
$AdfsGroupServiceAccountIdentifier = 'AM-Koeln\adfs-service'
$AdfsCertificateName = "am-koeln.am-architekten.de"

# Uncomment, if you want to deinstall and cleanup an yet active installation
#Uninstall-WindowsFeature-AdfsFederation -ForceRestart $true -Verbose
$Ret = Install-WindowsFeature-AdfsFederation -Verbose
#Write-Output "Return-Object: $Ret"

if ( (Get-AdfsProperties).Hostname -eq $null -and (Get-AdfsProperties).FederationPassiveAddress -eq $null) {
    $Ret = Test-AdfsFarmInstallation-nextcloud `
        -FederationServiceName $AdfsFederationServiceName `
        -AdfsCertificateName $AdfsCertificateName `
        -Credential $Credential `
        -Verbose
    #Write-Output "Return-Object: $Ret"

    $Ret = Install-AdfsFarm-nextcloud -Verbose `
        -Credential $Credential `
        -FederationServiceName $AdfsFederationServiceName `
        -FederationServerName $AdfsFederationServerName `
        -AdfsCertificateName $AdfsCertificateName `
        -GroupServiceAccountIdentifier $AdfsGroupServiceAccountIdentifier
    #Write-Output "Return-Object: $Ret"
}

$Ret = Create-AdfsTrust-nextcloud -NextCloudFQDN $NextCloudFQDN -AdfsPartyTrustName $AdfsPartyTrustName
#Write-Output "Return-Object: $Ret"

$Ret = Enable-Adfs-IdpInitiatedSignonPage
#Write-Output "Return-Object: $Ret"
