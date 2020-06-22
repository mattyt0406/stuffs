param(
						[string] [Parameter(Mandatory=$true)] $keyVaultName,
						[string] [Parameter(Mandatory=$true)] $RGName,
						[string] [Parameter(Mandatory=$true)] $AutomationAccountName,
						[string] [Parameter(Mandatory=$true)] $environment,
						[string] [Parameter(Mandatory=$true)] $ObjectIDWorker 
                    )

                    $ErrorActionPreference = 'Stop'
                    $DeploymentScriptOutputs = @{}  
                    
                    [String] $ApplicationDisplayName = $AutomationAccountName
					$KeyVaultName = Get-AZKeyVault -ResourceGroupName $RGName | Select-Object -ExpandProperty VaultName
					
					$CertifcateAssetName = 'AzureRunAsCertificate'
                    $CertificateName = $AutomationAccountName + $CertifcateAssetName
                    $CerCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + '.cer')
                    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + '.pfx')
                    [String] $PfxCertPlainPasswordForRunAsAccount = [Guid]::NewGuid().ToString().Substring(0, 8) + '!'            
                    
                    $certSubjectName = 'cn=' + $certificateName    
                    $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName $certSubjectName  -IssuerName 'Self' -ValidityInMonths 12 -ReuseKeyOnRenewal
                    $AddAzureKeyVaultCertificateStatus = Add-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName -CertificatePolicy $Policy 
                    
                    While ($AddAzureKeyVaultCertificateStatus.Status -eq 'inProgress') {
                        Write-Host 'Waiting for certificate creation completion...'
                        Start-Sleep -Seconds 10
                        $AddAzureKeyVaultCertificateStatus = Get-AzKeyVaultCertificateOperation -VaultName $keyVaultName -Name $certificateName
                    }
                    if ($AddAzureKeyVaultCertificateStatus -eq 'completed'){
                        Write-Host 'Certificate creation complete'
                    }                    
                    $secretRetrieved = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $certificateName
                    $pfxBytes = [System.Convert]::FromBase64String($secretRetrieved.SecretValueText)
                    $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                    $certCollection.Import($pfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
                    
                    #Export the .pfx file 
                    $protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
                    [System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $protectedCertificateBytes)
					
                    $cert = Get-AZKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName
                    $certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $certBytes)

                    $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)    
                    $keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
					$KeyId = [Guid]::NewGuid() 
                    $startDate = Get-Date
                    $endDate = (Get-Date $PfxCert.GetExpirationDateString()).AddDays(-1)
                    $Application = New-AZADApplication -DisplayName $ApplicationDisplayName -HomePage ('http://' + $applicationDisplayName) -IdentifierUris ('http://' + $KeyId)
                    Start-Sleep -seconds 45
                    New-AZADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $startDate -EndDate $endDate 
                    New-AZADServicePrincipal -ApplicationId $Application.ApplicationId -Role 'VA-Automation Manager'
                    Start-Sleep -s 15
                    
                    $CertPassword = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force   
                    Remove-AZAutomationCertificate -ResourceGroupName $RGName -automationAccountName $AutomationAccountName -Name $certifcateAssetName -ErrorAction SilentlyContinue
                    New-AZAutomationCertificate -ResourceGroupName $RGName -automationAccountName $AutomationAccountName -Path $PfxCertPathForRunAsAccount -Name $certifcateAssetName -Password $CertPassword -Exportable  | write-verbose
                    
                    $ConnectionTypeName = 'AzureServicePrincipal'
                    $ConnectionAssetName = 'AzureRunAsConnection'
                    $ApplicationId = $Application.ApplicationId 
                    $SubscriptionInfo = get-AZsubscription -SubscriptionId $environment
                    $TenantID = $SubscriptionInfo | Select-Object TenantId -First 1
                    $Thumbprint = $PfxCert.Thumbprint
                    $ConnectionFieldValues = @{ApplicationId = $ApplicationID; TenantId = $TenantID.TenantId; CertificateThumbprint = $Thumbprint; SubscriptionId = $($SubscriptionInfo.SubscriptionId)} 
                    Remove-AZAutomationConnection -ResourceGroupName $RGName -automationAccountName $AutomationAccountName -Name $connectionAssetName -Force #-ErrorAction SilentlyContinue
                    New-AZAutomationConnection -ResourceGroupName $RGName -automationAccountName $AutomationAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $ConnectionFieldValues
					Remove-AZKeyVaultAccessPolicy -ObjectId $ObjectIDWorker -ResourceGroupName $RGName -VaultName $keyVaultName