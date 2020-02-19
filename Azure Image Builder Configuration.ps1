#********CONFIGURE TENANT FOR AIB PREVIEW************

Install-Module Az -Force
Connect-AzAccount
$sub = get-azsubscription -SubscriptionName "Microsoft Azure Sponsorship 2"
Select-AzSubscription -SubscriptionObject $sub

#Register the AIB Preview Feature
Register-AzProviderFeature -ProviderNamespace Microsoft.VirtualMachineImages -FeatureName VirtualMachineTemplatePreview

#Check AIB REgistration Status
Get-AzProviderFeature -ProviderNamespace Microsoft.VirtualMachineImages -FeatureName VirtualMachineTemplatePreview
Get-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages | Select-Object RegistrationState
Get-AzResourceProvider -ProviderNamespace Microsoft.Storage | Select-Object RegistrationState

#If something is not registered run the following
Register-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages
Register-AzResourceProvider -ProviderNamespace Microsoft.Storage

#Create a resource group for use by AIB. During the previous step we enabled the feature, one of the things that happend, was that a service principal has been made in our Azure AD. This service principal (SP) is used to give AIB rights on certian resource (groups). The Application ID of the service principal is always the same:
# cf32a0cc-373c-47c9-9156-0db11f6a6dfc
New-AzResourceGroup -Name "WVD2-ResourceGroup-AIB" -Location 'West US 2'
New-AzRoleAssignment -RoleDefinitionName "Contributor" -ApplicationId "cf32a0cc-373c-47c9-9156-0db11f6a6dfc" -ResourceGroupName "WVD2-ResourceGroup-AIB"

Register-AzResourceProvider -ProviderNamespace Microsoft.KeyVault
Get-AzResourceProvider -ProviderNamespace Microsoft.KeyVault | Select-Object RegistrationState

#*******************************************************



#*******Deploy Test AIB JSON and PowerShell Script*****************

$TemplateFile = "C:\Users\mhooks\OneDrive - Microsoft\Windows Virtual Desktop\WVD_GoldImage_Configuration.json"
New-AzResourceGroupDeployment -ResourceGroupName WVD2-ResourceGroup-AIB -TemplateFile $TemplateFile -OutVariable Output -Verbose
$ImageTemplateName = $Output.Outputs["imageTemplateName"].Value
Invoke-AzResourceAction -ResourceGroupName WVD2-ResourceGroup-AIB -ResourceType Microsoft.VirtualMachineImages/imageTemplates -ResourceName $ImageTemplateName -Action Run -Force

#*****************************************************************

#*******Deploy Test AIB/SIG JSON and PowerShell Script*****************

$TemplateFile = "C:\Users\mhooks\OneDrive - Microsoft\Windows Virtual Desktop\WVD_GoldImage_Configuration_SIG.json"
New-AzResourceGroupDeployment -ResourceGroupName WVD2-ResourceGroup-AIB -TemplateFile $TemplateFile -OutVariable Output -Verbose
$ImageTemplateName = $Output.Outputs["imageTemplateName"].Value
Invoke-AzResourceAction -ResourceGroupName WVD2-ResourceGroup-AIB -ResourceType Microsoft.VirtualMachineImages/imageTemplates -ResourceName $ImageTemplateName -Action Run -Force

#*****************************************************************



#*******Build Image**********************************************
$ImageTemplateName = $Output.Outputs["imageTemplateName"].Value
Invoke-AzResourceAction -ResourceGroupName WVD2-ResourceGroup-AIB -ResourceType Microsoft.VirtualMachineImages/imageTemplates -ResourceName $ImageTemplateName -Action Run

#Check Status
(Get-AzResource -ResourceGroupName WVD2-ResourceGroup-AIB -ResourceType Microsoft.VirtualMachineImages/imageTemplates -Name $ImageTemplateName).Properties.lastRunStatus

#*****************************************************************