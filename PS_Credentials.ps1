#----------------------------------------------------------------
#no cred specified
Get-ADUser -Filter 'Name -eq "demo"' -Server domain.local
#----------------------------------------------------------------
#cred specified - prompted
Get-ADUser -Credential domain\demo -Filter 'Name -eq "demo"' -Server domain.local
#----------------------------------------------------------------
#will this work?
$user = "domain\demo"
$PASSWORD = 'P@$$w0rd'
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$PASSWORD
#----------------------------------------------------------------
#this will work
$user = "domain\demo"
$PASSWORD = 'P@$$w0rd'
$secureString = ConvertTo-SecureString -AsPlainText -Force -String $PASSWORD
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$secureString
#----------------------------------------------------------------
#look inside the cred
$cred
#----------------------------------------------------------------
#passing cred inside parameter
Get-ADUser -Credential $cred -Filter 'Name -eq "demo"' -Server domain.local
#----------------------------------------------------------------
#reversing secure string
$PlainPassword = $cred.GetNetworkCredential().Password 
#----------------------------------------------------------------
#prompt user for 
$SecurePassword = Read-Host -Prompt "Enter password" -AsSecureString 
#note cannot convert this!
#----------------------------------------------------------------
#the infamous DOUBLE HOP CRED PROBLEM!!!!
$creds = Get-Credential domain\jake
 Invoke-Command -ComputerName WSUS -ScriptBlock { 
    Invoke-Command -ComputerName DHCP -ScriptBlock {Get-Service -Name BITS}
} 

$creds = Get-Credential domain\jake
Invoke-Command -ComputerName WSUS -ScriptBlock { 
    Invoke-Command -ComputerName DHCP -Credential $using:creds -ScriptBlock {Get-Service -Name BITS}
} 
#----------------------------------------------------------------
Get-cluster * -Domain domain.local
#----------------------------------------------------------------
function Get-ImpersonatetLib {
	if ($script:ImpersonateLib) {
		return $script:ImpersonateLib
	}
	
	$sig = @'
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

[DllImport("kernel32.dll")]
public static extern Boolean CloseHandle(IntPtr hObject);
'@
	$script:ImpersonateLib = Add-Type -PassThru -Namespace 'Lib.Impersonation' -Name ImpersonationLib -MemberDefinition $sig
	
	return $script:ImpersonateLib
	
}
function ImpersonateAs([PSCredential]$cred) {
	[IntPtr]$userToken = [Security.Principal.WindowsIdentity]::GetCurrent().Token
	$userToken
	$ImpersonateLib = Get-ImpersonatetLib
	
	$bLogin = $ImpersonateLib::LogonUser($cred.GetNetworkCredential().UserName, $cred.GetNetworkCredential().Domain, $cred.GetNetworkCredential().Password,
		9, 0, [ref]$userToken)
	
	if ($bLogin) {
		$Identity = New-Object Security.Principal.WindowsIdentity $userToken
		$context = $Identity.Impersonate()
	}
	else {
		throw "Can't Logon as User $cred.GetNetworkCredential().UserName."
	}
	$context, $userToken
}
function CloseUserToken([IntPtr]$token) {
	$ImpersonateLib = Get-ImpersonatetLib
	
	$bLogin = $ImpersonateLib::CloseHandle($token)
	if (!$bLogin) {
		throw "Can't close token"
	}
}
$credential = Get-Credential
						
($oldToken, $context, $newToken) = ImpersonateAs -cred $Credential
#----------------------------------------------------------------
#commands from this point forward will be run as the credential you provided
Get-cluster * -Domain domain.local
#----------------------------------------------------------------
#interacting with azure credentials
$Credential = Get-AutomationPSCredential -Name 'MPC-J'
#----------------------------------------------------------------