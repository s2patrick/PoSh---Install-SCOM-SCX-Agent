<#
.SYNOPSIS

This script is used to manual install, sign and discover an Linux agent.

(c) 27.06.2017, Patrick Seidl, s2 - seidl solutions

.DESCRIPTION

The script connects to the new Linux machine, configures optionally the firewall, 
install the agent, sign the certificate and discover the new agent.

The script has the following prerequisites:

1. Posh-SSH module
    https://github.com/darkoperator/Posh-SSH
    Find-Module Posh-SSH | Install-Module
    Get-Command -Module Posh-SSH
2. Port 22 and 1270 needs to be open from the MS in the RP to the Linux machine.
3. The user needs to have sudo rights:
    sudo  vi /etc/sudoers.d/waagent
    <username> ALL=(ALL) NOPASSWD: ALL
4. Name Resolution (DNS, hosts) needs to be configured for the Linux machine.
5. The computername must match the DNS name.
6. UAC may be disabled (otherwise cert signing will show the UAC prompt).

The script has been tested with RHEL 7.3

.PARAMETER computername

The computername should match the exact name of the Linux machine. 
If this is a FQDN, you should provide it as FQDN here as well.

.PARAMETER resourcePoolName

The script expects a resource pool.

.PARAMETER sshUserName

This is the user with SUDO rights the script uses to connect to the Linux machine.

.PARAMETER sshPassword

And the users password.

.PARAMETER installAgent

If present the script will install the agent; otherwise it will only sign the certs 
and configure the agent (in case of deployment through another tool).

.PARAMETER setFirewall

If present the local Linux firewall will be configured; otherwise not.

.PARAMETER firewallZone

The zone for which the configuration should be made.
Samples are work, internal, trusted, public or any other which applies

.PARAMETER scom2012r2

The scom2012r2 switch does only the signing, not the installation of the agent.

.EXAMPLE

.\Install-ScxAgent.ps1 -computername "testRhelVm.westeurope.cloudapp.azure.com" -resourcePoolName "Linux Devices Resource Pool" -sshUsername "root" -sshPassword "putyouraccountspasswordhere" -installAgent -setFirewall $true -firewallZone "public"

 This sample installs the agent and configures the firewall.

.EXAMPLE

.\Install-ScxAgent.ps1 -computername "testRhelVm.westeurope.cloudapp.azure.com" -resourcePoolName "Linux Devices Resource Pool" -sshUsername "root" -sshPassword "putyouraccountspasswordhere" -installAgent

 This sample installs the agent and does not configure the firewall

.EXAMPLE

.\Install-ScxAgent.ps1 -computername "testRhelVm.westeurope.cloudapp.azure.com" -resourcePoolName "Linux Devices Resource Pool" -sshUsername "root" -sshPassword "putyouraccountspasswordhere"

 This sample only signs the cert and configures the agent and does not configure the firewall
#>

param(
    [Parameter(Mandatory=$true)] 
    [string]$computername,
    [Parameter(Mandatory=$true)] 
    [string]$resourcePoolName,
    [Parameter(Mandatory=$true)] 
    [string]$sshUsername,
    [Parameter(Mandatory=$true)] 
    $sshPassword,
    [Parameter(Mandatory=$false)] 
    [switch]$installAgent,
    [Parameter(Mandatory=$false)] 
    [switch]$setFirewall,
    [Parameter(Mandatory=$false)] 
    [string]$firewallZone,
    [Parameter(Mandatory=$false)] 
    [switch]$scom2012r2
)

<#
# some test values
$computername = "fqdn"
$resourcePoolName = "UNIX Resource Pool MEDC" 
$sshUsername = "user" 
$sshPassword = "password"
#>

Import-Module OperationsManager
Import-Module Posh-SSH

# credentials for SSH
$sshPassword = ConvertTo-SecureString $sshPassword -AsPlainText -Force
$sshCredential = New-Object System.Management.Automation.PsCredential($sshUsername, $sshPassword)

# credentials for SSH used in SCX command
$sshScxCredential = New-Object Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.CredentialSet
$scred = New-Object Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.PosixHostCredential
$scred.Usage = 16
$scred.PrincipalName = $sshUsername
$scred.Passphrase = $sshPassword
$sshScxCredential.Add($scred)

# initiate new SSH session
try {
    Write-Host "initiate new SSH session"
    $sshSession = New-SSHSession -ComputerName $computername -Credential $sshCredential -AcceptKey -ErrorAction stop
} catch {
    Write-Host "Could not initiate SSH session" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    Break
}

# set Firewall rules for WinRM (optionally)
if ($setFirewall) {
    try {
        if (!$firewallZone) {throw "Firewall Zone has not been provided"}
        Write-Host "set Firewall rules for WinRM"
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo firewall-cmd --zone=$firewallZone --add-port=1270/tcp --permanent" -TimeOut 60
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo firewall-cmd --zone=$firewallZone --add-port=1270/udp --permanent" -TimeOut 60
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo firewall-cmd --reload" -TimeOut 60
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
    } catch {
        Write-Host "Could not configure firewall for port 1270" -ForegroundColor Red
        Write-Host $Error[0].Exception.Message -ForegroundColor Red
    }
}

$installDirectory = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" -Name InstallDirectory).InstallDirectory
if ($installAgent) {
    # get sources folder
    $agentDirectory = Join-Path $installDirectory "AgentManagement\UnixAgents"
    $agentDownloadedKits = Join-Path $installDirectory "AgentManagement\UnixAgents\DownloadedKits"

    # copy and run OS check script
    try {
        Write-Host "copy and run OS check script"
        $getOsVersion = Join-Path $agentDirectory "GetOSVersion.sh"
        Set-SCPFile -ComputerName $computername -LocalFile $getOsVersion -RemotePath /tmp -Credential $sshCredential -AcceptKey $true -ConnectionTimeout 300 -ErrorAction stop
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo chmod u+x /tmp/GetOSVersion.sh" -TimeOut 60
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
        $osVersionOut = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "/tmp/GetOSVersion.sh" -TimeOut 60
        if ($osVersionOut.ExitStatus -ne 0) {throw $output.ExitStatus}
        [xml]$osVersion  = $osVersionOut.output
    } catch {
        Write-Host "Could not run OS check script" -ForegroundColor Red
        Write-Host $Error[0].Exception.Message -ForegroundColor Red
        Break
    }

    # get Linux architecture (sample: "i386" or "x86_64" or "ppc")
    if ($osVersion.DiscoveredOS.Arch -eq "i386") {
        $osArch = "x86"
    } elseif  ($osVersion.DiscoveredOS.Arch -eq "x86_64") {
        $osArch = "x64"
    } else {
        $osArch = "ppc"
    }

    # copy agent to Linux VM
    try {
        Write-Host "copy agent to Linux VM"
        $agentFile = gci $agentDownloadedKits | ? {$_.Name -match ($osVersion.DiscoveredOS.OSAlias.ToLower())+"."+($osVersion.DiscoveredOS.Version.split(".")[0])+"."+$osArch} | sort CreationTime | select -last 1
        Set-SCPFile -ComputerName $computername -LocalFile $agentFile.FullName -RemotePath /tmp -Credential $sshCredential -AcceptKey $true -ConnectionTimeout 600 -ErrorAction stop
    } catch {
        Write-Host "Could not copy agent sources" -ForegroundColor Red
        Write-Host $Error[0].Exception.Message -ForegroundColor Red
        Break
    }

    # install agent
    try {
        Write-Host "install agent"
        $agentFilePath = "/tmp/"+ $agentFile.Name
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo chmod a+x $agentFilePath" -TimeOut 300
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo $agentFilePath --install" -TimeOut 300
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
    } catch {
        Write-Host "Could not install agent" -ForegroundColor Red
        Write-Host $Error[0].Exception.Message -ForegroundColor Red
        Break
    }
}

# verify agent on VM
try {
    Write-Host "verify agent on VM"
    $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "rpm -q scx" -TimeOut 60
    if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
} catch {
    Write-Host "Installation NOT verified" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    Break
}

# copy .pem to SCOM MS
try {
    Write-Host "copy .pem to SCOM MS"
    if ($scom2012r2) {
        # SCOM 2012 R2:
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "ls /etc/opt/microsoft/scx/ssl/*-host-*.pem | head -1" -TimeOut 60
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
    } else {
        # SCOM 2016:
        $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "ls /etc/opt/omi/ssl/*-host-*.pem | head -1" -TimeOut 60
        if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
    }
    [string]$scxCertOri = $output.Output
    $winCertOri = (Join-Path $env:temp (($scxCertOri.split("/")[-1]).split(".")[0] + "_ori.pem"))
    Get-SCPFile -ComputerName $computername -RemoteFile $scxCertOri -LocalFile $winCertOri -Credential $sshCredential -AcceptKey -ConnectionTimeout 300 -ErrorAction stop
} catch {
    Write-Host "Could not copy unsigned certificate from agent" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    Break
}

# sign cert
try {
    Write-Host "sign cert"
    $winCertNew = (Join-Path $env:temp (($scxCertOri.split("/")[-1]).split(".")[0] + "_new.pem"))
    $arguments = " -sign $winCertOri $winCertNew"
    Start-Process (Join-Path $installDirectory scxcertconfig.exe) -verb runas -ArgumentList $arguments -ErrorAction stop
} catch {
    Write-Host "Could not sign certificate" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    Break
}

# copy new .pem to VM
try {
    Write-Host "copy new .pem to VM"
    Set-SCPFile -ComputerName $computername -LocalFile $winCertNew -RemotePath /tmp -Credential $sshCredential -AcceptKey $true -ConnectionTimeout 300 -ErrorAction stop
    $scxCertNew = "/tmp/"+(($scxCertOri.split("/")[-1]).split(".")[0] + "_new.pem")
    $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo cp --force $scxCertNew $scxCertOri" -TimeOut 60
    if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
} catch {
    Write-Host "Could not copy signed certificate to agent" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    Break
}

# restart agent
try {
    Write-Host "restart agent"
    $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "sudo scxadmin -restart" -TimeOut 60
    if ($output.ExitStatus -ne 0) {throw $output.ExitStatus}
} catch {
    Write-Host "Could not restart agent; please try manually" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
}

# run discovery
try {
    Write-Host "run discovery"
    $resourcePool = Get-SCOMResourcePool | ? {$_.DisplayName -eq "$resourcePoolName"}
    Invoke-SCXDiscovery -Name $computername -ResourcePool $resourcePool -WSManCredential $sshCredential -SshCredential $sshScxCredential -ErrorAction stop | Install-SCXAgent -ErrorAction stop
} catch {
    Write-Host "Could not discover agent; please try manually" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
}

# verify agent in MG
try {
    Write-Host "verify agent in MG"
    Get-SCXAgent | ? { $_.Name -eq $computername -or $_.IPAddress -eq $computername}
} catch {
    Write-Host "Could not verify agent in SCOM" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
}

# cleanup
Write-Host "cleanup"
$output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "rm /tmp/GetOSVersion.sh" -TimeOut 60
$output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "rm $agentFilePath" -TimeOut 60
Remove-Item -Path $winCertOri -Force
Remove-Item -Path $winCertNew -Force
$output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "rm $scxCertNew" -TimeOut 60

Write-Host "Finish. Have a great day." -ForegroundColor Green