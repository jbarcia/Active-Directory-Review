@echo off

REM Active Directory Review - Checks your configs and settings to review for AD Security
REM Copyright (C) 2014 Joseph Barcia - joseph@barcia.me
REM https://github.com/jbarcia
REM
REM License
REM -------
REM This tool may be used for legal purposes only.  Users take full responsibility
REM for any actions performed using this tool.  The author accepts no liability
REM for damage caused by this tool.  If you do not accept these condition then
REM you are prohibited from using this tool.
REM
REM In all other respects the GPL version 2 applies:
REM
REM This program is free software; you can redistribute it and/or modify
REM it under the terms of the GNU General Public License version 2 as
REM published by the Free Software Foundation.
REM
REM This program is distributed in the hope that it will be useful,
REM but WITHOUT ANY WARRANTY; without even the implied warranty of
REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
REM GNU General Public License for more details.
REM
REM You should have received a copy of the GNU General Public License along
REM with this program; if not, write to the Free Software Foundation, Inc.,
REM 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
REM
REM You are encouraged to send comments, improvements or suggestions to
REM me at joseph@barcia.me
REM
REM
REM Description
REM -----------
REM Auditing tool to check your configs and settings to review for AD Security.
REM 
REM It is intended to be run by security auditors and pentetration testers 
REM against systems they have been engaged to assess, and also by system 
REM admnisitrators who want to check configuration files for PCI Compliance.
REM
REM Ensure that you have the appropriate legal permission before running it
REM someone else's system.
REM
REM
REM Changelog
REM ---------
REM
REM ------------
set version=1.0
REM ------------



REM sets file location to where the script is run from
set filedir=%~dp0


REM Needed Variables - DO NOT CHANGE
REM ******************************************************************************
REM Sets date
for /f "tokens=1-4 delims=/ " %%a in ('date /t') do (set weekday=%%a& set month=%%b& set day=%%c& set year=%%d)
for /f "tokens=1-3 delims=: " %%a in ('TIME /t') do (set hour=%%a& set minute=%%b& set second=%%c)
set fdate=%year%%month%%day%-%hour%%minute%
REM echo %fdate%
SETLOCAL EnableDelayedExpansion
REM Sets Hostname
FOR /F "usebackq" %%i IN (`hostname`) DO SET Hostname=%%i

set tempdir=%USERPROFILE%\Desktop\%fdate%-%SiteName%-%Hostname%
REM ******************************************************************************

cls

:Top
echo Active Directory Review V_%version%
echo:
echo:

if not exist "%filedir%\tools\7za.exe" GOTO MissingFiles

:Assessment
	echo Enter Site Name
	set /p SiteName= : %=%
	echo:
	set tempdir=%USERPROFILE%\Desktop\%fdate%-%SiteName%-%Hostname%
	if exist "%tempdir%" echo *****WARNING: %tempdir% already exists rename the folder to prevent data loss***** && pause
	if not exist "%tempdir%" mkdir "%tempdir%"
echo:

:Domain
cls
color 0A
echo Active Directory Review V_%version%
echo:
echo:
echo SITE:  	%SiteName% 
echo:
echo --------------------------------------------------
echo Configuring the Domain Information (ex. domain.com)
echo --------------------------------------------------
echo Enter the Sub Domain without the (.) (left label) (ex. domain)
set /p subdomain= : %=%
echo:
echo:
echo Enter the Top Level Domain without the (.) (right-most label) (ex. com)
set /p top-level-domain= : %=%
echo:
echo:
echo:
echo DOMAIN:	%subdomain%.%top-level-domain%
echo Is the Domain correct? [Y]
set answer=n
set /p answer= : %=%
IF %answer%==n GOTO Domain
IF %answer%==N GOTO Domain
IF %answer%==y GOTO Script
IF %answer%==Y GOTO Script


:Script
REM Lets make some directories...
	mkdir "%tempdir%\Domain Info"
	mkdir "%tempdir%\Server Config"
	mkdir "%tempdir%\Domain Policies"
	mkdir "%tempdir%\Domain Users and Groups"
	if not exist "%filedir%\Saved" mkdir "%filedir%\Saved"


cls
color 0A
echo Active Directory Review V_%version%
echo			Domain Information
echo:
echo:
echo SITE:  	%SiteName% 
echo DOMAIN:	%subdomain%.%top-level-domain%
echo:
	echo --------------------------------------------------
	echo Domain Servers
	echo --------------------------------------------------
		dsquery server >> "%tempdir%\Domain Info\%Hostname% Domain Servers - 1.txt"
		nltest /dclist:%userdnsdomain% >> "%tempdir%\Domain Info\%Hostname% Domain Servers - 2.txt"
	echo --------------------------------------------------
	echo Domain Server Roles 
	echo --------------------------------------------------
		netdom query fsmo >> "%tempdir%\Domain Info\%Hostname% Domain Roles.txt"
	echo --------------------------------------------------
	echo AD Site Information
	echo --------------------------------------------------
		dsquery * "CN=Sites,CN=Configuration,DC=%subdomain%,DC=%top-level-domain%" -attr cn description location -filter (objectClass=site) >> "%tempdir%\Domain Info\%Hostname% Domain Site Info - 1.txt"
		dsquery * "CN=Sites,CN=Configuration,DC=%subdomain%,DC=%top-level-domain%" -attr cn costdescription replInterval siteList -filter (objectClass=siteLink) >> "%tempdir%\Domain Info\%Hostname% Domain Site Info - 2.txt"
	echo --------------------------------------------------
	echo AD Replication
	echo --------------------------------------------------
		repadmin /istg * /verbose >> "%tempdir%\Domain Info\%Hostname% AD Replication - 1.txt"
		repadmin /latency /verbose >> "%tempdir%\Domain Info\%Hostname% AD Replication - 2.txt"
		repadmin /queue * >> "%tempdir%\Domain Info\%Hostname% AD Replication - 3.txt"
		repadmin /viewlist * >> "%tempdir%\Domain Info\%Hostname% AD Replication - 4.txt"
	echo --------------------------------------------------
	echo Domain Trusts 
	echo --------------------------------------------------
		nltest /domain_trusts /v >> "%tempdir%\Domain Info\%Hostname% AD Trusts.txt"
	echo --------------------------------------------------
	echo Forest Functional Level
	echo --------------------------------------------------
		dsquery * "CN=Partitions,CN=Configuration,DC=%subdomain%,DC=%top-level-domain%" -scope base -attr msDS-Behavior-Version >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
			echo:
			echo Conversion table: >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
			echo 0 = Windows 2000 >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
			echo 1 = Windows 2003 interim >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
			echo 2 = Windows 2003 >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
			echo 3 = Windows 2008 >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
			echo 4 = Windows 2008 R2 >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
			echo 5 = Windows 2012 >> "%tempdir%\Domain Info\%Hostname% AD Forest Functional Level.txt"
	echo --------------------------------------------------
	echo Domain Functional Level
	echo --------------------------------------------------
		dsquery * "DC=%subdomain%,DC=%top-level-domain%" -scope base -attr msDS-Behavior-Version ntMixedDomain >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
			echo:
			echo Conversion table: >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
			echo 0, 0 = Windows 2000 Native >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
			echo 0, 1 = Windows 2000 Mixed >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
			echo 2, 0 = Windows 2003 >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
			echo 3, 0 = Windows 2008 >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
			echo 4, 0 = Windows 2008 R2 >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
			echo 5, 0 = Windows 2012 >> "%tempdir%\Domain Info\%Hostname% AD Domain Functional Level.txt"
	echo --------------------------------------------------
	echo Active Directory Schema Version
	echo --------------------------------------------------
		dsquery * "CN=Schema,CN=Configuration,DC=%subdomain%,DC=%top-level-domain%" -scope base -attr objectVersion >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
			echo:
			echo Conversion table: >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
			echo 13 = Windows 2000 Server >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
			echo 30 = Windows Server 2003 RTM, Windows Server 2003 with Service Pack 1, Windows Server 2003 with Service Pack 2 >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
			echo 31 = Windows Server 2003 R2 >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
			echo 44 = Windows Server 2008 RTM >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
			echo 47 = Windows Server 2008 R2 >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
			echo 56 = Windows Server 2012 RTM >> "%tempdir%\Domain Info\%Hostname% AD Schema Version.txt"
pause

cls
color 0A
echo Active Directory Review V_%version%
echo			Server Configuration
echo:
echo:
echo SITE:  	%SiteName% 
echo DOMAIN:	%subdomain%.%top-level-domain%
echo:
	echo --------------------------------------------------
	echo  System Information
	echo --------------------------------------------------
		systeminfo >> "%tempdir%\Server Config\%Hostname% System Info.txt"
		msinfo32 /nfo "%tempdir%\Server Config\%Hostname% System Info.NFO" /categories +all
	echo --------------------------------------------------
	echo  ADDS Version
	echo --------------------------------------------------
		reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters" >> "%tempdir%\Server Config\%Hostname% ADDS Info.txt"
	echo --------------------------------------------------
	echo  Patch Information
	echo --------------------------------------------------
		wmic qfe list full /format:htable >> "%tempdir%\Server Config\%Hostname% Patch Info.txt"
	echo --------------------------------------------------
	echo  Listening and Running Services
	echo --------------------------------------------------
		netstat -nabor >> "%tempdir%\Server Config\%Hostname% Listening Services.txt"
		sc queryex >> "%tempdir%\Server Config\%Hostname% Running Services.txt"
	echo --------------------------------------------------
	echo  Network Information
	echo --------------------------------------------------
		ipconfig /all >> "%tempdir%\Server Config\%Hostname% Network Info.txt"
	echo --------------------------------------------------
	echo  Local Accounts and Password Parameters
	echo --------------------------------------------------
		net accounts >> "%tempdir%\Server Config\%Hostname% Local Password Settings.txt"
		net localgroup administrators >> "%tempdir%\Server Config\%Hostname% Local Administrators.txt"
	echo --------------------------------------------------
	echo Grabbing the Screensaver Settings
	echo --------------------------------------------------
		reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive >> "%tempdir%\Server Config\%Hostname% Screensaver Settings.txt"
		reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure >> "%tempdir%\Server Config\%Hostname% Screensaver Settings.txt"
		reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveTimeOut >> "%tempdir%\Server Config\%Hostname% Screensaver Settings.txt" 
	echo --------------------------------------------------
	echo Grabbing RDP Encryption and Idle Settings
	echo --------------------------------------------------
		reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel >> "%tempdir%\Server Config\%Hostname% RDP Encryption Setting.txt"
		echo: >> "%tempdir%\Server Config\%Hostname% RDP Encryption Setting.txt"
		echo 1 = low >> "%tempdir%\Server Config\%Hostname% RDP Encryption Setting.txt"
		echo 2 = client compatible >> "%tempdir%\Server Config\%Hostname% RDP Encryption Setting.txt"
		echo 3 = high >> "%tempdir%\Server Config\%Hostname% RDP Encryption Setting.txt"
		echo 4 = fips >> "%tempdir%\Server Config\%Hostname% RDP Encryption Setting.txt"
		reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxIdleTime >> "%tempdir%\Server Config\%Hostname% RDP Timeout Setting.txt"
	echo --------------------------------------------------
	echo  Grabbing Scheduled Jobs
	echo --------------------------------------------------
		schtasks /query /fo CSV /v >> "%tempdir%\Server Config\%Hostname% Scheduled Tasks.csv"
	echo --------------------------------------------------
	echo  Grabbing Local Firewall Settings
	echo --------------------------------------------------
		netsh advfirewall firewall show rule name=all >> "%tempdir%\Server Config\%Hostname% Local Firewall Settings.txt"
	echo --------------------------------------------------
	echo  Grabbing NTP Settings
	echo --------------------------------------------------
		reg query HKLM\SYSTEM\CurrentControlSet\services\W32Time\Parameters\ /v NtpServer >> "%tempdir%\Server Config\%Hostname% NTP Configurations.txt"  
pause

cls
color 0A
echo Active Directory Review V_%version%
echo				Domain Policies
echo:
echo:
echo SITE:  	%SiteName% 
echo DOMAIN:	%subdomain%.%top-level-domain%
echo:

	echo --------------------------------------------------
	echo Group Policies
	echo --------------------------------------------------
		gpresult /z >> "%tempdir%\Domain Policies\%Hostname% GPO Dump.txt"
REM PowerShell Commands
	powershell -Command "&{import-module grouppolicy; Get-GPOReport -All -Domain %subdomain%.%top-level-domain% -ReportType html -Path '%tempdir%\Domain Policies\%Hostname% AllGPOsReport.html';}"
	echo --------------------------------------------------
	echo Domain Password Parameters
	echo --------------------------------------------------
		net accounts /domain >> "%tempdir%\Domain Policies\%Hostname% Domain Password Parameters.txt"
	echo --------------------------------------------------
	echo Audit Policies
	echo --------------------------------------------------
		auditpol.exe /get /category:* >> "%tempdir%\Domain Policies\%Hostname% Audit Policies.txt"
pause

cls
color 0A
echo Active Directory Review V_%version%
echo			Domain Users and Groups
echo:
echo:
echo SITE:  	%SiteName% 
echo DOMAIN:	%subdomain%.%top-level-domain%
echo:

	echo --------------------------------------------------
	echo Inactive computer accounts 
	echo --------------------------------------------------
		dsquery computer domainroot -stalepwd 180 -limit 0 >> "%tempdir%\Domain Users and Groups\%Hostname% Inactive computers.txt"
	echo --------------------------------------------------
	echo Inactive user accounts 
	echo --------------------------------------------------
		dsquery user domainroot -stalepwd 180 -limit 0 >> "%tempdir%\Domain Users and Groups\%Hostname% Inactive users - 1.txt"
		dsquery user "dc=%subdomain%,dc=%top-level-domain%" -inactive 13 -limit 0 >> "%tempdir%\Domain Users and Groups\%Hostname% Inactive users - 2.txt"
	echo --------------------------------------------------
	echo User accounts with no password required 
	echo --------------------------------------------------
		dsquery * domainroot -filter "(&(objectCategory=Person)(objectClass=User)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr samaccountname name >> "%tempdir%\Domain Users and Groups\%Hostname% user no password.txt"
	echo --------------------------------------------------
	echo User accounts with no password expiry 
	echo --------------------------------------------------
		dsquery * -limit 0 -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -attr samaccountname name >> "%tempdir%\Domain Users and Groups\%Hostname% user no password expiry.txt"
	echo --------------------------------------------------
	echo Dump of Enabled Active Directory users
	echo --------------------------------------------------
		dsquery * -filter (msRTCSIP-UserEnabled=TRUE) -limit 0 -attr samaccountname name >> "%tempdir%\Domain Users and Groups\%Hostname% Domain Active Users.txt"
	echo --------------------------------------------------
	echo Dump of Disabled Active Directory users
	echo --------------------------------------------------
		dsquery user "dc=%subdomain%,dc=%top-level-domain%" -disabled -limit 0 >> "%tempdir%\Domain Users and Groups\%Hostname% Domain Disabled Users.txt"
	echo --------------------------------------------------
	echo  Grabbing Default Administrator Groups
	echo --------------------------------------------------
		dsget group "CN=Enterprise Admins,OU=SecurityGroups,dc=%subdomain%,dc=%top-level-domain%" -members | dsget user -samid -fn -mi -ln -display >> "%tempdir%\Domain Users and Groups\%Hostname% Enterprise Admins.txt"
		dsget group "CN=Schema Administrators,OU=SecurityGroups,dc=%subdomain%,dc=%top-level-domain%" -members | dsget user -samid -fn -mi -ln -display >> "%tempdir%\Domain Users and Groups\%Hostname% Schema Admins.txt"
		dsget group "CN=Domain Administrators,OU=SecurityGroups,dc=%subdomain%,dc=%top-level-domain%" -members | dsget user -samid -fn -mi -ln -display >> "%tempdir%\Domain Users and Groups\%Hostname% Domain Admins.txt"
		dsget group "CN=Server Operators,OU=SecurityGroups,dc=%subdomain%,dc=%top-level-domain%" -members | dsget user -samid -fn -mi -ln -display >> "%tempdir%\Domain Users and Groups\%Hostname% Server Operators.txt"
		dsget group "CN=Account Operators,OU=SecurityGroups,dc=%subdomain%,dc=%top-level-domain%" -members | dsget user -samid -fn -mi -ln -display >> "%tempdir%\Domain Users and Groups\%Hostname% Account Operators.txt"
		dsget group "CN=Backup Operators,OU=SecurityGroups,dc=%subdomain%,dc=%top-level-domain%" -members | dsget user -samid -fn -mi -ln -display >> "%tempdir%\Domain Users and Groups\%Hostname% Backup Operators.txt"

echo:
	echo --------------------------------------------------
	echo Dump of users and Their Last Password Change
	echo --------------------------------------------------	 
		FOR /F "skip=1 tokens=1-4 delims= " %%a IN ('Dsquery * -filter "&(objectClass=User)(objectCategory=Person)" -limit 0 -attr name pwdlastset ') DO (
			FOR /F "tokens=3-4 delims=-( " %%w IN ('%systemroot%\system32\w32tm /ntte %%b') DO SET tmpLLTS=%%w 
			FOR /F "tokens=3-4 delims=-( " %%x IN ('%systemroot%\system32\w32tm /ntte %%c') DO SET tmpPLT=%%x 
			FOR /F "tokens=4-4 delims=-( " %%y IN ('%systemroot%\system32\w32tm /ntte %%b') DO SET tmpLLLTS=%%y
			FOR /F "tokens=4-4 delims=-( " %%z IN ('%systemroot%\system32\w32tm /ntte %%c') DO SET tmpPLLT=%%z 
			FOR /F "tokens=5-5 delims=-( " %%t IN ('%systemroot%\system32\w32tm /ntte %%b') DO SET tmpPLLLT=%%t
		REM	echo %%a	!tmpLLTS!	!tmpPLT!	!tmpLLLTS!	!tmpPLLT!	!tmpPLLLT! >> "%tempdir%\Req 8\8.5 %Hostname% Users Last Password Changed.txt")
		echo %%a	!tmpLLLTS! ----- !tmpPLT!	!tmpPLLT!	!tmpPLLLT! >> "%tempdir%\Domain Users and Groups\%Hostname% Users Last Password Changed.txt")




pause
	echo --------------------------------------------------
	echo  Packaging up the Files
	echo --------------------------------------------------
		cd %filedir%\tools\
		7za.exe a -t7z "%USERPROFILE%\Desktop\%fdate%-%SiteName%-%Hostname%.7z" "%tempdir%\*.*" -r
		rmdir "%tempdir%" /s /q
	echo .
	echo ..
	echo ...
	echo ....
	echo Your files are located here: 
	echo %USERPROFILE%\Desktop\%fdate%-%SiteName%-%Hostname%.7z
	pause
	GOTO END
	
:MissingFiles
	echo Files missing...Please extract all of the files including the tools.
	pause

:END
