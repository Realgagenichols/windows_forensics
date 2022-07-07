# Library imports
import subprocess
import os
import sqlite3


'''
ProgramData is a hidden dir on Windows
strip attributes for read-only, system file, and hidden
generate wlan report
'''
os.system("attrib -r -s -h C:\\ProgramData")
os.system("netsh wlan show wlanreport")


'''
Function: run
Parameter: cmd - command to be run
Use: run the command passed in as a parameter using subprocess to call PowerShell
'''
def run(cmd):
	try:
		subprocess.call(["powershell", cmd])
	except:
		print()


'''
Data Structure: List
Name: "script"
Data Held: PS commands 
Use: Holds PS commands to be run by subprocess
'''
script = [ "New-Item -ItemType \"directory\" -Force -Path \"C:\\PCInfo\"",   # Create a directory to store the files
"New-Item -ItemType \"directory\" -Force -Path \"C:\\PCInfo\\ComputerInfo\"",
"New-Item -ItemType \"directory\" -Force -Path \"C:\\PCInfo\\Software\"",
"New-Item -ItemType \"directory\" -Force -Path \"C:\\PCInfo\\Logs\"",
"New-Item -ItemType \"directory\" -Force -Path \"C:\\PCInfo\\Users\"",
"New-Item -ItemType \"directory\" -Force -Path \"C:\\PCInfo\\Network\"",
"New-Item -ItemType \"directory\" -Force -Path \"C:\\PCInfo\\BrowserHistory\"",
"cat (Get-PSReadlineOption).HistorySavePath > C:\\PCInfo\\Logs\\$($env:COMPUTERNAME)_PS-History.txt",   # get the history of PowerShell commands 
"\"TimeCreated\",\"Security ID:\",\"Account Name:\",\"Account Domain:\",\"Logon ID:\",\"Logon Type:\",\"Logon GUID:\",\"Process Name:\" | ForEach-Object {Add-content -path C:\\PCInfo\\searches.txt -Value $_}",  # temp txt file containing searches to use later
"\"TimeCreated\",\"Security ID:\",\"Account Name:\",\"Account Domain:\",\"Logoff ID:\",\"Logoff Type:\",\"Logoff GUID:\",\"Process Name:\" | ForEach-Object {Add-content -path C:\\PCInfo\\searches1.txt -Value $_}",  # temp txt file containing searches to use later
"netstat -anbo | Out-file C:\\PCInfo\\Network\\$($env:COMPUTERNAME)_netstat_anbo.txt",  # get result of netstat (network connections)
"Get-PSDrive | Out-file C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_PSDrive.txt",  # gets the drives in the current session
"ipconfig /all | Out-file C:\\PCInfo\\Network\\$($env:COMPUTERNAME)_ipconfig.txt",  # current TCP/IP network configuration 
"tasklist | Out-file C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_processes.txt",  # current running processes
"gcim Win32_StartupCommand | Out-File C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_StartupApps.txt",  # Displays the commands run at startup
"Get-LocalUser | Select *  | Out-File C:\\PCInfo\\Users\\$($env:COMPUTERNAME)_LocalUsers.txt",  # gets local user accounts - default, created, and local connected to microsoft
"query user | Out-File C:\\PCInfo\\Users\\$($env:COMPUTERNAME)_ActiveUsers.txt",  # information about user session
"Get-EventLog -LogName Security -InstanceId 4800 | Out-File C:\\PCInfo\\Logs\\Lock.txt",
"Get-EventLog -LogName Security -InstanceId 4801 | Out-File C:\\PCInfo\\Logs\\UnLock.txt",
"$LogonTypes=Get-WinEvent -FilterHashtable @{Logname='security';Id=4624} ; foreach ($item in $LogonTypes) {($item | Select TimeCreated, Message | fl * | findstr /G:C:\\PCInfo\\searches.txt ) | Out-File -append C:\\PCInfo\\Logs\\$($env:COMPUTERNAME)_4624-SuccessfulAccountLogon.txt}",  # information about logons to computer
"$LogoffTypes=Get-WinEvent -FilterHashtable @{Logname='security';Id=4634} ; foreach ($item in $LogoffTypes) {($item | Select TimeCreated, Message | fl * | findstr /G:C:\\PCInfo\\searches1.txt ) | Out-File -append C:\\PCInfo\\Logs\\$($env:COMPUTERNAME)_4634-SuccessfulAccountLogOff.txt}", # information about logoffs
"$LogoffTypes=Get-WinEvent -FilterHashtable @{Logname='security';Id=4647} ; foreach ($item in $LogoffTypes) {($item | Select TimeCreated, Message | fl * | findstr /G:C:\\PCInfo\\searches1.txt ) | Out-File -append C:\\PCInfo\\Logs\\$($env:COMPUTERNAME)_4647-User-InitLogOff.txt}", # user initiated logoffs
"Get-CimInstance -ClassName Win32_Product | Select-Object Name,version,Vendor,InstallDate,InstallSource,PackageName,LocalPackage | Out-File -append C:\\PCInfo\\Software\\$($env:COMPUTERNAME)_programs.txt",  # programs installed on the computer
"Get-ItemProperty \"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | Select-Object DisplayName, DisplayVersion, InstallDate, InstallLocation, Publisher | Out-File -append C:\\PCInfo\\Software\\$($env:COMPUTERNAME)_programs.txt", # ext programs installed on the computer
"Get-ItemProperty \"HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | Select-Object DisplayName, DisplayVersion, InstallDate, InstallLocation, Publisher | Out-File -append C:\\PCInfo\\Software\\$($env:COMPUTERNAME)_programs.txt", # ext ext programs installed on the computer
"systeminfo | Out-File -append C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_computer_info.txt",  # information about the computer
"Get-ItemProperty \"HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\" | Select-Object ReleaseID | Out-File -append C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_computer_info.txt",  # append release ID to computer information 
"Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, StartMode, State, PathName, StartName, ServiceType | Out-File -append C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_services.txt",  # services on the computer
"Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State | where Author -NotLike 'MicroSoft*' | where Author -ne $null | where Author -NotLike '*@%SystemRoot%\\*' | Out-File -append C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_scheduled_tasks.txt",  # scheduled tasks on the computer
"Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State | where Author -NotLike 'MicroSoft*' | where Author -ne $null | where Author -NotLike '*@%SystemRoot%\\*' | Select-Object TaskName | ForEach-Object {Export-ScheduledTask -TaskName $_ | Out-File -append C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_scheduled_tasks_more.txt }", # attempts more information about scheduled tasks
"$shell = New-Object -com shell.application ; $rb = $shell.Namespace(10) ; $rb.Items() | Out-File C:\\PCInfo\\Software\\$($env:COMPUTERNAME)_recyclebin.txt",  # contents of the recycle bin
"net share | Out-File C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_networkShares.txt",  # net share
"net use | Out-File C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_mappedDrivesDevices.txt",  # mapped drives
"ipconfig /displaydns | Out-File C:\\PCInfo\\Network\\$($env:COMPUTERNAME)_cachedDNS.txt",   # cached DNS
"type C:\\Windows\\system32\\drivers\\etc\\hosts | Out-File C:\\PCInfo\\Network\\$($env:COMPUTERNAME)_localHosts.txt",
"driverquery | Out-File C:\\PCInfo\\Software\\$($env:COMPUTERNAME)_deviceDrivers.txt",   # device drivers
"dir C:\\Windows\\Prefetch | Out-File C:\\PCInfo\\Software\\$($env:COMPUTERNAME)_prefetchFiles.txt",   # windows prefetch files
"dir C:\\Users | Out-File C:\\PCInfo\\Users\\$($env:COMPUTERNAME)_loggedOnUsers.txt",  # out put of contents from C:\Users
"Get-PnpDevice | Out-File C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_PnpDevicesAll.txt",   # All PnP devices including history
"Get-PnpDevice -PresentOnly | Out-File C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_PnpDevicesCurrent.txt",  # Present PnP devices
"Get-ItemProperty -Path HKLM\\:SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\* | Out-File C:\\PCInfo\\ComputerInfo\\$($env:COMPUTERNAME)_usbHistory.txt",  # history from USBSTOR
"arp -av | Out-File C:\\PCInfo\\Network\\$($env:COMPUTERNAME)_ARP.txt"]  # IP Addresses of LAN Devices

cleanUp =[ "Move-Item -Path C:\\ProgramData\\Microsoft\\Windows\\WlanReport -Destination C:\\PCInfo\\Logs -Force",
"Remove-Item C:\\PCInfo\\searches.txt", # remove the temporary file
"Remove-Item C:\\PCInfo\\searches1.txt" ] # remove the temporary file



'''
For each line in the 'script' list
pass that line as a variable to
the run function to run it using PS
'''
for line in script:
	runLine = run(line)

for line in cleanUp:
	runLine = run(line)

'''
End browser processes
browsers must be closed to access history files
'''
os.system("taskkill /im msedge.exe /f")
os.system("taskkill /im chrome.exe /f")

'''
AppData is a hidden dir on Windows
strip attributes for read-only, system file, and hidden
'''
appPath = 'attrib -r -s -h ' + str(os.path.expanduser('~')) + "\\AppData"
os.system(appPath)

'''
construct path to history files
'''
data_path = os.path.expanduser('~')+"\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
files = os.listdir(data_path)
history_db = os.path.join(data_path, 'history')

'''
connect to history database
perform SQL query for information
'''
c = sqlite3.connect(history_db)
cursor = c.cursor()
select_statement = "SELECT urls.url, urls.title, urls.visit_count, \
        datetime(urls.last_visit_time/1000000-11644473600,'unixepoch','localtime'), urls.hidden,\
        visits.visit_time, visits.transition FROM urls, visits\
         WHERE  urls.id = visits.url and urls.title is not null order by last_visit_time desc "
cursor.execute(select_statement)

# retrieve results
results = cursor.fetchall()

'''
create a .txt document for history
write results to document 
'''
try:
	f = open("C:\\PCInfo\\BrowserHistory\\chrome_history.txt", "a")
except:
	print("")

for url in results:
	urlVisited, title, visitCounts, date, hiddenURL, visitTime, transition = url
	f.write(title+"\n")
	f.write(urlVisited+"\n")
	f.write(date+"\n")
	f.write("Visit time: " + str(visitTime) + "\n")
	f.write("Visit counts: " + str(visitCounts) + "\n")
	f.write("Hidden URLs: " + str(hiddenURL) + "\n")
	f.write("Transition: " + str(transition) + "\n")
	f.write("\n")


'''
similar steps to above browser history query
executed on ms edge
'''
data_path = os.path.expanduser('~')+"\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"
files = os.listdir(data_path)
history_db = os.path.join(data_path, 'history')

c = sqlite3.connect(history_db)
cursor = c.cursor()
select_statement = "SELECT urls.url, urls.title, urls.visit_count, \
        datetime(urls.last_visit_time/1000000-11644473600,'unixepoch','localtime'), urls.hidden,\
        visits.visit_time, visits.transition FROM urls, visits\
         WHERE  urls.id = visits.url and urls.title is not null order by last_visit_time desc "
cursor.execute(select_statement)


results = cursor.fetchall()


try:
	f = open("C:\\PCInfo\\BrowserHistory\\edge_history.txt", "a")
except:
	print("")

for url in results:
	urlVisited, title, visitCounts, date, hiddenURL, visitTime, transition = url
	f.write(title+"\n")
	f.write(urlVisited+"\n")
	f.write(date+"\n")
	f.write("Visit time: " + str(visitTime) + "\n")
	f.write("Visit counts: " + str(visitCounts) + "\n")
	f.write("Hidden URLs: " + str(hiddenURL) + "\n")
	f.write("Transition: " + str(transition) + "\n")
	f.write("\n")