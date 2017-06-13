# Trustlook WannaCry Vaccine Tool

The WannaCry Vaccine Tool helps users protecting their systems from being infected by WannaCry Ransomeware

## Install and Usage

### 1. Run

tl_wannacry_console.exe and tl_wannacry_no_console.exe prevent WannaCry Ransomeware to encrypt
user's files.

The two tools work similarly, except tl_wannacry_console.exe comes with a console 
to show progress information. tl_wannacry_no_console.exe runs in background.

Users may want to add tl_wannacry_no_console.exe to Windows startup script, so everytime users
start their computers, Trustlook WannaCry Vaccine Tool starts protecting their systems from being
infected.

### 2. Add to Windows startup script
add tl_wannacry_no_console.exe value to following register scripts

```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

## Tech details and update
Please check out Trustlook blog at [https://blog.trustlook.com/](https://blog.trustlook.com/)

## Install SEcurity Path From Microsoft

### For general windows system, download at:
[https://technet.microsoft.com/en-us/library/security/ms17-010.aspx](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx)

### For Windows XP, 2003, Vista and Windows 8 system, download at:
[http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598](http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598)
