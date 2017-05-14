# Trustlook WannaCry Vaccine Tool

The WannaCry Vaccine Tool help user to prevent your system from being affected by WannaCry Ransomeware

## Install and Usage

# 1. Run

tl_wannacry_console.exe and tl_wannacry_no_console.exe prevent WannaCry Ransomeware to encrypt
user's files.

The two tools works pretty much the same, except tl_wannacry_console.exe comes with a console 
to show some progress information. tl_wannacry_no_console.exe runs in background.

Users may want to add tl__wannacry_no_console.exe to Windows startup script, so everytime user
start his computer, Trustlook WannaCry Vaccine Tool will start prevent your system from being
affected.

# 2. Add to Windows startup script
add tl_wannacry_no_console.exe value to following register script

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

## Tech details and update
Please check out Trustlook blog at [https://blog.trustlook.com/](https://blog.trustlook.com/)
