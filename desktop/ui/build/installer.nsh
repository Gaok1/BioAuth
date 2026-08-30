; Windows installer customisation for PhoneAuth.
;
; The only thing added beyond a normal install is a Startup shortcut. PhoneAuth
; is a background authenticator: it has to be listening before the user needs to
; approve anything, and an app the user must remember to launch first is one
; that is never running at the moment it matters.
;
; The shortcut points at the tray, not at the agent. The tray starts the agent
; when nothing is already serving (see `src/agent-supervisor.js`), so one entry
; brings up both and there is no second process to leave orphaned.

!macro customInstall
  CreateShortCut "$SMSTARTUP\PhoneAuth.lnk" "$INSTDIR\PhoneAuth.exe"
  CreateShortCut "$SMPROGRAMS\PhoneAuth File Locker.lnk" "$INSTDIR\resources\file-manager\phone-auth-file-manager.cmd" "" "$INSTDIR\PhoneAuth.exe" 0
  CreateShortCut "$DESKTOP\PhoneAuth File Locker.lnk" "$INSTDIR\resources\file-manager\phone-auth-file-manager.cmd" "" "$INSTDIR\PhoneAuth.exe" 0

  ; Keep the extension's existing default handler intact. PhoneAuth appears in
  ; Open With and adds explicit verbs; installing a security tool must not
  ; silently seize a file type another program already owns.
  WriteRegStr HKCU "Software\Classes\.balock\OpenWithProgids" "BioAuth.Locker" ""
  WriteRegStr HKCU "Software\Classes\BioAuth.Locker" "" "BioAuth locked file"
  WriteRegStr HKCU "Software\Classes\BioAuth.Locker\DefaultIcon" "" "$INSTDIR\PhoneAuth.exe,0"
  WriteRegStr HKCU "Software\Classes\BioAuth.Locker\shell\open" "MUIVerb" "Unlock with PhoneAuth"
  WriteRegStr HKCU "Software\Classes\BioAuth.Locker\shell\open\command" "" '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\file-manager\phone-auth-file-manager.ps1" -Action unlock "%1"'
  WriteRegStr HKCU "Software\Classes\SystemFileAssociations\.balock\shell\BioAuth.Unlock" "MUIVerb" "Unlock with PhoneAuth"
  WriteRegStr HKCU "Software\Classes\SystemFileAssociations\.balock\shell\BioAuth.Unlock\command" "" '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\file-manager\phone-auth-file-manager.ps1" -Action unlock "%1"'
  WriteRegStr HKCU "Software\Classes\*\shell\BioAuth.Lock" "MUIVerb" "Lock with PhoneAuth..."
  WriteRegStr HKCU "Software\Classes\*\shell\BioAuth.Lock" "AppliesTo" 'System.FileExtension:<>".balock"'
  WriteRegStr HKCU "Software\Classes\*\shell\BioAuth.Lock\command" "" '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\file-manager\phone-auth-file-manager.ps1" -Action lock "%1"'
!macroend

!macro customUnInstall
  Delete "$SMSTARTUP\PhoneAuth.lnk"
  Delete "$SMPROGRAMS\PhoneAuth File Locker.lnk"
  Delete "$DESKTOP\PhoneAuth File Locker.lnk"
  DeleteRegValue HKCU "Software\Classes\.balock\OpenWithProgids" "BioAuth.Locker"
  DeleteRegKey HKCU "Software\Classes\BioAuth.Locker"
  DeleteRegKey HKCU "Software\Classes\SystemFileAssociations\.balock\shell\BioAuth.Unlock"
  DeleteRegKey HKCU "Software\Classes\*\shell\BioAuth.Lock"
!macroend
