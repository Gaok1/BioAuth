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
!macroend

!macro customUnInstall
  Delete "$SMSTARTUP\PhoneAuth.lnk"
!macroend
