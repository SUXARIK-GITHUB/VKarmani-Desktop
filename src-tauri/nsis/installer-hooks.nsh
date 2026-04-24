; VKarmani NSIS installer hooks.
; Tauri creates the normal shortcuts using productName = "VKarmani".
; Hooks keep upgrades clean and remove legacy duplicate shortcuts.

!macro NSIS_HOOK_PREINSTALL
  ; Stop a running Xray process before replacing bundled core files.
  ; If xray.exe is locked during updater/install, Windows can leave a stale or corrupted core file.
  nsExec::ExecToLog 'taskkill /F /IM xray.exe /T'

  ; Force a clean copy of runtime core files on reinstall/update.
  ; The app stores user settings in AppData, not in $INSTDIR\core.
  RMDir /r "$INSTDIR\core"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  SetShellVarContext current
  Delete "$SMPROGRAMS\VKarmani Desktop.lnk"
  Delete "$DESKTOP\VKarmani Desktop.lnk"
  Delete "$SMPROGRAMS\START_VKarmani.lnk"
  Delete "$DESKTOP\START_VKarmani.lnk"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  SetShellVarContext current
  Delete "$SMPROGRAMS\VKarmani.lnk"
  Delete "$DESKTOP\VKarmani.lnk"
  Delete "$SMPROGRAMS\VKarmani Desktop.lnk"
  Delete "$DESKTOP\VKarmani Desktop.lnk"
  Delete "$SMPROGRAMS\START_VKarmani.lnk"
  Delete "$DESKTOP\START_VKarmani.lnk"
!macroend
