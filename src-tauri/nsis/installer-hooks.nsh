; VKarmani NSIS installer hooks.
; Tauri creates the normal shortcuts using productName = "VKarmani".
; These hooks only remove legacy duplicate shortcuts from older builds.

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
