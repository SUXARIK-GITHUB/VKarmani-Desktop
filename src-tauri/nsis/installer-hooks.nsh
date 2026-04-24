; VKarmani NSIS installer hooks.
; These hooks keep Tauri updater behavior intact and only add user-facing shortcuts.

!macro NSIS_HOOK_POSTINSTALL
  SetShellVarContext current
  ; Keep the shortcut name simple and user-facing.
  Delete "$SMPROGRAMS\VKarmani Desktop.lnk"
  Delete "$DESKTOP\VKarmani Desktop.lnk"
  CreateShortCut "$SMPROGRAMS\VKarmani.lnk" "$INSTDIR\vkarmani-desktop.exe" "" "$INSTDIR\vkarmani-desktop.exe" 0
  CreateShortCut "$DESKTOP\VKarmani.lnk" "$INSTDIR\vkarmani-desktop.exe" "" "$INSTDIR\vkarmani-desktop.exe" 0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  SetShellVarContext current
  Delete "$SMPROGRAMS\VKarmani.lnk"
  Delete "$DESKTOP\VKarmani.lnk"
  Delete "$SMPROGRAMS\VKarmani Desktop.lnk"
  Delete "$DESKTOP\VKarmani Desktop.lnk"
!macroend
