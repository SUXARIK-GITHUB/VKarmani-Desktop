; VKarmani NSIS installer hooks.
; Tauri creates the normal shortcuts using productName = "VKarmani".
; Hooks keep upgrades clean and remove legacy duplicate shortcuts.

!include "LogicLib.nsh"
!macro VKARMANI_REQUIRE_UNLOCKED FILE
  ${If} ${FileExists} "${FILE}"
  System::Call 'kernel32::CreateFileW(w "${FILE}", i 0x40000000, i 3, p 0, i 3, i 0, p 0) p.r0'
  ${If} $0 == -1
    MessageBox MB_OK|MB_ICONEXCLAMATION "Close VKarmani and its runtime before installing or uninstalling. A bundled file is busy or cannot be replaced. No Xray processes were terminated."
    Abort
  ${EndIf}
  System::Call 'kernel32::CloseHandle(p r0)'
  ${EndIf}
!macroend

!macro VKARMANI_CHECK_CORE_UNLOCKED
  !insertmacro VKARMANI_REQUIRE_UNLOCKED "$INSTDIR\core\windows\xray.exe"
  !insertmacro VKARMANI_REQUIRE_UNLOCKED "$INSTDIR\core\windows\wintun.dll"
  !insertmacro VKARMANI_REQUIRE_UNLOCKED "$INSTDIR\core\windows\geoip.dat"
  !insertmacro VKARMANI_REQUIRE_UNLOCKED "$INSTDIR\core\windows\geosite.dat"
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; Application cleanup owns its exact child/job. Installer has no authority
  ; over name/path-matched processes, or an entire pre-existing core directory.
  !insertmacro VKARMANI_CHECK_CORE_UNLOCKED
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro VKARMANI_CHECK_CORE_UNLOCKED
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
