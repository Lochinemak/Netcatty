; Tauri NSIS installer hooks (bundle.windows.nsis.installerHooks).
; Same Explorer "Open in Netcatty" verbs as the Electron installer
; (build/installer.nsh) and as commands/integration.rs writes at runtime, so
; the Settings toggle recognises installer-created entries as current
; (netcatty-integration explorer.rs, schema v3).

!macro NSIS_HOOK_POSTINSTALL
  ; Open a selected folder in a new Netcatty local terminal. `--open-terminal-path="%1."`
  ; keeps paths with spaces in one token; the trailing dot avoids the `"C:\"` quote bug.
  WriteRegStr SHCTX "Software\Classes\Directory\shell\Netcatty" "MUIVerb" "Open in Netcatty"
  WriteRegStr SHCTX "Software\Classes\Directory\shell\Netcatty" "Icon" "$INSTDIR\${MAINBINARYNAME}.exe,0"
  WriteRegStr SHCTX "Software\Classes\Directory\shell\Netcatty\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" -- --open-terminal-path="%1."'

  ; Open the directory currently displayed by Explorer.
  WriteRegStr SHCTX "Software\Classes\Directory\Background\shell\Netcatty" "MUIVerb" "Open in Netcatty"
  WriteRegStr SHCTX "Software\Classes\Directory\Background\shell\Netcatty" "Icon" "$INSTDIR\${MAINBINARYNAME}.exe,0"
  WriteRegStr SHCTX "Software\Classes\Directory\Background\shell\Netcatty\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" -- --open-terminal-path="%V."'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey SHCTX "Software\Classes\Directory\shell\Netcatty"
  DeleteRegKey SHCTX "Software\Classes\Directory\Background\shell\Netcatty"
!macroend
