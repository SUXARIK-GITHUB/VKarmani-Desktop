# VKarmani Updater / GitHub Releases

Этот проект уже настроен на static JSON updater через GitHub Releases.

## Что уже включено
- `bundle.createUpdaterArtifacts: true`
- `plugins.updater.pubkey`
- endpoint: `https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json`
- npm script: `npm run tauri`

## Как собрать релиз с подписью
Открой PowerShell в корне проекта и выполни:

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY_PATH="$env:USERPROFILE\.tauri\vkarmani_updater.key"
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD="ТВОЙ_ПАРОЛЬ"
npm run tauri build
```

## Что загрузить в GitHub Release
Из `src-tauri/target/release/bundle/` загрузить Windows installer и соответствующий `.sig`.

## latest.json
Пример содержимого:

```json
{
  "version": "0.13.9",
  "notes": "Исправления TUN и стабильности.",
  "pub_date": "2026-03-18T12:00:00Z",
  "platforms": {
    "windows-x86_64": {
      "signature": "ВСТАВЬ_СОДЕРЖИМОЕ_SIG_ФАЙЛА",
      "url": "https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/download/v0.13.9/ИМЯ_ИНСТАЛЛЕРА.exe"
    }
  }
}
```
