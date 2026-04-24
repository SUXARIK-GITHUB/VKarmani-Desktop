# VKarmani Desktop updater checklist

## Что должно быть настроено один раз

1. В GitHub repository secrets добавь:
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
2. Public key из этой пары должен совпадать с `plugins.updater.pubkey` в `src-tauri/tauri.conf.json`.
3. Endpoint updater должен указывать на GitHub Release asset:
   - `https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json`

## Как выпустить обновление

1. Подними версию одинаково в трёх местах:
   - `package.json`
   - `src-tauri/Cargo.toml`
   - `src-tauri/tauri.conf.json`
2. Проверь конфиг:
   ```bash
   npm run verify:updater
   ```
3. Создай git tag:
   ```bash
   git tag v0.13.9
   git push origin v0.13.9
   ```
4. GitHub Actions соберёт draft release.
5. Перед публикацией проверь, что в assets есть:
   - Windows installer `.msi` или `.exe`
   - `.sig` подписи
   - `latest.json`
6. Нажми Publish release.

После публикации installed app будет проверять `latest.json` на GitHub. Если настройка автообновления включена, приложение само скачает и установит обновление через Tauri updater. Если пользователь нажмёт “Проверить обновления”, приложение вручную проверит тот же endpoint.
