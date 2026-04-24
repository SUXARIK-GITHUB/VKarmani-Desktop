# VKarmani Desktop updater / GitHub Releases

Важно: автообновление Tauri не обновляет программу от обычного `git push`. Пользовательское приложение проверяет публичный `latest.json` из GitHub Releases:

```text
https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json
```

Чтобы кнопка "Проверить обновления" нашла обновление, должны выполняться условия:

1. Репозиторий или release assets доступны пользователю без авторизации GitHub. Для private repo прямой updater endpoint часто отдаёт 404.
2. На GitHub опубликован не draft release.
3. В release assets есть `latest.json`.
4. В release assets есть Windows installer/update bundle и соответствующий `.sig`.
5. Версия в `latest.json` выше, чем установленная версия приложения.
6. Версии совпадают в `package.json`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`.
7. В GitHub Actions secrets добавлены:
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, если ключ создан с паролем.
8. Публичный ключ в `src-tauri/tauri.conf.json -> plugins.updater.pubkey` соответствует приватному ключу из GitHub Secrets.

## Правильный выпуск обновления

```bash
npm run release:version -- 0.13.9
npm run verify:updater
git add package.json src-tauri/Cargo.toml src-tauri/tauri.conf.json package-lock.json .github/workflows/release.yml scripts docs
git commit -m "release: v0.13.9"
git tag v0.13.9
git push origin main --tags
```

После завершения GitHub Actions открой Release `v0.13.9` и проверь, что там есть `latest.json`.

## Быстрая проверка endpoint

Открой в браузере:

```text
https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json
```

Если браузер показывает 404, приложение тоже не сможет проверить обновления.

