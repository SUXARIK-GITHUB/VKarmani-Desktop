# VKarmani Desktop — проверка GitHub updater перед релизом

Updater Tauri не работает от обычного `git push`. Приложение проверяет именно GitHub Release asset:

```text
https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json
```

Этот URL обязан открываться в браузере без 404 и отдавать JSON такого вида:

```json
{
  "version": "0.13.9",
  "notes": "Release notes",
  "pub_date": "2026-04-24T00:00:00Z",
  "platforms": {
    "windows-x86_64": {
      "signature": "СОДЕРЖИМОЕ .sig ФАЙЛА, НЕ ССЫЛКА",
      "url": "https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/download/v0.13.9/VKarmani_Desktop_0.13.9_x64-setup.exe"
    }
  }
}
```

Обязательные поля:

```text
version
platforms.windows-x86_64.url
platforms.windows-x86_64.signature
```

## Как выпускать обновление

1. Поставить новую версию:

```bash
npm run release:version -- 0.13.9
```

2. Проверить конфиг:

```bash
npm run verify:updater
```

3. Закоммитить и отправить тег:

```bash
git add .
git commit -m "release: v0.13.9"
git tag v0.13.9
git push origin main --tags
```

4. Дождаться GitHub Actions `Release VKarmani Desktop`.

5. Открыть GitHub → Releases → последний релиз и проверить assets. Там должны быть:

```text
latest.json
*.sig
Windows installer: *.exe или *.msi
```

6. Проверить URL в браузере:

```text
https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json
```

Если открывается 404, значит релиз draft/private, workflow не завершился, файл latest.json не был загружен или последним релизом считается другой релиз без latest.json.

## Важные условия

- Repository secret `TAURI_SIGNING_PRIVATE_KEY` должен быть добавлен в GitHub.
- Если у приватного ключа есть пароль, нужен `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
- Release не должен быть draft.
- Версии в `package.json`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json` должны совпадать.
- Старая установленная версия должна быть меньше версии релиза.
