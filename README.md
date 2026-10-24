# 🚀 VKarmani Desktop

<p align="center">
  <b>Современный VPN-клиент для Windows</b><br/>
  Простое подключение к VKarmani через ключ подписки, Xray, Proxy и TUN.
</p>

<p align="center">
  <a href="https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest">
    <img src="https://img.shields.io/github/v/release/SUXARIK-GITHUB/VKarmani-Desktop?style=for-the-badge&label=Latest%20Release" alt="Latest release" />
  </a>
  <a href="https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases">
    <img src="https://img.shields.io/badge/Download-GitHub%20Releases-2ea44f?style=for-the-badge&logo=github" alt="Download" />
  </a>
  <img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/Tauri-v2-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" alt="Tauri" />
</p>

<p align="center">
  <a href="https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json">
    <img src="https://img.shields.io/badge/Auto--Update-enabled-5865F2?style=for-the-badge" alt="Auto update" />
  </a>
  <img src="https://img.shields.io/badge/Xray-core-orange?style=for-the-badge" alt="Xray" />
  <img src="https://img.shields.io/badge/Proxy%20%2B%20TUN-supported-111827?style=for-the-badge" alt="Proxy and TUN" />
</p>

---

## ✨ Что такое VKarmani Desktop

**VKarmani Desktop** — это удобное приложение для Windows, которое помогает подключаться к VPN-инфраструктуре VKarmani через персональный ключ подписки.

Приложение создано для тех, кому нужен понятный интерфейс, быстрый выбор сервера, стабильное подключение, режимы **Proxy / TUN** и автоматические обновления без ручной настройки сложных конфигов.

---

## 🧩 Возможности

- 🔑 **Подключение по ключу VKarmani** — пользователь вставляет ключ подписки, а приложение само проверяет профиль и подтягивает серверы.
- 🔐 **Сохранение ключа** — ключ может храниться в защищённом хранилище Windows, чтобы при следующем запуске не вводить его заново.
- 🧷 **Защищённый кэш серверов** — рабочие runtime-конфиги серверов не сохраняются открытым текстом в обычном client-state/localStorage.
- 🚪 **Быстрый выход из профиля** — сохранённый ключ можно удалить через интерфейс, если нужно выйти или сменить доступ.
- 🌍 **Список серверов** — серверы подтягиваются из live-профиля Remnawave и отображаются в удобном списке.
- ⭐ **Избранные серверы** — избранные узлы сохраняются и поднимаются выше в списке для быстрого выбора.
- 📶 **Проверка пинга** — можно проверить доступность серверов и увидеть задержку перед подключением.
- 🔌 **Proxy-режим** — подключение через локальный Xray proxy с возможностью включать системный proxy Windows.
- 🛡️ **TUN-режим** — туннель через Wintun для всех приложений с DIRECT-исключениями.
- 🧭 **Выбор приложений для TUN** — правила `.exe` и служб сохраняются, но подключение в режиме «Только выбранные» временно недоступно: ошибка определения процесса в Xray может отправить выбранный трафик напрямую.
- 🧩 **Исключения маршрутизации** — домены, зоны и IPv4-сети можно направлять напрямую, не через VPN.
- 🔁 **Аккуратное переключение серверов** — при смене сервера приложение проверяет выбранный узел и не должно случайно подключаться к другому.
- 🧯 **Откат при неудачном переключении** — если новый сервер не поднялся, приложение старается вернуть прежнее рабочее подключение.
- 📡 **Проверка внешнего IP** — после подключения можно проверить внешний адрес и состояние маршрута.
- 📊 **Сессия и трафик** — на главном экране отображается время подключения, входящий/исходящий трафик и статус.
- 🩺 **Диагностика** — есть служебная вкладка для проверки runtime, proxy, TUN, маршрутов и последних действий.
- 🧾 **Экспорт отчёта** — диагностический отчёт собирается без ключей, токенов и приватных ссылок.
- 🖥️ **Иконка в системном трее** — быстрый доступ к окну приложения, подключению, отключению и проверке обновлений.
- 🔄 **Автообновления** — приложение умеет проверять новые версии через GitHub Releases и Tauri Updater.
- 🌐 **Русский и английский интерфейс установщика** — установщик поддерживает выбор языка.
- 🪟 **Ярлык VKarmani после установки** — приложение устанавливается как обычная Windows-программа.

---

## 🖥️ Как пользоваться

1. Скачайте установщик из раздела **GitHub Releases**.
2. Установите приложение.
3. Запустите **VKarmani**.
4. Введите ключ подписки VKarmani.
5. Дождитесь загрузки профиля и списка серверов.
6. Выберите сервер.
7. Выберите режим подключения: **Proxy** или **TUN**.
8. Нажмите кнопку подключения.

---

## 🔄 Обновления

VKarmani Desktop поддерживает автообновления через **GitHub Releases** и **Tauri Updater**.

`0.13.82` — выпуск в стабильном канале для контролируемого тестирования на реальной Windows 11 по решению владельца проекта. Код приложения соответствует `0.13.81-rc.1`; изменены версия и описание выпуска. DNS containment, перемежающиеся TCP/UDP-таймауты и сбои VirtualBox не объявляются исправленными; полная нативная приёмка не завершена. Подробности и ограничения указаны в Release Notes. Откат данных на `0.13.76` после перехода в хранилище v2 требует отдельного экспорта/восстановления, одного старого установщика недостаточно. Windows 7 текущим bundled Xray не поддерживается; selected-app TUN сохраняет защитный отказ. Не удаляйте `core`, AppData или DPAPI backup вручную при ошибке запуска: сохраните диагностику и используйте проверенный установщик для восстановления ресурсов.

Когда выходит новая версия, приложение может:

- проверить наличие обновления;
- показать, что доступна новая версия;
- скачать актуальный установщик;
- автоматически установить только при подтверждённом idle; при активной VPN запросить явное подтверждение остановки;
- запустить установку без ручной загрузки архива.

---

## 🧱 Что внутри

| Часть | Что используется | За что отвечает |
|---|---|---|
| 🖼️ Интерфейс | React, TypeScript, Vite | Главное окно, авторизация, серверы, настройки, диагностика, уведомления |
| 🧠 Desktop backend | Rust, Tauri v2 | Native-команды, запуск Xray, системный proxy, TUN, маршруты, tray, updater |
| 🌐 VPN core | Xray-core | Реальное VPN/proxy-подключение, inbound/outbound, проверка конфигов |
| 🛡️ TUN | Wintun | Режимы для всех приложений и DIRECT-исключений; «Только выбранные» временно недоступен |
| 🔑 Хранение ключа и runtime-кэша | Windows DPAPI / secure storage | Защищённое сохранение ключа доступа и полного server runtime cache на устройстве |
| 📦 Обновления | Tauri Updater, GitHub Releases, latest.json | Проверка, загрузка и установка новых версий |
| 🧩 Парсер подписки | Remnawave parser | Разбор VLESS, VMess, Trojan, Shadowsocks, Hysteria2 и server metadata |
| 🧭 Маршрутизация | Routing exclusions, split-tunnel rules | Direct-исключения, приложения, службы, IPv4/TUN-правила |
| 🩺 Диагностика | Runtime status, logs, export | Проверка состояния, отчёты без приватных данных |
| 🧪 Проверки | Vitest, Cargo tests, PowerShell/Node scripts | Тесты парсеров, проверка Xray, updater и runtime-сценариев |
| 🚀 CI/CD | GitHub Actions | Сборка релиза, проверка manifest, тесты, публикация updater-файлов |

---

## 📁 Структура проекта

| Каталог | Содержимое |
|---|---|
| `src/` | React UI, IPC adapters, подписки, состояния и утилиты |
| `src-tauri/src/` | Rust lifecycle, storage, сетевые операции и проверки ownership |
| `resources/core/windows/` | Bundled Xray/Wintun/geoip/geosite и manifest |
| `tests/` | Frontend regression, parser, security и concurrency fixtures |
| `scripts/` | Проверки ресурсов, updater и изолированных Windows scenarios |
| `.github/workflows/` | CI и draft-first release workflow |

`dist/` и `src-tauri/target/` — результаты локальной сборки, не исходники.

---

## 🧪 Проверки и сборка

Текущая проверяемая сборочная среда: **Node.js 22.23.3**, npm 10+, **Rust/Cargo 1.94.0**, MSVC Build Tools и Windows SDK. Наличие WebView2 и совместимость с целевой Windows проверяются отдельно. Поле `rust-version` в manifest пока не подтверждает сборку старым toolchain.

```bash
npm ci
npm run lint
npm test
npm run build
npm run test:parsers
npm run verify:updater
npm run verify:xray:manifest
cargo tree --locked --manifest-path src-tauri/Cargo.toml
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo check --locked --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

Для Xray/resource-проверок используются PowerShell-скрипты из `scripts/`. `npm run smoke:windows` требует чистого отключённого тестового сеанса: не используйте его для acceptance параллельно рабочей VPN. `npm run tauri:build` создаёт Windows-пакеты; проверка подписи и native acceptance остаются отдельными шагами.

---

## 🧭 Полезные ссылки

- 🌐 **Релизы VKarmani Desktop:** [GitHub Releases](https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases)
- ⬇️ **Последний релиз:** [Latest Release](https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest)
- 🔄 **Файл автообновлений:** [latest.json](https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json)
- 🧾 **GitHub Actions / сборки:** [Actions](https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/actions)
- 🦀 **Tauri:** [tauri.app](https://tauri.app/)
- ⚛️ **React:** [react.dev](https://react.dev/)
- ⚡ **Vite:** [vite.dev](https://vite.dev/)
- 🧠 **Rust:** [rust-lang.org](https://www.rust-lang.org/)
- 🌐 **Xray-core:** [github.com/XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- 🛡️ **Wintun:** [wintun.net](https://www.wintun.net/)
- 🧩 **Shields.io badges:** [shields.io](https://shields.io/)

---

## 🛡️ Безопасность

VKarmani Desktop не предназначен для хранения публичных тестовых ключей, приватных токенов или секретных данных в репозитории.

Если вы нашли проблему безопасности, не публикуйте её открыто в Issues. Лучше сообщить владельцу проекта напрямую.

---

## 📌 Статус проекта

Текущие исходники содержат изменения TASK-009 для проверки и дальнейшей доработки. Публикация кода в GitHub не означает выпуск новой сборки или обновление клиентов. До завершения обязательных native/platform/security проверок действует **PRODUCTION_NO_GO**. Код этой ветки и файлы установленной сборки могут различаться.

Windows 10/11 x64 — целевые системы текущего backend. Поддержка Windows 7 и Linux ещё не подтверждена. Firewall Kill Switch, полная DNS leak protection и Strict Isolation не должны считаться проверенными возможностями этой сборки.

Proxy использует системные HTTP/HTTPS настройки Windows; он не обеспечивает прозрачный UDP и не запрещает программам обращаться к локальному SOCKS/HTTP вручную. Выбранные service rules требуют отдельного исполняемого файла; shared `svchost.exe` не считается изолированной службой.

В текущих исходниках read-only Diagnostics отделена от repair; error-уведомления сохраняются до закрытия, а история ограничена 128 записями без ключей и endpoint. Новое v2-хранилище использует DPAPI и revision/CAS; откат к старой схеме требует явного экспорта. Доступные локальные проверки не заменяют миграцию/откат и network acceptance на целевой системе.

---

<p align="center">
  <b>VKarmani</b><br/>
  VPN VKarmani — для людей и компаний.
</p>
