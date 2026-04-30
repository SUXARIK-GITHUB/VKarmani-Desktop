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
- 🚪 **Быстрый выход из профиля** — сохранённый ключ можно удалить через интерфейс, если нужно выйти или сменить доступ.
- 🌍 **Список серверов** — серверы подтягиваются из live-профиля Remnawave и отображаются в удобном списке.
- ⭐ **Избранные серверы** — избранные узлы сохраняются и поднимаются выше в списке для быстрого выбора.
- 📶 **Проверка пинга** — можно проверить доступность серверов и увидеть задержку перед подключением.
- 🔌 **Proxy-режим** — подключение через локальный Xray proxy с возможностью включать системный proxy Windows.
- 🛡️ **TUN-режим** — режим туннеля через Wintun для выбранных приложений и служб.
- 🧭 **Выбор приложений для TUN** — можно указать, какие `.exe` и службы должны идти через VPN.
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

Когда выходит новая версия, приложение может:

- проверить наличие обновления;
- показать, что доступна новая версия;
- скачать актуальный установщик;
- остановить VPN перед установкой обновления;
- запустить установку без ручной загрузки архива.

---

## 🧱 Что внутри

| Часть | Что используется | За что отвечает |
|---|---|---|
| 🖼️ Интерфейс | React, TypeScript, Vite | Главное окно, авторизация, серверы, настройки, диагностика, уведомления |
| 🧠 Desktop backend | Rust, Tauri v2 | Native-команды, запуск Xray, системный proxy, TUN, маршруты, tray, updater |
| 🌐 VPN core | Xray-core | Реальное VPN/proxy-подключение, inbound/outbound, проверка конфигов |
| 🛡️ TUN | Wintun | Туннелирование выбранных приложений и служб через VPN |
| 🔑 Хранение ключа | Windows DPAPI / secure storage | Защищённое сохранение ключа доступа на устройстве |
| 📦 Обновления | Tauri Updater, GitHub Releases, latest.json | Проверка, загрузка и установка новых версий |
| 🧩 Парсер подписки | Remnawave parser | Разбор VLESS, VMess, Trojan, Shadowsocks, Hysteria2 и server metadata |
| 🧭 Маршрутизация | Routing exclusions, split-tunnel rules | Direct-исключения, приложения, службы, IPv4/TUN-правила |
| 🩺 Диагностика | Runtime status, logs, export | Проверка состояния, отчёты без приватных данных |
| 🧪 Проверки | Vitest, Cargo tests, PowerShell/Node scripts | Тесты парсеров, проверка Xray, updater и runtime-сценариев |
| 🚀 CI/CD | GitHub Actions | Сборка релиза, проверка manifest, тесты, публикация updater-файлов |

---

## 📁 Актуальная структура проекта

```text
VKarmani-Desktop/
├─ .github/
│  ├─ dependabot.yml
│  └─ workflows/
│     └─ release.yml
│
├─ public/
│  ├─ assets/
│  │  ├─ logo-dark.jpg
│  │  ├─ logo-white.jpg
│  │  ├─ logo-vkarmani.png
│  │  └─ wallpaper.jpg
│  └─ favicon.ico
│
├─ resources/
│  └─ core/
│     └─ windows/
│        ├─ xray.exe
│        ├─ geoip.dat
│        ├─ geosite.dat
│        ├─ wintun.dll
│        └─ core-manifest.json
│
├─ scripts/
│  ├─ fetch-xray-windows.ps1
│  ├─ repair-xray-windows.ps1
│  ├─ set-version.mjs
│  ├─ verify-core-manifest.mjs
│  ├─ verify-hysteria2-bundled-xray.ps1
│  ├─ verify-updater-config.mjs
│  ├─ verify-xray-windows.ps1
│  └─ windows-runtime-smoke.ps1
│
├─ src/
│  ├─ components/
│  │  ├─ AppInfoModal.tsx
│  │  ├─ AuthScreen.tsx
│  │  ├─ DiagnosticsTab.tsx
│  │  ├─ OverviewTab.tsx
│  │  ├─ ServerFlag.tsx
│  │  ├─ SettingsTab.tsx
│  │  ├─ SidebarNav.tsx
│  │  ├─ SplitTunnelModal.tsx
│  │  ├─ StartupSkeleton.tsx
│  │  ├─ SupportTab.tsx
│  │  ├─ TabErrorBoundary.tsx
│  │  ├─ ToastViewport.tsx
│  │  └─ WindowHeader.tsx
│  │
│  ├─ hooks/
│  │  ├─ useConnectionStateController.ts
│  │  ├─ useOperationManager.ts
│  │  ├─ usePingManager.ts
│  │  ├─ useSyncedRef.ts
│  │  └─ useToastManager.ts
│  │
│  ├─ services/
│  │  ├─ remnawave/
│  │  │  └─ subscriptionParser.ts
│  │  ├─ connectionGuards.ts
│  │  ├─ remnawave.ts
│  │  ├─ runtime.ts
│  │  ├─ storage.ts
│  │  └─ updater.ts
│  │
│  ├─ styles/
│  │  ├─ components/
│  │  ├─ base.css
│  │  ├─ dashboard.css
│  │  └─ responsive.css
│  │
│  ├─ types/
│  │  ├─ appState.ts
│  │  └─ vpn.ts
│  │
│  ├─ utils/
│  │  ├─ async.ts
│  │  ├─ diagnosticsExport.ts
│  │  ├─ redaction.ts
│  │  ├─ routingExclusions.ts
│  │  ├─ serverDisplay.ts
│  │  ├─ serverIdentity.ts
│  │  ├─ serverSorting.ts
│  │  ├─ toast.ts
│  │  └─ traffic.ts
│  │
│  ├─ App.tsx
│  ├─ i18n.ts
│  ├─ main.tsx
│  ├─ styles.css
│  └─ vite-env.d.ts
│
├─ src-tauri/
│  ├─ capabilities/
│  │  └─ default.json
│  ├─ icons/
│  │  ├─ 32x32.png
│  │  ├─ 128x128.png
│  │  ├─ icon.ico
│  │  └─ icon.png
│  ├─ nsis/
│  │  └─ installer-hooks.nsh
│  ├─ src/
│  │  ├─ app_run.rs
│  │  ├─ commands.rs
│  │  ├─ core_paths.rs
│  │  ├─ lib.rs
│  │  ├─ main.rs
│  │  ├─ platform.rs
│  │  ├─ remote_fetch.rs
│  │  ├─ runtime_lifecycle.rs
│  │  ├─ runtime_status.rs
│  │  ├─ state.rs
│  │  ├─ tests.rs
│  │  └─ xray_config.rs
│  ├─ build.rs
│  ├─ Cargo.toml
│  ├─ Cargo.lock
│  └─ tauri.conf.json
│
├─ tests/
│  └─ remnawave.test.ts
│
├─ dist/
│  ├─ assets/
│  ├─ favicon.ico
│  └─ index.html
│
├─ .env.example
├─ .gitattributes
├─ .gitignore
├─ .npmrc
├─ index.html
├─ package.json
├─ package-lock.json
├─ README.md
├─ START_VKarmani.bat
├─ tsconfig.json
├─ tsconfig.node.json
└─ vite.config.ts
```

> `dist/` — это собранный frontend. Основная разработка ведётся в `src/` и `src-tauri/`.

---

## 🧪 Проверки и сборка

```bash
npm ci
npm run build
npm run test:parsers
npm run verify:updater
npm run verify:xray:manifest
npm run tauri:build
```

Для Windows-проверок Xray и runtime используются PowerShell-скрипты из папки `scripts/`.

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

Проект активно развивается.  
Основной фокус — стабильное подключение, удобный интерфейс, корректные обновления, безопасное хранение ключа и аккуратная работа на Windows.

---

<p align="center">
  <b>VKarmani</b><br/>
  VPN VKarmani — для людей и компаний.
</p>