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

## ✨ Что такое VKarmani Desktop \ VKarmani

**VKarmani Desktop \ VKarmani** — это удобное приложение для Windows, которое помогает подключаться к VPN-инфраструктуре VKarmani через персональный ключ подписки.

Приложение создано для тех, кому нужен понятный интерфейс, быстрый выбор сервера, стабильное подключение и автоматические обновления без ручной настройки сложных конфигов.

---

## 🧩 Возможности

- 🔑 Подключение по ключу VKarmani
- 🌍 Список доступных серверов
- ⚡ Режим **Proxy**
- 🛡️ Режим **TUN**
- 🧭 Выбор приложений, которые должны идти через TUN
- 📡 Проверка внешнего IP
- 🩺 Диагностика подключения
- 🖥️ Иконка в системном трее
- 🔄 Автоматическая проверка обновлений
- 🌐 Русский и английский язык установщика
- 🪟 Ярлык **VKarmani** после установки

---

## 🖥️ Как пользоваться

1. Скачайте установщик из раздела **Releases**
2. Установите приложение
3. Запустите **VKarmani**
4. Введите ключ подписки
5. Выберите сервер
6. Нажмите кнопку подключения

---

## 🔄 Обновления

VKarmani Desktop поддерживает автообновления через GitHub Releases.

Когда выходит новая версия, приложение может:
- проверить наличие обновления;
- скачать актуальный установщик;
- обновиться без ручной загрузки архива.

---

## 🧱 Что внутри

Проект использует современный стек:

| Часть | Технологии |
|---|---|
| 🖼️ Интерфейс | React, TypeScript, Vite |
| 🧠 Desktop backend | Rust, Tauri v2 |
| 🌐 VPN core | Xray |
| 🛡️ TUN | Wintun |
| 📦 Обновления | Tauri Updater, GitHub Releases |

---

## 📁 Актуальная структура проекта

```text
VKarmani-Desktop/
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
│        └─ wintun.dll
│
├─ src/
│  ├─ components/
│  ├─ data/
│  ├─ hooks/
│  ├─ services/
│  ├─ types/
│  ├─ utils/
│  ├─ App.tsx
│  ├─ i18n.ts
│  ├─ main.tsx
│  └─ styles.css
│
├─ src-tauri/
│  ├─ capabilities/
│  ├─ icons/
│  ├─ nsis/
│  ├─ src/
│  │  ├─ lib.rs
│  │  └─ main.rs
│  ├─ Cargo.toml
│  └─ tauri.conf.json
│
├─ .github/
│  └─ workflows/
│     └─ release.yml
│
├─ scripts/
│  ├─ set-version.mjs
│  └─ verify-updater-config.mjs
│
├─ .env.example
├─ README.md
├─ START_VKarmani.bat
├─ package.json
├─ package-lock.json
├─ tsconfig.json
├─ tsconfig.node.json
└─ vite.config.ts
```

---

## 🧭 Полезные ссылки

- 🌐 **Релизы:** [GitHub Releases](https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases)
- 🔄 **Файл автообновлений:** [latest.json](https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json)
- 🦀 **Tauri:** [tauri.app](https://tauri.app/)
- ⚛️ **React:** [react.dev](https://react.dev/)
- ⚡ **Vite:** [vite.dev](https://vite.dev/)
- 🧠 **Rust:** [rust-lang.org](https://www.rust-lang.org/)
- 🌐 **Xray-core:** [github.com/XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- 🛡️ **Wintun:** [wintun.net](https://www.wintun.net/)

---

## 🛡️ Безопасность

VKarmani Desktop не предназначен для хранения публичных тестовых ключей, приватных токенов или секретных данных в репозитории.

Если вы нашли проблему безопасности, не публикуйте её открыто в Issues. Лучше сообщить владельцу проекта напрямую.

---

## 📌 Статус проекта

Проект активно развивается.  
Основной фокус — стабильное подключение, удобный интерфейс, корректные обновления и аккуратная работа на Windows.

---

<p align="center">
  <b>VKarmani</b><br/>
  VPN VKarmani - для людей и компаний.
</p>
