# 🚀 VKarmani Desktop

<p align="center">
  Современный desktop-клиент для <b>VKarmani</b> с поддержкой <b>Xray</b>, режимов <b>Proxy</b> и <b>TUN</b>, диагностикой, управлением профилем и локальным runtime на Windows.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Desktop-Tauri%20v2-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" />
  <img src="https://img.shields.io/badge/Frontend-React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" />
  <img src="https://img.shields.io/badge/Language-TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/Backend-Rust-000000?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/Core-Xray-orange?style=for-the-badge" />
</p>

---

## ✨ О проекте

**VKarmani Desktop** — это настольное приложение, созданное для удобного, стабильного и современного подключения к инфраструктуре **VKarmani** через нативный desktop-интерфейс.

Программа объединяет в себе:

- 🔐 авторизацию по ключу или подписке
- 🔄 синхронизацию профиля и серверов
- 🌐 подключение через локальный **Xray runtime**
- 🛡️ режимы **Proxy** и **TUN**
- 🧪 диагностику и проверку состояния подключения
- 🖥️ интеграцию современного UI и нативного backend в одном приложении

Основная цель проекта — предоставить быстрый, понятный и аккуратный VPN/Proxy-клиент для Windows на базе **Tauri + Rust + React/Vite**.

---

## 🔥 Основные возможности

- 🔑 Вход по ключу, short UUID, UUID или subscription URL
- 🌍 Синхронизация профиля и списка доступных серверов
- ⚡ Подключение через **Proxy mode**
- 🛡️ Подключение через **TUN mode**
- 📦 Работа с локальным **Xray-core**
- 🧭 Поддержка `geoip.dat`, `geosite.dat`, `wintun.dll`
- 🩺 Диагностика состояния runtime и сети
- 📱 Просмотр устройств и состояния профиля
- ⚙️ Управление параметрами запуска и поведения клиента
- 🦀 Нативный backend на Rust через Tauri

---

## 🧰 Технологический стек

### 🎨 Frontend
- **React**
- **TypeScript**
- **Vite**
- **CSS**

### 🖥️ Desktop runtime
- **Tauri v2**

### ⚙️ Backend
- **Rust**

### 🌐 Network / Core
- **Xray-core**
- **Wintun**
- **GeoIP / GeoSite rules**

### 🛠️ Tooling
- **npm**
- **Git / GitHub**
- **GitHub Desktop**

---

## 🏗️ Архитектура проекта

Проект разделён на две основные части:

### 1️⃣ Frontend
Отвечает за:
- интерфейс приложения
- вкладки и экраны
- авторизацию
- состояние приложения
- взаимодействие с Tauri-командами

### 2️⃣ Rust / Tauri backend
Отвечает за:
- запуск и контроль Xray runtime
- генерацию runtime-конфигурации
- работу с Proxy / TUN
- проверку системного состояния
- маршруты, DNS, диагностику и sidecar-процессы

---

## 📁 Структура проекта

```text
VKarmani-Desktop/
├─ public/                     # Публичные frontend-ресурсы
│  └─ assets/                  # Логотипы, изображения, обои
│
├─ resources/
│  └─ core/
│     └─ windows/              # Xray runtime и сопутствующие файлы
│        ├─ xray.exe
│        ├─ geoip.dat
│        ├─ geosite.dat
│        └─ wintun.dll
│
├─ src/                        # Frontend-приложение
│  ├─ components/              # UI-компоненты и вкладки
│  ├─ services/                # Работа с API, runtime, storage
│  ├─ types/                   # TypeScript-типы
│  ├─ utils/                   # Вспомогательные утилиты
│  ├─ data/                    # Константы и локальные данные
│  ├─ App.tsx                  # Главный корневой компонент
│  └─ main.tsx                 # Точка входа frontend
│
├─ src-tauri/                  # Backend на Rust + конфиг Tauri
│  ├─ src/
│  │  ├─ main.rs               # Точка входа desktop-приложения
│  │  └─ lib.rs                # Основная runtime-логика
│  ├─ icons/                   # Иконки приложения
│  ├─ capabilities/            # Конфигурация возможностей Tauri
│  ├─ Cargo.toml               # Rust-зависимости
│  └─ tauri.conf.json          # Конфигурация сборки Tauri
│
├─ .env.example                # Пример переменных окружения
├─ .gitignore                  # Исключения для Git
├─ package.json                # npm-скрипты и frontend-зависимости
├─ vite.config.ts              # Конфигурация Vite
├─ tsconfig.json               # Конфигурация TypeScript
└─ START_VKarmani.bat          # Упрощённый запуск проекта на Windows