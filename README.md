# 🚀 VKarmani Desktop

> Современный desktop-клиент для **VKarmani** с удобным интерфейсом, поддержкой подключения через **Xray**, режимами **Proxy** и **TUN**, диагностикой, управлением профилем и локальным runtime на Windows.

---

## ✨ О проекте

**VKarmani Desktop** — это настольное приложение, созданное для удобного, стабильного и понятного подключения к инфраструктуре **VKarmani** через современный desktop-интерфейс.

Программа объединяет в себе:

- 🔐 авторизацию по ключу или подписке
- 🔄 синхронизацию профиля и серверов
- 🌐 подключение через локальный **Xray runtime**
- 🛡️ режимы **Proxy** и **TUN**
- 🧪 диагностику, проверку состояния и управление подключением
- 🖥️ интеграцию desktop UI + backend runtime в одном приложении

Основная цель проекта — дать быстрый, аккуратный и удобный VPN/Proxy-клиент для Windows на базе **Tauri + Rust + React/Vite**.

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
- 🦀 Desktop-оболочка на Tauri с нативным backend на Rust

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