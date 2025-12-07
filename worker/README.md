# Game Trade Hub — Worker

Стартовая заготовка Cloudflare Worker для API.

## Быстрый старт
1. Установите Wrangler (`npm i -g wrangler`).
2. В файле `wrangler.toml` пропишите реальные значения `database_id` для D1 и задайте переменные `RAPIDAPI_KEY`, `TELEGRAM_BOT_TOKEN` (если нужны уведомления).
3. Примените схему БД: `wrangler d1 execute game-trade-hub --file=./db/schema.sql`.
4. Запустите локально: `wrangler dev` из каталога `worker`.

## Структура
- `src/index.ts` — маршрутизация и заглушки API, перечисленные в требованиях.
- `src/lib/response.ts` — хелперы для JSON‑ответов.
- `db/schema.sql` — базовая схема таблиц D1.

На следующем шаге нужно подключить клиент Just One API, логику ролей (JWT), хранение товаров и интеграцию с переводами/биржами.
