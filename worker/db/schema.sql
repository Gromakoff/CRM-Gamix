-- Базовая схема D1 для Game Trade Hub
CREATE TABLE IF NOT EXISTS games (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE IF NOT EXISTS filter_sets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  game_id INTEGER NOT NULL REFERENCES games(id),
  name TEXT NOT NULL,
  price_min REAL,
  price_max REAL,
  params_json TEXT,
  markup_percent REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT,
  game_id INTEGER REFERENCES games(id),
  type TEXT,
  title TEXT NOT NULL,
  price_cny REAL,
  price_usd REAL,
  description_ru TEXT,
  description_en TEXT,
  images_json TEXT,
  status TEXT NOT NULL DEFAULT 'cart',
  source TEXT DEFAULT 'taobao',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL REFERENCES products(id),
  purchase_price_cny REAL,
  purchase_price_usd REAL,
  sale_price_usd REAL,
  sale_platform TEXT,
  commission REAL,
  profit REAL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  sold_at TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT,
  message TEXT,
  level TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  read INTEGER DEFAULT 0
);
