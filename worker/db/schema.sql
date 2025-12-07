-- Cloudflare D1 schema for Game Trade Hub
-- Covers showcase (витрина), warehouse (склад), hand-trade, and user management

PRAGMA foreign_keys=ON;

-- Reference tables
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE CHECK (code IN ('admin','trader')),
    name TEXT NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role_id, is_active);

CREATE TABLE IF NOT EXISTS games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS filter_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    price_min REAL,
    price_max REAL,
    params_json TEXT,
    markup_percent REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_filter_sets_game ON filter_sets(game_id);

-- Core catalog for showcase/warehouse and hand-trade entries
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT,
    source TEXT, -- taobao, tmall, funpay, manual
    entry_type TEXT NOT NULL DEFAULT 'auto' CHECK (entry_type IN ('auto','hand')),
    owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL, -- трейдер-владелец для Hand-Trade
    game_id INTEGER REFERENCES games(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    resource_type TEXT,
    description_ru TEXT,
    description_en TEXT,
    images_json TEXT,
    status TEXT NOT NULL DEFAULT 'cart' CHECK (status IN ('cart','warehouse','showcase','sold')),
    quantity INTEGER NOT NULL DEFAULT 1,
    purchase_price_cny REAL,
    purchase_price_usd REAL,
    listing_price_usd REAL,
    sale_price_usd REAL,
    commission_usd REAL DEFAULT 0,
    sale_platform TEXT, -- funpay / other marketplaces
    source_url TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    purchased_at TEXT,
    listed_at TEXT,
    sold_at TEXT,
    UNIQUE (external_id, source)
);

CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
CREATE INDEX IF NOT EXISTS idx_items_game_status ON items(game_id, status);
CREATE INDEX IF NOT EXISTS idx_items_entry_owner ON items(entry_type, owner_id);
CREATE INDEX IF NOT EXISTS idx_items_sale_platform ON items(sale_platform);

-- Track how statuses change over time (cart -> warehouse -> showcase -> sold)
CREATE TABLE IF NOT EXISTS item_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('cart','warehouse','showcase','sold')),
    changed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    note TEXT,
    changed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_status_history_item ON item_status_history(item_id, changed_at);

-- Detailed price movements for analytics (витрина/склад/продано)
CREATE TABLE IF NOT EXISTS item_prices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    price_type TEXT NOT NULL CHECK (price_type IN ('purchase','listing','sale')),
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    rate_cny REAL, -- курс юаня на момент фиксации
    markup_percent REAL,
    note TEXT,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_item_prices_item_type ON item_prices(item_id, price_type);
CREATE INDEX IF NOT EXISTS idx_item_prices_recorded ON item_prices(recorded_at DESC);

-- Orders/sales table for Sold section
CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    sale_price_usd REAL NOT NULL,
    commission_usd REAL DEFAULT 0,
    net_profit_usd REAL, -- может заполняться в приложении
    sale_platform TEXT,
    sold_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sales_item ON sales(item_id);
CREATE INDEX IF NOT EXISTS idx_sales_platform ON sales(sale_platform);

-- Settings and notifications to support UI sections
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info','warning','error')),
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read, created_at DESC);
