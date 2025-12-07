-- Migration 001: initial schema for showcase, warehouse, hand-trade, users
-- Apply with: wrangler d1 migrations apply <db_name>

BEGIN TRANSACTION;

PRAGMA foreign_keys=ON;

-- Roles and users
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE CHECK (code IN ('admin','trader')),
    name TEXT NOT NULL,
    description TEXT
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_users_role_active ON users(role_id, is_active);

-- Games and filters
CREATE TABLE games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE filter_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    price_min REAL,
    price_max REAL,
    params_json TEXT,
    markup_percent REAL DEFAULT 0
);
CREATE INDEX idx_filter_sets_game ON filter_sets(game_id);

-- Items for cart/warehouse/showcase/sold and Hand-Trade ownership
CREATE TABLE items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT,
    source TEXT,
    entry_type TEXT NOT NULL DEFAULT 'auto' CHECK (entry_type IN ('auto','hand')),
    owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
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
    sale_platform TEXT,
    source_url TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    purchased_at TEXT,
    listed_at TEXT,
    sold_at TEXT,
    UNIQUE (external_id, source)
);
CREATE INDEX idx_items_status ON items(status);
CREATE INDEX idx_items_game_status ON items(game_id, status);
CREATE INDEX idx_items_entry_owner ON items(entry_type, owner_id);
CREATE INDEX idx_items_sale_platform ON items(sale_platform);

-- Status flow history
CREATE TABLE item_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('cart','warehouse','showcase','sold')),
    changed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    note TEXT,
    changed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_status_history_item ON item_status_history(item_id, changed_at);

-- Price history for analytics
CREATE TABLE item_prices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    price_type TEXT NOT NULL CHECK (price_type IN ('purchase','listing','sale')),
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    rate_cny REAL,
    markup_percent REAL,
    note TEXT,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_item_prices_item_type ON item_prices(item_id, price_type);
CREATE INDEX idx_item_prices_recorded ON item_prices(recorded_at DESC);

-- Sales table for Sold section
CREATE TABLE sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    sale_price_usd REAL NOT NULL,
    commission_usd REAL DEFAULT 0,
    net_profit_usd REAL,
    sale_platform TEXT,
    sold_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_sales_item ON sales(item_id);
CREATE INDEX idx_sales_platform ON sales(sale_platform);

-- Settings and notifications
CREATE TABLE settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info','warning','error')),
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_notifications_read ON notifications(read, created_at DESC);

COMMIT;
