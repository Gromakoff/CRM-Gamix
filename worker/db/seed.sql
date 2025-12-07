-- Seed data for local testing (Admin + Trader, showcase/warehouse/hand-trade items)
-- Run after applying migrations: wrangler d1 execute <db_name> --file=worker/db/seed.sql

INSERT INTO roles(code, name, description) VALUES
    ('admin', 'Admin', 'Полный доступ к панели'),
    ('trader', 'Trader', 'Доступ только к разделу Hand-Trade')
ON CONFLICT(code) DO NOTHING;

INSERT INTO users(username, password_hash, role_id)
VALUES
    ('admin', 'hash_admin_example', (SELECT id FROM roles WHERE code='admin')),
    ('trader01', 'hash_trader_example', (SELECT id FROM roles WHERE code='trader'))
ON CONFLICT(username) DO NOTHING;

INSERT INTO games(name, description) VALUES
    ('Genshin Impact', 'Азиатский сервер, примогемы и аккаунты'),
    ('Honkai: Star Rail', 'Ресурсы для европ. сервера')
ON CONFLICT(name) DO NOTHING;

INSERT INTO filter_sets(game_id, name, price_min, price_max, params_json, markup_percent)
VALUES
    ((SELECT id FROM games WHERE name='Genshin Impact'), 'Стартовые аккаунты', 5, 50, '{"ar":7}', 25),
    ((SELECT id FROM games WHERE name='Honkai: Star Rail'), 'Ресурсы mid-game', 10, 80, '{"eidolon":1}', 20)
ON CONFLICT DO NOTHING;

-- Auto-sourced item in cart
INSERT INTO items(external_id, source, entry_type, owner_id, game_id, title, resource_type, status, purchase_price_cny, purchase_price_usd, listing_price_usd, source_url)
VALUES
    ('tb_1001', 'taobao', 'auto', NULL, (SELECT id FROM games WHERE name='Genshin Impact'), 'Аккаунт с 60 lvl AR', 'account', 'cart', 120, 16.5, 28, 'https://item.taobao.com/item.htm?id=1001');

-- Warehouse item ready for showcase
INSERT INTO items(external_id, source, entry_type, owner_id, game_id, title, resource_type, status, purchase_price_cny, purchase_price_usd, listing_price_usd, purchased_at, listed_at)
VALUES
    ('tb_2002', 'taobao', 'auto', NULL, (SELECT id FROM games WHERE name='Honkai: Star Rail'), 'Ресурсы mid-game', 'resources', 'warehouse', 220, 30.1, 55, datetime('now','-1 day'), NULL);

-- Hand-Trade item owned by trader
INSERT INTO items(external_id, source, entry_type, owner_id, game_id, title, resource_type, status, purchase_price_usd, listing_price_usd, sale_platform, listed_at)
VALUES
    ('ht_3003', 'manual', 'hand', (SELECT id FROM users WHERE username='trader01'), (SELECT id FROM games WHERE name='Genshin Impact'), 'Ручной лот: стартовый пак', 'bundle', 'showcase', 12, 22, 'funpay', datetime('now','-2 hours'));

-- Sold item to populate Sold section
INSERT INTO items(external_id, source, entry_type, owner_id, game_id, title, resource_type, status, purchase_price_usd, listing_price_usd, sale_price_usd, sale_platform, listed_at, sold_at)
VALUES
    ('tb_4004', 'taobao', 'auto', NULL, (SELECT id FROM games WHERE name='Genshin Impact'), 'Топ аккаунт', 'account', 'sold', 40, 70, 85, 'funpay', datetime('now','-3 days'), datetime('now','-1 day'));

INSERT INTO sales(item_id, sale_price_usd, commission_usd, net_profit_usd, sale_platform, sold_at)
VALUES
    ((SELECT id FROM items WHERE external_id='tb_4004'), 85, 4, 41, 'funpay', datetime('now','-1 day'));

-- Price history entries
INSERT INTO item_prices(item_id, price_type, amount, currency, rate_cny, markup_percent, note)
VALUES
    ((SELECT id FROM items WHERE external_id='tb_1001'), 'purchase', 16.5, 'USD', 7.3, 20, 'Первичная закупка'),
    ((SELECT id FROM items WHERE external_id='tb_2002'), 'listing', 55, 'USD', NULL, 25, 'Подготовка к витрине'),
    ((SELECT id FROM items WHERE external_id='ht_3003'), 'listing', 22, 'USD', NULL, 45, 'Трейдер установил цену'),
    ((SELECT id FROM items WHERE external_id='tb_4004'), 'sale', 85, 'USD', NULL, 40, 'Продано на FunPay');

-- Status history illustrating movement between sections
INSERT INTO item_status_history(item_id, status, changed_by, note, changed_at)
VALUES
    ((SELECT id FROM items WHERE external_id='tb_2002'), 'cart', (SELECT id FROM users WHERE username='admin'), 'Добавлен в корзину', datetime('now','-3 day')),
    ((SELECT id FROM items WHERE external_id='tb_2002'), 'warehouse', (SELECT id FROM users WHERE username='admin'), 'Выкуплен и на складе', datetime('now','-1 day')),
    ((SELECT id FROM items WHERE external_id='ht_3003'), 'showcase', (SELECT id FROM users WHERE username='trader01'), 'Опубликован трейдером', datetime('now','-2 hour')),
    ((SELECT id FROM items WHERE external_id='tb_4004'), 'showcase', (SELECT id FROM users WHERE username='admin'), 'Опубликован', datetime('now','-2 day')),
    ((SELECT id FROM items WHERE external_id='tb_4004'), 'sold', (SELECT id FROM users WHERE username='admin'), 'Продано на FunPay', datetime('now','-1 day'));

-- Initial settings examples
INSERT INTO settings(key, value)
VALUES
    ('rapidapi_key', 'PLACEHOLDER'),
    ('cny_rate', '7.30'),
    ('default_markup_percent', '30')
ON CONFLICT(key) DO UPDATE SET value=excluded.value;

-- Sample notifications
INSERT INTO notifications(type, message, level)
VALUES
    ('worker', 'Парсинг Taobao завершён', 'info'),
    ('sale', 'Лот tb_4004 продан на FunPay', 'info'),
    ('limit', 'Достигнут лимит бесплатных запросов RapidAPI', 'warning');
