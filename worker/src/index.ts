import type { Ai, D1Database, Fetcher } from '@cloudflare/workers-types';
import { execute, getFirst, runQuery } from './lib/d1';
import { badRequest, json, notFound } from './lib/response';

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

type Env = {
  DB: D1Database;
  ASSETS?: Fetcher;
  RAPIDAPI_KEY?: string;
  AI?: Ai;
  TELEGRAM_BOT_TOKEN?: string;
  ADMIN_EMAIL?: string;
  ADMIN_PASSWORD?: string;
  ADMIN_SECRET?: string;
  ADMIN_GATE_USER?: string;
  ADMIN_GATE_PASS?: string;
};

const DEFAULT_GATE_USER = 'gth-admin';
const DEFAULT_GATE_PASSWORD = 'gth-protect-9824';

const corsHeaders = new Headers({
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
});

function withCors(response: Response): Response {
  const result = new Response(response.body, response);
  corsHeaders.forEach((value, key) => {
    if (!result.headers.has(key)) {
      result.headers.set(key, value);
    }
  });
  return result;
}

function unauthorized(message?: string): Response {
  return json({ error: message ?? 'Требуется авторизация' }, { status: 401 });
}

function isBasicAuthorized(request: Request, user: string, password: string): boolean {
  const header = request.headers.get('Authorization');
  if (!header || !header.startsWith('Basic ')) return false;
  const decoded = atob(header.slice(6));
  const [name, ...rest] = decoded.split(':');
  const pass = rest.join(':');
  return name === user && pass === password;
}

function protectStatic(request: Request, env: Env): Response | null {
  const user = env.ADMIN_GATE_USER || DEFAULT_GATE_USER;
  const password = env.ADMIN_GATE_PASS || DEFAULT_GATE_PASSWORD;
  if (isBasicAuthorized(request, user, password)) return null;
  return new Response('Доступ к админке закрыт паролем.', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="GameTradeHub Admin"' },
  });
}

function ensureAuthSecret(env: Env): Response | null {
  if (!getAuthSecret(env)) {
    return json(
      {
        error: 'Секрет подписи не настроен',
        hint: 'Задайте ADMIN_SECRET или используйте ADMIN_PASSWORD как резервный секрет.',
      },
      { status: 500 },
    );
  }
  return null;
}

function getAuthSecret(env: Env): string | null {
  if (env.ADMIN_SECRET) return env.ADMIN_SECRET;
  if (env.ADMIN_PASSWORD) return env.ADMIN_PASSWORD;
  return null;
}

async function signContent(content: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(content));
  const bytes = new Uint8Array(signature);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

async function createToken(payload: TokenPayload, secret: string, ttlSeconds = DEFAULT_TOKEN_TTL) {
  const encodedPayload = btoa(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
  const signature = await signContent(encodedPayload, secret);
  return `${encodedPayload}.${signature}`;
}

async function verifyToken(token: string, secret: string): Promise<TokenPayload | null> {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, signature] = parts;
  const expectedSignature = await signContent(encodedPayload, secret);
  if (expectedSignature !== signature) return null;
  try {
    const payload = JSON.parse(atob(encodedPayload)) as TokenPayload;
    if (!payload.email || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (error) {
    console.error('Token parse error', error);
    return null;
  }
}

async function authenticate(request: Request, env: Env): Promise<{ ok: true; user: AuthUser } | { ok: false; response: Response }> {
  const secretError = ensureAuthSecret(env);
  if (secretError) return { ok: false, response: secretError };

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { ok: false, response: unauthorized('Передайте токен в заголовке Authorization: Bearer <token>.') };
  }

  const token = authHeader.replace('Bearer ', '').trim();
  const secret = getAuthSecret(env);
  if (!secret) {
    return { ok: false, response: unauthorized('Секрет подписи не настроен. Укажите ADMIN_SECRET.') };
  }

  const payload = await verifyToken(token, secret);
  if (!payload) {
    return { ok: false, response: unauthorized('Токен не прошёл проверку или истёк.') };
  }

  const userRow = await getFirst<{ id: number; username: string; role: string; is_active: number }>(
    env.DB,
    'SELECT u.id, u.username, u.is_active, r.code as role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?',
    [payload.userId],
  );

  if (!userRow || !userRow.is_active) {
    return { ok: false, response: unauthorized('Пользователь не найден или отключён.') };
  }

  return {
    ok: true,
    user: { id: userRow.id, username: userRow.username, role: userRow.role as string, provider: payload.provider },
  };
}

interface RouteHandler {
  method: Method;
  path: RegExp;
  public?: boolean;
  handler: (request: Request, env: Env, params: Record<string, string>) => Promise<Response> | Response;
}

interface TokenPayload {
  userId: number;
  username: string;
  role: string;
  provider?: 'password' | 'telegram';
  exp: number;
}

interface AuthUser {
  id: number;
  username: string;
  role: string;
  provider?: 'password' | 'telegram';
}

interface TelegramAuthPayload {
  id: number;
  first_name?: string;
  last_name?: string;
  username?: string;
  auth_date: number;
  hash: string;
}

const DEFAULT_TOKEN_TTL = 60 * 60 * 24; // 24 hours

async function hashPassword(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  const bytes = Array.from(new Uint8Array(digest));
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function ensureBaseRoles(env: Env) {
  await env.DB.prepare("INSERT OR IGNORE INTO roles(code, name, description) VALUES ('admin','Admin','Полный доступ')").run();
  await env.DB.prepare("INSERT OR IGNORE INTO roles(code, name, description) VALUES ('trader','Trader','Ограниченный доступ')").run();
}

async function getRoleId(env: Env, code: 'admin' | 'trader'): Promise<number | null> {
  const role = await getFirst<{ id: number }>(env.DB, 'SELECT id FROM roles WHERE code = ?', [code]);
  return role?.id ?? null;
}

async function isFirstUser(env: Env): Promise<boolean> {
  const row = await getFirst<{ count: number }>(env.DB, 'SELECT COUNT(*) as count FROM users');
  return (row?.count ?? 0) === 0;
}

async function hmacSha256Hex(message: string, key: ArrayBuffer): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
  const bytes = Array.from(new Uint8Array(signature));
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyTelegramAuth(payload: Record<string, string | number>, botToken: string): Promise<boolean> {
  const { hash, ...rest } = payload as Record<string, string>;
  if (!hash) return false;

  const checkData = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${rest[key]}`)
    .join('\n');

  const secret = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(botToken)));
  const signature = await hmacSha256Hex(checkData, secret.buffer);
  return signature === hash;
}

interface ItemInput {
  title?: string;
  gameId?: number;
  resourceType?: string;
  descriptionRu?: string;
  descriptionEn?: string;
  images?: string[];
  status?: 'cart' | 'warehouse' | 'showcase' | 'sold';
  entryType?: 'auto' | 'hand';
  purchasePriceCny?: number;
  listingPriceUsd?: number;
  salePriceUsd?: number;
  commissionUsd?: number;
  salePlatform?: string;
  sourceUrl?: string;
  quantity?: number;
}

interface ItemUpdateInput extends ItemInput {
  statusNote?: string;
}

function mapItemRow(row: Record<string, unknown>) {
  const imagesJson = row.images_json as string | null;
  return {
    id: row.id,
    externalId: row.external_id,
    source: row.source,
    entryType: row.entry_type,
    ownerId: row.owner_id,
    gameId: row.game_id,
    title: row.title,
    resourceType: row.resource_type,
    descriptionRu: row.description_ru,
    descriptionEn: row.description_en,
    images: imagesJson ? JSON.parse(imagesJson) : [],
    status: row.status,
    quantity: row.quantity,
    purchasePriceCny: row.purchase_price_cny,
    purchasePriceUsd: row.purchase_price_usd,
    listingPriceUsd: row.listing_price_usd,
    salePriceUsd: row.sale_price_usd,
    commissionUsd: row.commission_usd,
    salePlatform: row.sale_platform,
    sourceUrl: row.source_url,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function login(request: Request, env: Env): Promise<Response> {
  const secretError = ensureAuthSecret(env);
  if (secretError) return secretError;

  const payload = (await request.json().catch(() => null)) as { email?: string; username?: string; password?: string } | null;
  const username = (payload?.email || payload?.username)?.trim().toLowerCase();
  if (!username || !payload?.password) {
    return badRequest('Передайте email (или username) и password в JSON.');
  }

  await ensureBaseRoles(env);

  const userRow = await getFirst<{
    id: number;
    username: string;
    password_hash: string;
    role: string;
    is_active: number;
  }>(
    env.DB,
    'SELECT u.id, u.username, u.password_hash, u.is_active, r.code as role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.username = ?',
    [username],
  );

  if (!userRow || !userRow.is_active) {
    return unauthorized('Пользователь не найден или отключён. Зарегистрируйтесь.');
  }

  const passwordHash = await hashPassword(payload.password);
  if (passwordHash !== userRow.password_hash) {
    return unauthorized('Неверный логин или пароль.');
  }

  const secret = getAuthSecret(env);
  if (!secret) {
    return unauthorized('Секрет подписи не настроен. Укажите ADMIN_SECRET.');
  }

  const tokenPayload: TokenPayload = {
    userId: userRow.id,
    username: userRow.username,
    role: userRow.role,
    provider: 'password',
    exp: 0,
  };

  const token = await createToken(tokenPayload, secret);
  const expiresAt = new Date(Date.now() + DEFAULT_TOKEN_TTL * 1000).toISOString();

  return json({ token, user: { id: userRow.id, username: userRow.username, role: userRow.role }, expiresAt });
}

async function register(request: Request, env: Env): Promise<Response> {
  const secretError = ensureAuthSecret(env);
  if (secretError) return secretError;

  const payload = (await request.json().catch(() => null)) as { email?: string; username?: string; password?: string } | null;
  const username = (payload?.email || payload?.username)?.trim().toLowerCase();
  const password = payload?.password?.trim();

  if (!username || !password) {
    return badRequest('Передайте email (или username) и password в JSON.');
  }

  await ensureBaseRoles(env);

  const existing = await getFirst<{ id: number }>(env.DB, 'SELECT id FROM users WHERE username = ?', [username]);
  if (existing) {
    return badRequest('Пользователь уже существует. Используйте другой email или войдите.');
  }

  const roleCode: 'admin' | 'trader' = (await isFirstUser(env)) ? 'admin' : 'trader';
  const roleId = await getRoleId(env, roleCode);

  if (!roleId) {
    return json({ error: 'Не найдена роль для пользователя' }, { status: 500 });
  }

  const passwordHash = await hashPassword(password);
  const userId = await execute(env.DB, 'INSERT INTO users(username, password_hash, role_id, is_active) VALUES (?, ?, ?, 1)', [
    username,
    passwordHash,
    roleId,
  ]);

  const secret = getAuthSecret(env);
  if (!secret) {
    return unauthorized('Секрет подписи не настроен. Укажите ADMIN_SECRET.');
  }

  const tokenPayload: TokenPayload = {
    userId,
    username,
    role: roleCode,
    provider: 'password',
    exp: 0,
  };

  const token = await createToken(tokenPayload, secret);
  const expiresAt = new Date(Date.now() + DEFAULT_TOKEN_TTL * 1000).toISOString();

  return json({
    message: roleCode === 'admin' ? 'Первый пользователь автоматически получает роль admin.' : 'Регистрация успешна.',
    token,
    user: { id: userId, username, role: roleCode },
    expiresAt,
  });
}

async function telegramLogin(request: Request, env: Env): Promise<Response> {
  const secretError = ensureAuthSecret(env);
  if (secretError) return secretError;

  if (!env.TELEGRAM_BOT_TOKEN) {
    return json({ error: 'Укажите TELEGRAM_BOT_TOKEN в переменных окружения.' }, { status: 500 });
  }

  const payload = (await request.json().catch(() => null)) as Partial<TelegramAuthPayload> | null;

  if (!payload || !payload.id || !payload.auth_date || !payload.hash) {
    return badRequest('Передайте auth payload от Telegram Login Widget (id, username, auth_date, hash).');
  }

  const valid = await verifyTelegramAuth(
    {
      id: payload.id,
      first_name: payload.first_name ?? '',
      last_name: payload.last_name ?? '',
      username: payload.username ?? '',
      auth_date: payload.auth_date,
      hash: payload.hash,
    },
    env.TELEGRAM_BOT_TOKEN,
  );

  if (!valid) {
    return unauthorized('Подпись Telegram не прошла проверку.');
  }

  await ensureBaseRoles(env);

  const normalizedUsername = (payload.username || `tg_${payload.id}`).toLowerCase();
  const existing = await getFirst<{ id: number; role: string }>(
    env.DB,
    'SELECT u.id, r.code as role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.username = ?',
    [normalizedUsername],
  );

  let userId = existing?.id;
  let roleCode: 'admin' | 'trader' = existing?.role === 'admin' ? 'admin' : 'trader';
  let message = 'Вход через Telegram';

  if (!existing) {
    const first = await isFirstUser(env);
    roleCode = first ? 'admin' : 'trader';
    const roleId = await getRoleId(env, roleCode);
    if (!roleId) {
      return json({ error: 'Не найдена роль для пользователя' }, { status: 500 });
    }
    const passwordHash = await hashPassword(`telegram:${payload.id}:${payload.auth_date}`);
    userId = await execute(env.DB, 'INSERT INTO users(username, password_hash, role_id, is_active) VALUES (?, ?, ?, 1)', [
      normalizedUsername,
      passwordHash,
      roleId,
    ]);
    message = first ? 'Первый Telegram-пользователь стал администратором.' : 'Пользователь создан через Telegram.';
  }

  if (!userId) {
    return json({ error: 'Не удалось создать пользователя' }, { status: 500 });
  }

  const secret = getAuthSecret(env);
  if (!secret) {
    return unauthorized('Секрет подписи не настроен. Укажите ADMIN_SECRET.');
  }

  const tokenPayload: TokenPayload = {
    userId,
    username: normalizedUsername,
    role: roleCode,
    provider: 'telegram',
    exp: 0,
  };

  const token = await createToken(tokenPayload, secret);
  const expiresAt = new Date(Date.now() + DEFAULT_TOKEN_TTL * 1000).toISOString();

  return json({ message, token, user: { id: userId, username: normalizedUsername, role: roleCode }, expiresAt });
}

async function createItem(request: Request, env: Env): Promise<Response> {
  const payload = (await request.json().catch(() => null)) as ItemInput | null;
  if (!payload || !payload.title) {
    return badRequest('Передайте JSON с обязательным полем title.');
  }

  const insertData = {
    title: payload.title,
    game_id: payload.gameId ?? null,
    resource_type: payload.resourceType ?? null,
    description_ru: payload.descriptionRu ?? null,
    description_en: payload.descriptionEn ?? null,
    images_json: payload.images ? JSON.stringify(payload.images) : null,
    status: payload.status ?? 'cart',
    entry_type: payload.entryType ?? 'hand',
    purchase_price_cny: payload.purchasePriceCny ?? null,
    listing_price_usd: payload.listingPriceUsd ?? null,
    sale_price_usd: payload.salePriceUsd ?? null,
    commission_usd: payload.commissionUsd ?? null,
    sale_platform: payload.salePlatform ?? null,
    source_url: payload.sourceUrl ?? null,
    quantity: payload.quantity ?? 1,
  } as const;

  const columns = Object.keys(insertData);
  const placeholders = columns.map(() => '?').join(', ');
  const values = Object.values(insertData);

  const id = await execute(env.DB, `INSERT INTO items (${columns.join(', ')}) VALUES (${placeholders})`, values);
  const row = await getFirst<Record<string, unknown>>(env.DB, 'SELECT * FROM items WHERE id = ?', [id]);
  return json({ message: 'Товар сохранён', item: row ? mapItemRow(row) : null });
}

async function updateItem(request: Request, env: Env, params: Record<string, string>): Promise<Response> {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return badRequest('Некорректный ID товара.');
  }

  const payload = (await request.json().catch(() => null)) as ItemUpdateInput | null;
  if (!payload || typeof payload !== 'object') {
    return badRequest('Передайте JSON с полями для обновления.');
  }

  const allowedStatuses = ['cart', 'warehouse', 'showcase', 'sold'];
  const updateMap: Record<string, unknown> = {};

  if (payload.title) updateMap.title = payload.title;
  if (payload.gameId !== undefined) updateMap.game_id = payload.gameId ?? null;
  if (payload.resourceType !== undefined) updateMap.resource_type = payload.resourceType ?? null;
  if (payload.descriptionRu !== undefined) updateMap.description_ru = payload.descriptionRu ?? null;
  if (payload.descriptionEn !== undefined) updateMap.description_en = payload.descriptionEn ?? null;
  if (payload.images) updateMap.images_json = JSON.stringify(payload.images);
  if (payload.status) {
    if (!allowedStatuses.includes(payload.status)) {
      return badRequest('Недопустимый статус. Используйте cart, warehouse, showcase или sold.');
    }
    updateMap.status = payload.status;
  }
  if (payload.entryType) updateMap.entry_type = payload.entryType;
  if (payload.purchasePriceCny !== undefined) updateMap.purchase_price_cny = payload.purchasePriceCny;
  if (payload.listingPriceUsd !== undefined) updateMap.listing_price_usd = payload.listingPriceUsd;
  if (payload.salePriceUsd !== undefined) updateMap.sale_price_usd = payload.salePriceUsd;
  if (payload.commissionUsd !== undefined) updateMap.commission_usd = payload.commissionUsd;
  if (payload.quantity !== undefined) updateMap.quantity = payload.quantity;
  if (payload.salePlatform !== undefined) updateMap.sale_platform = payload.salePlatform;
  if (payload.sourceUrl !== undefined) updateMap.source_url = payload.sourceUrl;

  if (!Object.keys(updateMap).length) {
    return badRequest('Нет полей для обновления.');
  }

  updateMap.updated_at = new Date().toISOString();

  const columns = Object.keys(updateMap);
  const placeholders = columns.map((column) => `${column} = ?`).join(', ');
  const bindings = [...Object.values(updateMap), id];

  const result = await env.DB.prepare(`UPDATE items SET ${placeholders} WHERE id = ?`).bind(...bindings).run();

  if (!result.success || (result.meta?.changes ?? 0) === 0) {
    return notFound('Товар не найден.');
  }

  if (payload.status) {
    const note = payload.statusNote ?? null;
    await env.DB.prepare('INSERT INTO item_status_history (item_id, status, note) VALUES (?, ?, ?)')
      .bind(id, payload.status, note)
      .run();
  }

  const row = await getFirst<Record<string, unknown>>(env.DB, 'SELECT * FROM items WHERE id = ?', [id]);
  return json({ message: 'Товар обновлён', item: row ? mapItemRow(row) : null });
}

async function listItems(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const allowedStatuses = ['cart', 'warehouse', 'showcase', 'sold'];

  const bindings: unknown[] = [];
  let whereClause = '';
  if (status) {
    if (!allowedStatuses.includes(status)) {
      return badRequest('Недопустимый статус. Используйте cart, warehouse, showcase или sold.');
    }
    whereClause = 'WHERE status = ?';
    bindings.push(status);
  }

  const rows = await runQuery<Record<string, unknown>>(env.DB, `SELECT * FROM items ${whereClause} ORDER BY created_at DESC`, bindings);
  return json({ items: rows.map(mapItemRow) });
}

async function getItem(request: Request, env: Env, params: Record<string, string>): Promise<Response> {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return badRequest('Некорректный ID товара.');
  }

  const row = await getFirst<Record<string, unknown>>(env.DB, 'SELECT * FROM items WHERE id = ?', [id]);
  if (!row) return notFound('Товар не найден.');

  const history = await runQuery<Record<string, unknown>>(
    env.DB,
    'SELECT status, note, changed_at FROM item_status_history WHERE item_id = ? ORDER BY changed_at DESC',
    [id],
  );

  return json({ item: mapItemRow(row), history });
}

async function deleteItem(_request: Request, env: Env, params: Record<string, string>): Promise<Response> {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return badRequest('Некорректный ID товара.');
  }

  const result = await env.DB.prepare('DELETE FROM items WHERE id = ?').bind(id).run();
  if (!result.success || (result.meta?.changes ?? 0) === 0) {
    return notFound('Товар не найден.');
  }

  return json({ message: 'Товар удалён' });
}

async function getStats(_request: Request, env: Env): Promise<Response> {
  const countsRows = await runQuery<{ status: string; count: number }>(
    env.DB,
    'SELECT status, COUNT(*) as count FROM items GROUP BY status',
  );
  const counts: Record<string, number> = { cart: 0, warehouse: 0, showcase: 0, sold: 0 };
  countsRows.forEach((row) => {
    if (counts[row.status] !== undefined) counts[row.status] = row.count;
  });
  const totalItems = Object.values(counts).reduce((acc, value) => acc + value, 0);

  const sums = await getFirst<{
    purchase: number | null;
    sale: number | null;
    commission: number | null;
  }>(
    env.DB,
    'SELECT SUM(COALESCE(purchase_price_usd, 0)) as purchase, SUM(COALESCE(sale_price_usd, 0)) as sale, SUM(COALESCE(commission_usd, 0)) as commission FROM items',
  );

  const statusTimeline = await runQuery<{
    day: string;
    status: string;
    count: number;
  }>(
    env.DB,
    "SELECT substr(changed_at, 1, 10) as day, status, COUNT(*) as count FROM item_status_history WHERE changed_at >= datetime('now', '-7 days') GROUP BY day, status ORDER BY day ASC",
  );

  const totals = {
    purchaseUsd: sums?.purchase ?? 0,
    saleUsd: sums?.sale ?? 0,
    commissionUsd: sums?.commission ?? 0,
  } as const;

  const profitUsd = totals.saleUsd - totals.purchaseUsd - totals.commissionUsd;

  return json({
    summary: { ...counts, total: totalItems },
    totals: { ...totals, profitUsd },
    timeline: statusTimeline,
  });
}

async function getTrends(_request: Request, env: Env): Promise<Response> {
  const lastAdded = await runQuery<{ day: string; count: number }>(
    env.DB,
    "SELECT substr(created_at, 1, 10) as day, COUNT(*) as count FROM items WHERE created_at >= datetime('now', '-14 days') GROUP BY day ORDER BY day ASC",
  );

  const lastSold = await runQuery<{ day: string; sold: number }>(
    env.DB,
    "SELECT substr(changed_at, 1, 10) as day, COUNT(*) as sold FROM item_status_history WHERE status = 'sold' AND changed_at >= datetime('now', '-14 days') GROUP BY day ORDER BY day ASC",
  );

  return json({
    added: lastAdded,
    sold: lastSold,
    message: 'Тренды собираются по событиям за последние 14 дней.',
  });
}

async function getSettings(_request: Request, env: Env): Promise<Response> {
  const rows = await runQuery<{ key: string; value: string }>(env.DB, 'SELECT key, value FROM settings');
  const settings = rows.reduce<Record<string, string>>((acc, row) => {
    acc[row.key] = row.value;
    return acc;
  }, {});
  return json({ settings });
}

async function saveSettings(request: Request, env: Env): Promise<Response> {
  const payload = (await request.json().catch(() => null)) as { settings?: Record<string, string> } | null;
  if (!payload || !payload.settings || typeof payload.settings !== 'object') {
    return badRequest('Передайте объект settings для сохранения.');
  }

  for (const [key, value] of Object.entries(payload.settings)) {
    await env.DB.prepare(
      'INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
    )
      .bind(key, String(value), new Date().toISOString())
      .run();
  }

  return json({ message: 'Настройки обновлены' });
}

const routes: RouteHandler[] = [
  {
    method: 'GET',
    path: /^\/api\/health$/,
    public: true,
    handler: () => json({ status: 'ok', timestamp: Date.now() }),
  },
  {
    method: 'POST',
    path: /^\/api\/login$/,
    public: true,
    handler: login,
  },
  {
    method: 'POST',
    path: /^\/api\/register$/,
    public: true,
    handler: register,
  },
  {
    method: 'POST',
    path: /^\/api\/telegram\/login$/,
    public: true,
    handler: telegramLogin,
  },
  {
    method: 'GET',
    path: /^\/api\/taobao\/search$/,
    handler: (_request, env) => {
      if (!env.RAPIDAPI_KEY) {
        return badRequest('RAPIDAPI_KEY не настроен в переменных окружения Cloudflare.');
      }
      return json({ data: [], message: 'Заглушка поиска. Реализуйте обращение к Just One API.' });
    },
  },
  {
    method: 'GET',
    path: /^\/api\/taobao\/item\/(?<id>[^/]+)$/,
    handler: (_request, env, params) => {
      if (!env.RAPIDAPI_KEY) {
        return badRequest('RAPIDAPI_KEY не настроен в переменных окружения Cloudflare.');
      }
      return json({ id: params.id, message: 'Заглушка деталей товара. Подключите Just One API.' });
    },
  },
  {
    method: 'POST',
    path: /^\/api\/products$/,
    handler: createItem,
  },
  {
    method: 'GET',
    path: /^\/api\/products$/,
    handler: listItems,
  },
  {
    method: 'GET',
    path: /^\/api\/products\/(?<id>\d+)$/,
    handler: getItem,
  },
  {
    method: 'PUT',
    path: /^\/api\/products\/(?<id>\d+)$/,
    handler: updateItem,
  },
  {
    method: 'GET',
    path: /^\/api\/stats$/,
    handler: getStats,
  },
  {
    method: 'GET',
    path: /^\/api\/trends$/,
    handler: getTrends,
  },
  {
    method: 'GET',
    path: /^\/api\/settings$/,
    handler: getSettings,
  },
  {
    method: 'POST',
    path: /^\/api\/settings$/,
    handler: saveSettings,
  },
  {
    method: 'DELETE',
    path: /^\/api\/products\/(?<id>\d+)$/,
    handler: deleteItem,
  },
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (!url.pathname.startsWith('/api')) {
      const protectedResponse = protectStatic(request, env);
      if (protectedResponse) return protectedResponse;
      if (env.ASSETS) {
        const assetResponse = await env.ASSETS.fetch(request);
        if (assetResponse.status !== 404) return assetResponse;
      }
      return new Response('Статика админки не найдена. Проверьте assets в wrangler.toml.', {
        status: 404,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }

    for (const route of routes) {
      if (route.method !== request.method) continue;
      const match = url.pathname.match(route.path);
      if (!match) continue;
      const params = (match.groups ?? {}) as Record<string, string>;
      try {
        if (!route.public) {
          const auth = await authenticate(request, env);
          if (!auth.ok) {
            return withCors(auth.response);
          }
        }
        const response = await route.handler(request, env, params);
        return withCors(response);
      } catch (error) {
        console.error('Route error', error);
        return withCors(json({ error: 'Внутренняя ошибка', details: String(error) }, { status: 500 }));
      }
    }
    return withCors(notFound());
  },
};
