import type { Ai, D1Database } from '@cloudflare/workers-types';
import { execute, getFirst, runQuery } from './lib/d1';
import { badRequest, json, notFound } from './lib/response';

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

type Env = {
  DB: D1Database;
  RAPIDAPI_KEY?: string;
  AI?: Ai;
  TELEGRAM_BOT_TOKEN?: string;
};

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

interface RouteHandler {
  method: Method;
  path: RegExp;
  handler: (request: Request, env: Env, params: Record<string, string>) => Promise<Response> | Response;
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
    handler: () => json({ status: 'ok', timestamp: Date.now() }),
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

    for (const route of routes) {
      if (route.method !== request.method) continue;
      const match = url.pathname.match(route.path);
      if (!match) continue;
      const params = (match.groups ?? {}) as Record<string, string>;
      try {
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
