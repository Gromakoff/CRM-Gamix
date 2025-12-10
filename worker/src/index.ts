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
  salePlatform?: string;
  sourceUrl?: string;
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
    sale_platform: payload.salePlatform ?? null,
    source_url: payload.sourceUrl ?? null,
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
    method: 'PUT',
    path: /^\/api\/products\/(?<id>\d+)$/,
    handler: updateItem,
  },
  {
    method: 'GET',
    path: /^\/api\/stats$/,
    handler: () => json({ revenue: 0, cost: 0, profit: 0, message: 'Заглушка статистики.' }),
  },
  {
    method: 'GET',
    path: /^\/api\/trends$/,
    handler: () => json({ items: [], message: 'Заглушка трендов.' }),
  },
  {
    method: 'GET',
    path: /^\/api\/settings$/,
    handler: () =>
      json({
        rapidApiKey: 'не настроено',
        translators: ['yandex', 'microsoft', 'workers-ai'],
        markupPercent: 0,
      }),
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
