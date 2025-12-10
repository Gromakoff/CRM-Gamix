import type { Ai, D1Database } from '@cloudflare/workers-types';
import { badRequest, json, notFound } from './lib/response';

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

type Env = {
  DB: D1Database;
  RAPIDAPI_KEY?: string;
  AI?: Ai;
  TELEGRAM_BOT_TOKEN?: string;
};

interface RouteHandler {
  method: Method;
  path: RegExp;
  handler: (request: Request, env: Env, params: Record<string, string>) => Promise<Response> | Response;
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
    handler: async (request) => {
      const body = await request.json().catch(() => null);
      if (!body) {
        return badRequest('Передайте JSON с данными товара.');
      }
      return json({ message: 'Заглушка сохранения товара.', data: body });
    },
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
    handler: () => json({
      rapidApiKey: 'не настроено',
      translators: ['yandex', 'microsoft', 'workers-ai'],
      markupPercent: 0,
    }),
  },
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    for (const route of routes) {
      if (route.method !== request.method) continue;
      const match = url.pathname.match(route.path);
      if (!match) continue;
      const params = (match.groups ?? {}) as Record<string, string>;
      try {
        return await route.handler(request, env, params);
      } catch (error) {
        console.error('Route error', error);
        return json({ error: 'Внутренняя ошибка', details: String(error) }, { status: 500 });
      }
    }
    return notFound();
  },
};
