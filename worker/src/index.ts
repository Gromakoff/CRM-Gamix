export interface Env {
  DB: D1Database;
  SESSION_CACHE: KVNamespace;
  INTEGRATION_CACHE: KVNamespace;
  RAPIDAPI_KEY: string;
  RAPIDAPI_HOST: string;
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_CHAT_ID: string;
  FUNPAY_TOKEN: string;
  AI_GATEWAY_TOKEN: string;
  JWT_SECRET: string;
}

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      const dbCheck = await checkDatabase(env);
      return jsonResponse({
        status: "ok",
        app: env.APP_NAME ?? "worker",
        db: dbCheck,
        timestamp: new Date().toISOString(),
      });
    }

    return jsonResponse({ error: "Not Found" }, 404);
  },
};

async function checkDatabase(env: Env) {
  try {
    const row = await env.DB.prepare("SELECT 1 as ok").first<{ ok: number }>();
    const success = row?.ok === 1;
    return { ok: success };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, error: message };
  }
}
