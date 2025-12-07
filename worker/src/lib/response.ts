export function json(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has('content-type')) {
    headers.set('content-type', 'application/json; charset=utf-8');
  }
  return new Response(JSON.stringify(body, null, 2), {
    ...init,
    headers,
  });
}

export function badRequest(message: string, details?: unknown): Response {
  return json({ error: message, details }, { status: 400 });
}

export function notFound(message = 'Not Found'): Response {
  return json({ error: message }, { status: 404 });
}

export function internalError(message = 'Internal Server Error', details?: unknown): Response {
  return json({ error: message, details }, { status: 500 });
}
