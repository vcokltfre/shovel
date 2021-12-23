export async function handleRequest(request: Request): Promise<Response> {
  const { pathname } = new URL(request.url);

  return new Response(`${request.method} ${pathname}`);
}
