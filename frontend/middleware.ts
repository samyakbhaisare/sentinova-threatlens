import { NextResponse, type NextRequest } from 'next/server';

// Structured per-request log line (NFR-10). Static assets are excluded by the
// matcher below so the signal stays about application requests.
export function middleware(request: NextRequest) {
  const started = Date.now();
  const response = NextResponse.next();
  response.headers.set('X-Correlation-ID', crypto.randomUUID());
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'info',
    service: 'frontend',
    method: request.method,
    path: request.nextUrl.pathname,
    correlation_id: response.headers.get('X-Correlation-ID'),
    duration_ms: Date.now() - started,
  }));
  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
