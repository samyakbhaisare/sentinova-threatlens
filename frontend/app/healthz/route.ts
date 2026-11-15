export const dynamic = 'force-dynamic';

export async function GET() {
  return Response.json({
    status: 'ok',
    service: 'frontend',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.round(process.uptime()),
  });
}
