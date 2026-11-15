export const dynamic = 'force-dynamic';

export async function GET() {
  const lines = [
    '# HELP threatlens_frontend_up Frontend process liveness.',
    '# TYPE threatlens_frontend_up gauge',
    'threatlens_frontend_up 1',
    '# HELP threatlens_frontend_uptime_seconds Frontend process uptime.',
    '# TYPE threatlens_frontend_uptime_seconds gauge',
    `threatlens_frontend_uptime_seconds ${Math.round(process.uptime())}`,
    '# HELP threatlens_frontend_info Frontend build information.',
    '# TYPE threatlens_frontend_info gauge',
    'threatlens_frontend_info{version="1.0.0"} 1',
    '',
  ];
  return new Response(lines.join('\n'), { headers: { 'Content-Type': 'text/plain; version=0.0.4' } });
}
