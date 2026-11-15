const api = process.env.API_INTERNAL_URL || 'http://127.0.0.1:8100';
const dev = process.env.NODE_ENV !== 'production';
const productionCsp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.tile.openstreetmap.org; connect-src 'self' ws://localhost:8100 ws://127.0.0.1:8100 wss://localhost:8100 wss://127.0.0.1:8100; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
const csp = dev ? productionCsp
  .replace("script-src 'self' 'unsafe-inline'", "script-src 'self' 'unsafe-inline' 'unsafe-eval'")
  .replace("connect-src 'self' ws://localhost:8100 ws://127.0.0.1:8100", "connect-src 'self' ws://localhost:8100 ws://127.0.0.1:8100 ws://localhost:8000 ws://127.0.0.1:8000 ws://localhost:3000 ws://127.0.0.1:3000")
  : productionCsp;
export default {
  output: 'standalone',
  poweredByHeader: false,
  async rewrites() { return [{source:'/api/:path*', destination:`${api}/api/:path*`}]; },
  async headers() { return [{source:'/:path*', headers:[
    {key:'X-Content-Type-Options',value:'nosniff'}, {key:'X-Frame-Options',value:'DENY'},
    {key:'Referrer-Policy',value:'no-referrer'},
    {key:'Content-Security-Policy',value:csp}
  ]}]; }
};
