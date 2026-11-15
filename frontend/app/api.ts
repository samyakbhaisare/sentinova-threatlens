let token = '';
let rotating: Promise<boolean> | null = null;
export const setToken = (value:string) => { token = value; };
export const getToken = () => token;

export async function rotate() {
  if (!rotating) rotating = fetch('/api/v1/auth/refresh', {method:'POST', credentials:'include',signal:AbortSignal.timeout(8000)}).then(async r => {
    if (!r.ok) {token=''; return false;}
    token=(await r.json()).access_token;
    return true;
  }).finally(() => {rotating=null;});
  return rotating;
}

export async function api<T = Record<string, unknown>>(path:string, method='GET', body?:unknown, retry=true):Promise<T> {
  const response=await fetch('/api/v1'+path, {method, credentials:'include', signal:AbortSignal.timeout(15000), headers:{'Content-Type':'application/json', ...(token?{Authorization:'Bearer '+token}:{})}, body:body===undefined?undefined:JSON.stringify(body)});
  if (response.status===401 && retry && !path.startsWith('/auth/')) {
    if (await rotate()) return api<T>(path,method,body,false);
    if (typeof window!=='undefined') window.dispatchEvent(new Event('threatlens:session-expired'));
    throw new Error('Session expired. Sign in again.');
  }
  if (!response.ok) {const error=await response.json().catch(()=>({message:'Service unavailable'})); throw new Error(error.message || 'Request failed');}
  return response.json();
}

export async function download(path:string, name:string) {
  let response=await fetch('/api/v1'+path,{credentials:'include',headers:token?{Authorization:'Bearer '+token}:{}});
  if (response.status===401 && await rotate()) {
    response=await fetch('/api/v1'+path,{credentials:'include',headers:token?{Authorization:'Bearer '+token}:{}});
  }
  if (!response.ok) {const error=await response.json().catch(()=>({message:'Download failed'})); throw new Error(error.message || 'Download failed');}
  const url=URL.createObjectURL(await response.blob());
  const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);
}
