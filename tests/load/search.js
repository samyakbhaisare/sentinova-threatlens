import http from 'k6/http';
import {check,sleep} from 'k6';
export const options={vus:20,duration:'5m',thresholds:{http_req_duration:['p(95)<800'],http_req_failed:['rate<0.01']}};
export function setup(){
 if(Number(__ENV.INDEX_DOCUMENT_COUNT)<10000000)throw new Error('Record actual >=10M index count before claiming NFR-05');
}
export default function(){
 const res=http.get(`${__ENV.BASE_URL}/api/v1/search?q=domain&type=domain`,{headers:{Authorization:`Bearer ${__ENV.ACCESS_TOKEN}`}});
 check(res,{'search ok':r=>r.status===200});sleep(1);
}
