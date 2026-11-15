import http from 'k6/http';
import {check,sleep} from 'k6';
export const options={vus:200,duration:'10m',thresholds:{http_req_duration:['p(95)<400'],http_req_failed:['rate<0.01']}};
export default function(){
 const res=http.get(`${__ENV.BASE_URL}/api/v1/dashboard`,{headers:{Authorization:`Bearer ${__ENV.ACCESS_TOKEN}`}});
 check(res,{'authorized response':r=>r.status===200});sleep(2);
}
