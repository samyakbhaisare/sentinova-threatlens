'use client';
import {FormEvent,useState} from 'react';
import {useQuery,useQueryClient} from '@tanstack/react-query';
import {api,download} from './api';

type Job={id:string;format:string;audience:string;state:string;record_count:number;matching_count:number;limited:boolean;attempts:number;checksum:string|null;error:string|null;completed_at:string|null};
export function BulkExports() {
 const client=useQueryClient(),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const jobs=useQuery({queryKey:['bulk-exports'],queryFn:()=>api<{items:Job[]}>('/exports'),refetchInterval:5000});
 async function run(action:()=>Promise<unknown>,message:string){setBusy(true);setError('');try{await action();setNotice(message);await client.invalidateQueries({queryKey:['bulk-exports']});}catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();const values=new FormData(event.currentTarget);void run(()=>api('/exports','POST',{format:values.get('format'),audience:values.get('audience'),max_records:Number(values.get('max_records')),selection:{q:values.get('q')||'',type:values.get('type')||null,min_score:Number(values.get('min_score')),tag:values.get('tag')||null,technique:values.get('technique')||null,status:'active'}}),'Export queued; download becomes available only after generation and integrity checks.');}
 return <section className="panel"><h2>Large background intelligence exports</h2>
  <p className="muted">Active IOC selections are generated in bounded batches. Public sharing includes TLP:clear only; internal sharing follows your role. Changed classifications revoke downloads. A selected row cap is explicitly reported.</p>
  {(error||jobs.error)&&<p role="alert" className="error">{error||jobs.error?.message}</p>}{notice&&<p role="status">{notice}</p>}
  <form className="inline-form" onSubmit={submit}>
   <label>Background export format<select name="format"><option value="csv">CSV</option><option value="stix">STIX 2.1</option></select></label>
   <label>Sharing audience<select name="audience"><option value="public">Public — clear only</option><option value="internal">Internal — role permitted labels</option></select></label>
   <label>Value contains<input name="q" maxLength={500}/></label>
   <label>IOC type<select name="type"><option value="">All types</option>{['ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','cve'].map(type=><option key={type}>{type}</option>)}</select></label>
   <label>Minimum exported score<input name="min_score" type="number" min={0} max={100} defaultValue={0}/></label>
   <label>Tag filter<input name="tag" maxLength={80}/></label><label>Technique filter<input name="technique" maxLength={16}/></label>
   <label>Maximum included records<input name="max_records" type="number" min={1} max={5000000} defaultValue={100000} required/></label><button disabled={busy}>Queue background export</button>
  </form>
  <div className="table-wrap"><table><thead><tr><th>Job / format</th><th>State</th><th>Records</th><th>Evidence</th><th>Actions</th></tr></thead><tbody>{jobs.data?.items.map(job=><tr key={job.id}>
   <td><span className="mono">{job.id}</span><small>{job.format} · {job.audience}</small></td><td>{job.state}<small>Attempt {job.attempts}</small></td><td>{job.record_count} / {job.matching_count}{job.limited&&<strong> · row cap applied</strong>}</td><td>{job.error||job.completed_at||'Pending'}{job.checksum&&<small className="mono break">SHA-256: {job.checksum}</small>}</td>
   <td><div className="actions">{job.state==='ready'&&<button disabled={busy} onClick={()=>void run(()=>download(`/exports/${job.id}/download`,`threatlens-${job.id}.${job.format==='csv'?'csv':'json'}`),'Export downloaded')}>Download export</button>}{['queued','running','ready'].includes(job.state)&&<button disabled={busy} onClick={()=>void run(()=>api(`/exports/${job.id}/cancel`,'POST'),'Export cancelled; artifacts remain retained')}>Cancel export</button>}{job.state==='failed'&&job.attempts<3&&<button disabled={busy} onClick={()=>void run(()=>api(`/exports/${job.id}/retry`,'POST'),'Retry queued')}>Retry export</button>}</div></td>
  </tr>)}</tbody></table></div>{!jobs.data?.items.length&&<p className="empty">No background export jobs for this account.</p>}
 </section>;
}
