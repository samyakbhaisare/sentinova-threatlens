'use client';

import {useState} from 'react';
import {useQuery,useQueryClient} from '@tanstack/react-query';
import {ResponsiveContainer,LineChart,Line,CartesianGrid,XAxis,YAxis,Tooltip} from 'recharts';
import {api} from './api';

type RiskPoint={id:string;captured_at:string;bucket_start:string;risk_score:number|null;active_indicators:number;high_critical:number;incidents:Record<string,number>;alerts:Record<string,number>};
type Technique={technique_id:string;name:string|null;tactics:string[];active_indicators:number;known:boolean;catalog_present:boolean;revoked:boolean;deprecated:boolean;reference_url:string|null};
type Coverage={items:Technique[];active_reference_count:number;observed_count:number;metric:string;sync:null|{state:string;completed_at:string|null;item_count:number;checksum:string|null;error:string|null}};

function stamp(input:unknown){const value=typeof input==='string'?input:input==null?'':String(input);if(!value)return 'Not recorded';const date=new Date(value);if(Number.isNaN(date.getTime()))return value;return date.toISOString().slice(0,16).replace('T',' ')+' UTC';}
function day(value:string){const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toISOString().slice(0,10);}

export function RiskHistory({days,canCapture}:{days:number;canCapture:boolean}) {
 const client=useQueryClient(),[error,setError]=useState(''),[pending,setPending]=useState(false),[notice,setNotice]=useState('');
 const history=useQuery({queryKey:['risk-history',days],queryFn:()=>api<{items:RiskPoint[];metric:string;backfilled:boolean}>(`/dashboard/risk-history?days=${days}`),refetchInterval:60000});
 // Measured points are plotted as recorded. No hourly interpolation is added,
 // so a gap stays a gap instead of a zero-length segment.
 const series=(history.data?.items||[]).map(point=>({bucket_start:point.bucket_start,risk_score:point.risk_score}));
 async function capture(){setPending(true);setError('');try{await api('/dashboard/risk-snapshots','POST');setNotice('Snapshot request queued. History updates after worker capture.');await client.invalidateQueries({queryKey:['risk-history']});}catch(e){setError((e as Error).message);}finally{setPending(false);}}
 return <section className="panel"><div className="title-row"><h2>Historical risk posture</h2>{canCapture&&<button disabled={pending} onClick={()=>void capture()}>Capture current posture</button>}</div>
  <p className="muted">Hourly measurements of mean active IOC priority. Missing periods remain gaps; no history is backfilled.</p>
  {(history.error||error)&&<p role="alert" className="error">{error||history.error?.message}</p>}{notice&&<p role="status">{notice}</p>}
  {history.data?.items.length?<><ResponsiveContainer width="100%" height={240}><LineChart data={series} margin={{top:8,right:16,bottom:4,left:0}}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="bucket_start" minTickGap={28} tickFormatter={day}/><YAxis domain={[0,100]}/><Tooltip labelFormatter={stamp}/><Line name="Risk priority" type="linear" dataKey="risk_score" stroke="#53dfca" connectNulls={false} dot={{r:2.5,strokeWidth:0,fill:'#53dfca'}} activeDot={{r:4}} isAnimationActive={false}/></LineChart></ResponsiveContainer>
  <details><summary>Measured posture data and incident throughput</summary><div className="table-wrap"><table><thead><tr><th>Captured</th><th>Risk priority</th><th>Active IOCs</th><th>High / critical</th><th>Open / resolved incidents</th></tr></thead><tbody>{history.data.items.map(point=><tr key={point.id}><td>{stamp(point.captured_at)}</td><td>{point.risk_score??'No active intelligence'}</td><td>{point.active_indicators}</td><td>{point.high_critical}</td><td>{point.incidents.open||0} / {point.incidents.resolved||0}</td></tr>)}</tbody></table></div></details></>:<p className="empty">{history.isLoading?'Loading measured history…':'No snapshots captured yet. History begins when the worker records actual posture.'}</p>}
 </section>;
}

export function AttackCoverage({canSync,onTechnique}:{canSync:boolean;onTechnique:(id:string)=>void}) {
 const client=useQueryClient(),[filter,setFilter]=useState(''),[page,setPage]=useState(0),[inactive,setInactive]=useState(false),[pending,setPending]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const coverage=useQuery({queryKey:['attack-coverage'],queryFn:()=>api<Coverage>('/attack/coverage'),refetchInterval:30000});
 const records=coverage.data?.items||[];
 const filtered=records.filter(t=>(inactive||!t.known||(t.catalog_present&&!t.revoked&&!t.deprecated))&&`${t.technique_id} ${t.name||''} ${t.tactics.join(' ')}`.toLowerCase().includes(filter.toLowerCase()));
 async function sync(){setPending(true);setError('');try{await api('/attack/sync','POST');setNotice('MITRE synchronization queued. Only validated source records become known references.');await client.invalidateQueries({queryKey:['attack-coverage']});}catch(e){setError((e as Error).message);}finally{setPending(false);}}
 return <section className="panel"><div className="title-row"><h2>MITRE ATT&CK intelligence coverage</h2>{canSync&&<button disabled={pending} onClick={()=>void sync()}>Synchronize MITRE reference</button>}</div>
  <p className="muted">{coverage.data?.metric||'Coverage represents active IOC mappings. It is not a measurement of detector effectiveness.'}</p>
  {(coverage.error||error)&&<p role="alert" className="error">{error||coverage.error?.message}</p>}{notice&&<p role="status">{notice}</p>}
  <p>{coverage.data?.observed_count||0} observed / {coverage.data?.active_reference_count||0} active reference techniques</p>
  {coverage.data?.sync&&<p className="muted">Reference job: {coverage.data.sync.state} · {coverage.data.sync.completed_at||'Not completed'} · {coverage.data.sync.item_count} references{coverage.data.sync.error?` · ${coverage.data.sync.error}`:''}</p>}
  <div className="toolbar"><label>Technique, tactic or name<input aria-label="ATT&CK reference filter" value={filter} onChange={e=>{setFilter(e.target.value);setPage(0);}}/></label><label className="check"><input type="checkbox" checked={inactive} onChange={e=>{setInactive(e.target.checked);setPage(0);}}/>Include retired or missing references</label></div>
  <div className="attack-grid">{filtered.slice(page*60,page*60+60).map(t=><article className="attack-card" key={t.technique_id}><button className="link" onClick={()=>onTechnique(t.technique_id)}>{t.technique_id} · {t.name||'Unresolved analyst mapping'}</button><p>{t.tactics.join(' · ')||'No synchronized tactic metadata'}</p><span className={'badge '+(t.active_indicators?'medium':'low')}>{t.active_indicators} active IOCs</span>{!t.known&&<small>Reference not synchronized; no MITRE metadata is asserted.</small>}{(t.revoked||t.deprecated||!t.catalog_present)&&t.known&&<small>Retired or absent from current reference catalog</small>}</article>)}</div>
  {!records.length&&<p className="empty">No ATT&CK references or analyst mappings stored. Synchronize the official reference to display coverage.</p>}
  <div className="toolbar"><button disabled={page===0} onClick={()=>setPage(page-1)}>Previous techniques</button><span>{filtered.length} matching techniques</span><button disabled={(page+1)*60>=filtered.length} onClick={()=>setPage(page+1)}>Next techniques</button></div>
  <small>Reference source: MITRE ATT&CK enterprise STIX. Catalog status and checksum are retained with each synchronization.</small>
 </section>;
}
