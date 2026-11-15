'use client';

import {FormEvent, useState} from 'react';
import {useQuery, useQueryClient} from '@tanstack/react-query';
import {api} from './api';

type IOCChoice = {id:string;value:string;type:string};
type Detail = IOCChoice & {status:string;tlp:string;notes:string;notes_tlp:string;version:number;expires_at:string;incident_ids:string[];relationships:{id:string;kind:string;target_id:string;source_id:string}[]};
type Rule = {id:string;version:number;name:string;min_score:number;min_sightings:number;category:string|null;feed_id:string|null;recipient_id:string|null;enabled:boolean};
type Person = {id:string;name:string;role:string};
type Feed = {id:string;name:string;interval_seconds:number;ttl_days:number};
type History = {id:string;action:string;created_at:string;data:unknown};

function useAction() {
  const client=useQueryClient();
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
  async function run(task:()=>Promise<unknown>, message='Changes saved') {
    setBusy(true);setError('');setNotice('');
    try {await task();setNotice(message);await client.invalidateQueries();}
    catch(e){setError((e as Error).message);}
    finally{setBusy(false);}
  }
  return {run,busy,feedback:<>{error&&<p className="error" role="alert">{error}</p>}{notice&&<p className="notice" role="status">{notice}</p>}</>};
}
function form(event:FormEvent<HTMLFormElement>) {event.preventDefault();return new FormData(event.currentTarget);}
function QueryError({error}:{error:Error|null}) {return error?<p className="error" role="alert">{error.message}</p>:null;}

export function IntelligenceOperations({indicators,role}:{indicators:IOCChoice[];role:string}) {
  const [id,setId]=useState('');
  const action=useAction();
  const detail=useQuery({queryKey:['operations-ioc',id],queryFn:()=>api<Detail>(`/indicators/${id}`),enabled:!!id});
  const history=useQuery({queryKey:['ioc-history',id],queryFn:()=>api<{items:History[]}>(`/indicators/${id}/history`),enabled:!!id});
  const ioc=detail.data;
  const contextual=role!=='incident_responder'||!!ioc?.incident_ids.length;
  const canLifecycle=['administrator','security_engineer','incident_responder'].includes(role)&&contextual;
  return <details className="panel"><summary>Manage IOC lifecycle, relationships and history</summary>
    <label>Indicator on the current results page<select aria-label="Managed indicator" value={id} onChange={e=>setId(e.target.value)}><option value="">Select indicator</option>{indicators.map(i=><option key={i.id} value={i.id}>{i.value} ({i.type})</option>)}</select></label>
    <QueryError error={detail.error}/><QueryError error={history.error}/>{action.feedback}
    {ioc&&<><p>Current handling: TLP:{ioc.tlp} · {ioc.status} · Expires {ioc.expires_at}</p>
      {!contextual&&<p className="muted">Responder edits require this IOC to be linked to an incident.</p>}
      {canLifecycle&&<form className="inline-form" key={id+':lifecycle:'+ioc.version} onSubmit={e=>{const values=form(e);const ttl=String(values.get('ttl_days')||'');void action.run(()=>api(`/indicators/${id}`,'PATCH',{expected_version:ioc.version,status:values.get('status'),tlp:values.get('tlp'),...(ttl?{ttl_days:Number(ttl)}:{})}),'IOC lifecycle updated');}}>
        <label>Status<select name="status" defaultValue={ioc.status}>{['active','expired','whitelisted','under_review'].map(v=><option key={v}>{v}</option>)}</select></label>
        <label>TLP<select name="tlp" defaultValue={ioc.tlp}>{['clear','green','amber','red'].map(v=><option key={v}>{v}</option>)}</select></label>
        <label>New TTL in days (optional)<input name="ttl_days" type="number" min={1} max={3650}/></label><button disabled={action.busy}>Save lifecycle</button>
      </form>}
      {contextual&&<form key={id+':notes:'+ioc.version} onSubmit={e=>{const values=form(e);void action.run(()=>api(`/indicators/${id}`,'PATCH',{expected_version:ioc.version,notes:values.get('notes'),notes_tlp:values.get('notes_tlp')}),'Classified IOC note saved');}}>
        <label>Classified IOC note<textarea name="notes" maxLength={20000} defaultValue={ioc.notes}/></label>
        <label>Note handling<select name="notes_tlp" defaultValue={ioc.notes_tlp||'amber'}>{['clear','green','amber','red'].map(tlp=><option key={tlp}>{tlp}</option>)}</select></label>
        <p className="muted">Narrative raises the IOC handling label when necessary. Ordinary edits cannot lower existing classifications.</p><button disabled={action.busy}>Save classified note</button>
      </form>}
      {contextual&&<form className="inline-form" onSubmit={e=>{const values=form(e);void action.run(()=>api(`/indicators/${id}/relationships`,'POST',{target_id:values.get('target_id'),kind:values.get('kind')}),'Relationship recorded');}}>
        <label>Relationship<select name="kind">{['resolves-to','communicates-with','drops','related-to'].map(v=><option key={v}>{v}</option>)}</select></label>
        <label>Related IOC ID<input name="target_id" required maxLength={36}/></label><button disabled={action.busy}>Add relationship</button>
      </form>}
      <h3>Stored relationships</h3>{ioc.relationships.length?ioc.relationships.map(edge=><p className="mono break" key={edge.id}>{edge.source_id} → {edge.kind} → {edge.target_id}</p>):<p className="muted">No relationships recorded.</p>}
      <h3>IOC history (latest 100 actions)</h3>{history.data?.items.map(item=><details key={item.id}><summary>{item.created_at} · {item.action}</summary><pre>{JSON.stringify(item.data,null,2)}</pre></details>)}
    </>}
  </details>;
}

export function AlertRuleManager() {
  const action=useAction(),[selected,setSelected]=useState('');
  const rules=useQuery({queryKey:['alert-rules'],queryFn:()=>api<{items:Rule[]}>('/alert-rules')});
  const feeds=useQuery({queryKey:['feeds'],queryFn:()=>api<{items:Feed[]}>('/feeds')});
  const people=useQuery({queryKey:['assignees'],queryFn:()=>api<{items:Person[]}>('/assignees')});
  const row=rules.data?.items.find(r=>r.id===selected);
  return <section className="panel"><h2>Manage correlation alert rules</h2><p className="muted">Changes affect subsequent correlation. Existing alerts retain their original routing and lifecycle.</p>
    {action.feedback}<QueryError error={rules.error}/><QueryError error={feeds.error}/><QueryError error={people.error}/>
    <label>Configured rule<select value={selected} onChange={e=>setSelected(e.target.value)}><option value="">Select a rule</option>{rules.data?.items.map(r=><option key={r.id} value={r.id}>{r.name} · {r.enabled?'enabled':'disabled'}</option>)}</select></label>
    {row&&<form key={row.id+':'+row.version} className="inline-form" onSubmit={e=>{const values=form(e);void action.run(()=>api(`/alert-rules/${row.id}`,'PATCH',{expected_version:row.version,name:values.get('name'),min_score:Number(values.get('min_score')),min_sightings:Number(values.get('min_sightings')),category:values.get('category')||null,feed_id:values.get('feed_id')||null,recipient_id:values.get('recipient_id')||null,enabled:values.get('enabled')==='on'}),'Alert rule updated');}}>
      <label>Rule name<input name="name" required maxLength={150} defaultValue={row.name}/></label>
      <label>Minimum score<input name="min_score" type="number" min={0} max={100} required defaultValue={row.min_score}/></label>
      <label>Minimum sightings<input name="min_sightings" type="number" min={0} max={100000} required defaultValue={row.min_sightings}/></label>
      <label>Category<input name="category" maxLength={100} defaultValue={row.category||''}/></label>
      <label>Intelligence source<select name="feed_id" defaultValue={row.feed_id||''}><option value="">Any source</option>{feeds.data?.items.map(f=><option key={f.id} value={f.id}>{f.name}</option>)}</select></label>
      <label>Notification recipient<select name="recipient_id" defaultValue={row.recipient_id||''}><option value="">Operational team</option>{people.data?.items.map(p=><option key={p.id} value={p.id}>{p.name} · {p.role}</option>)}</select></label>
      <label className="check"><input type="checkbox" name="enabled" defaultChecked={row.enabled}/>Enabled</label><button disabled={action.busy}>Save rule</button>
    </form>}
  </section>;
}

export function FeedScheduleManager() {
  const action=useAction(),[id,setId]=useState('');
  const feeds=useQuery({queryKey:['feeds'],queryFn:()=>api<{items:Feed[]}>('/feeds')});
  const feed=feeds.data?.items.find(f=>f.id===id);
  const diagnostics=useQuery({queryKey:['feed-diagnostics',id],queryFn:()=>api<{items:History[]}>(`/feeds/${id}/diagnostics`),enabled:!!id});
  return <details className="panel"><summary>Feed schedules, TTL and ingestion diagnostics</summary>{action.feedback}<QueryError error={diagnostics.error}/>
    <label>Feed<select value={id} onChange={e=>setId(e.target.value)}><option value="">Select feed</option>{feeds.data?.items.map(f=><option key={f.id} value={f.id}>{f.name}</option>)}</select></label>
    {feed&&<form key={id} className="inline-form" onSubmit={e=>{const values=form(e);void action.run(()=>api(`/feeds/${id}`,'PATCH',{interval_seconds:Number(values.get('interval_seconds')),ttl_days:Number(values.get('ttl_days'))}),'Feed schedule saved');}}>
      <label>Poll interval (seconds)<input type="number" name="interval_seconds" min={300} max={2592000} required defaultValue={feed.interval_seconds}/></label>
      <label>Indicator TTL (days)<input type="number" name="ttl_days" min={1} max={3650} required defaultValue={feed.ttl_days}/></label><button disabled={action.busy}>Save feed schedule</button>
    </form>}
    {diagnostics.data?.items.map(item=><details key={item.id}><summary>{item.created_at} · {item.action}</summary><pre>{JSON.stringify(item.data,null,2)}</pre></details>)}
  </details>;
}

export function IncidentEvidenceTools({id,role}:{id:string;role:string}) {
  const action=useAction();
  const people=useQuery({queryKey:['assignees'],queryFn:()=>api<{items:Person[]}>('/assignees')});
  return <section className="panel"><h2>Evidence and ownership</h2>{action.feedback}
    <form onSubmit={e=>{const values=form(e);void action.run(()=>api(`/incidents/${id}/timeline`,'POST',{text:values.get('text'),tlp:values.get('tlp')}),'Classified incident action appended');}}>
      <label>Classified incident action<textarea name="text" required maxLength={20000}/></label><label>Action handling<select name="tlp" defaultValue="amber">{['clear','green','amber','red'].map(tlp=><option key={tlp}>{tlp}</option>)}</select></label><button disabled={action.busy}>Append classified action</button>
    </form>
    <form className="inline-form" onSubmit={e=>{const values=form(e);void action.run(()=>api(`/incidents/${id}/links`,'POST',{indicator_id:values.get('indicator_id'),alert_id:values.get('alert_id')||null}),'Evidence linked to incident');}}>
      <label>Indicator ID<input name="indicator_id" required maxLength={36}/></label><label>Related alert ID (optional)<input name="alert_id" maxLength={36}/></label><button disabled={action.busy}>Link evidence</button>
    </form>
    {['administrator','incident_responder'].includes(role)&&<form className="inline-form" onSubmit={e=>{const values=form(e);void action.run(()=>api(`/incidents/${id}`,'PATCH',{owner_id:values.get('owner_id')}),'Incident ownership updated');}}>
      <label>Responder owner<select name="owner_id" required><option value="">Select responder</option>{people.data?.items.filter(p=>['administrator','incident_responder'].includes(p.role)).map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label><button disabled={action.busy}>Assign incident owner</button>
    </form>}
  </section>;
}

export function ReportScheduleManager() {
  const action=useAction();
  const reports=useQuery({queryKey:['reports'],queryFn:()=>api<{items:{id:string;title:string;state:string;schedule_hours:number|null}[]}>('/reports')});
  return <details className="panel"><summary>Manage scheduled and queued reports</summary>{action.feedback}<QueryError error={reports.error}/>
    {reports.data?.items.map(report=><div className="result" key={report.id}><strong>{report.title}</strong><span>{report.state}</span>
      {report.schedule_hours&&<button disabled={action.busy} onClick={()=>void action.run(()=>api(`/reports/${report.id}`,'PATCH',{schedule_hours:null}),'Report schedule disabled')}>Stop schedule</button>}
      {report.state==='queued'&&<button disabled={action.busy} onClick={()=>void action.run(()=>api(`/reports/${report.id}`,'PATCH',{cancel:true}),'Queued report cancelled')}>Cancel queued report</button>}
    </div>)}
  </details>;
}
