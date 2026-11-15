// Explicit component/HTTP-contract tests with controlled fixtures.
// These do not replace PostgreSQL/Redis/search end-to-end acceptance.
import {test,expect,Page} from '@playwright/test';

const ioc={id:'ioc-1',version:1,value:'CONTROLLED.example.org',type:'domain',score:70,confidence:50,status:'active',tlp:'clear',notes_tlp:'amber',category:'controlled-test',tags:[],techniques:[],notes:'',breakdown:{},expires_at:'2026-12-01T00:00:00Z',incident_ids:[],relationships:[],sources:[],sightings:[],enrichments:[]};
const feed={id:'feed-1',name:'CONTROLLED source',adapter:'json',enabled:false,interval_seconds:3600,ttl_days:30,ingested:0,rejected:0,last_success:null,last_failure:null,error:null};
const rule={id:'rule-1',version:1,name:'CONTROLLED rule',min_score:70,min_sightings:1,category:null,feed_id:null,recipient_id:null,enabled:true};

async function fixtures(page:Page,role='administrator',subscriptions?:string[][]) {
 const mutations:{path:string;body:Record<string,unknown>}[]=[];
 const permissions=role==='soc_analyst'?['dashboard','search','tag','enrich','alert','incident','hunt','export','report']:['dashboard','search','tag','enrich','alert','incident','hunt','export','report','feed','user','audit'];
 await page.route('**/api/v1/**',async route=>{
  const request=route.request(),path=new URL(request.url()).pathname.replace('/api/v1','');
  let result:unknown;
  if(path==='/auth/refresh')result={access_token:'controlled-test-token'};
  else if(path==='/auth/me')result={id:'user-1',name:'CONTROLLED TEST USER',email:'test@example.org',role,layout:[],permissions};
  else if(request.method()==='PATCH'||request.method()==='POST'){
   const body=request.postData()?request.postDataJSON():{};mutations.push({path,body});result={...body,id:'controlled-result'};
  } else if(path==='/dashboard')result={layout:[],active_indicators:0,high_critical:0,risk_score:null,trends:[],categories:[],sources:[],severity:[],alerts:{},incidents:{},geo:[],assets:[]};
  else if(path==='/indicators')result={items:[ioc],total:1};
  else if(path==='/indicators/ioc-1')result=ioc;
  else if(path==='/feeds')result={items:[feed]};
  else if(path==='/alert-rules')result={items:[rule]};
  else if(path==='/reports')result={items:[{id:'report-1',title:'CONTROLLED scheduled report',state:'queued',schedule_hours:24,error:null}]};
  else if(path==='/exports')result={items:[{id:'export-1',format:'csv',audience:'public',state:'queued',record_count:0,matching_count:0,limited:false,attempts:0,checksum:null,error:null,completed_at:null}]};
  else if(path==='/attack/coverage')result={items:[{technique_id:'T1059',name:'CONTROLLED reference',tactics:['execution'],active_indicators:2,known:true,catalog_present:true,revoked:false,deprecated:false,reference_url:null}],active_reference_count:1,observed_count:1,metric:'Controlled intelligence coverage fixture',sync:null};
  else if(path==='/dashboard/risk-history')result={items:[],metric:'Measured snapshots',backfilled:false};
  else if(path==='/incidents')result={items:[{id:'inc-1',title:'CONTROLLED investigation',state:'open',owner_id:'user-1',creator_id:'user-1',checklist:{}}]};
  else if(path==='/incidents/inc-1/timeline')result={incident:{id:'inc-1',title:'CONTROLLED investigation',state:'open',owner_id:'user-1',creator_id:'user-1',checklist:{}},items:[],links:[]};
  else if(path==='/assignees')result={items:[{id:'user-1',name:'CONTROLLED responder',role:'incident_responder'}]};
  else result={items:[]};
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(result)});
 });
 await page.routeWebSocket('**/api/v1/ws',socket=>{
  if(!subscriptions){socket.close();return;}
  socket.onMessage(message=>{const hello=JSON.parse(String(message));subscriptions.push(hello.channels);socket.send(JSON.stringify({status:'subscribed',channels:hello.channels}));});
 });
 return mutations;
}

test('engineer controls submit lifecycle, relationship and rule updates',async({page})=>{
 const mutations=await fixtures(page);
 await page.goto('/');
 await page.getByRole('button',{name:'Intelligence library',exact:true}).click();
 await page.getByText('Manage IOC lifecycle, relationships and history',{exact:true}).click();
 await page.getByLabel('Managed indicator').selectOption('ioc-1');
 await page.getByRole('combobox',{name:'Status',exact:true}).selectOption('expired');
 await page.getByRole('combobox',{name:'TLP',exact:true}).selectOption('amber');
 await page.getByLabel('New TTL in days (optional)').fill('7');
 await page.getByRole('button',{name:'Save lifecycle'}).click();
 await expect(page.getByRole('status')).toContainText('IOC lifecycle updated');
 expect(mutations.find(m=>m.path==='/indicators/ioc-1')?.body).toEqual({expected_version:1,status:'expired',tlp:'amber',ttl_days:7});
 await page.getByLabel('Related IOC ID').fill('ioc-2');
 await page.getByRole('button',{name:'Add relationship'}).click();
 await expect(page.getByRole('status')).toContainText('Relationship recorded');
 expect(mutations.find(m=>m.path.endsWith('/relationships'))?.body).toEqual({target_id:'ioc-2',kind:'resolves-to'});
 await page.getByRole('button',{name:'Feed operations',exact:true}).click();
 await page.getByLabel('Configured rule').selectOption('rule-1');
 const editor=page.locator('form').filter({has:page.getByRole('button',{name:'Save rule',exact:true})});
 await editor.getByLabel('Minimum score',{exact:true}).fill('90');
 await editor.getByLabel('Enabled',{exact:true}).uncheck();
 await editor.getByRole('button',{name:'Save rule',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Alert rule updated');
 expect(mutations.find(m=>m.path==='/alert-rules/rule-1')?.body).toMatchObject({min_score:90,enabled:false,feed_id:null,recipient_id:null});
});

test('analyst can inspect history and add relationships but has no lifecycle controls',async({page})=>{
 await fixtures(page,'soc_analyst');
 await page.goto('/');
 await page.getByRole('button',{name:'Intelligence library',exact:true}).click();
 await page.getByText('Manage IOC lifecycle, relationships and history',{exact:true}).click();
 await page.getByLabel('Managed indicator').selectOption('ioc-1');
 await expect(page.getByRole('heading',{name:'IOC history (latest 100 actions)'})).toBeVisible();
 await expect(page.getByRole('button',{name:'Save lifecycle'})).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Add relationship'})).toBeVisible();
 await expect(page.getByRole('button',{name:'Feed operations',exact:true})).toHaveCount(0);
});

test('report owner can request schedule stop and queued cancellation',async({page})=>{
 const mutations=await fixtures(page,'soc_analyst');
 await page.goto('/');
 await page.getByRole('button',{name:'Reports & exports',exact:true}).click();
 await page.getByText('Manage scheduled and queued reports',{exact:true}).click();
 await page.getByRole('button',{name:'Stop schedule',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Report schedule disabled');
 await page.getByRole('button',{name:'Cancel queued report',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Queued report cancelled');
 expect(mutations.filter(m=>m.path==='/reports/report-1').map(m=>m.body)).toEqual([{schedule_hours:null},{cancel:true}]);
});

test('incident selection subscribes to its authorized realtime channel',async({page})=>{
 const subscriptions:string[][]=[];
 await fixtures(page,'soc_analyst',subscriptions);
 await page.goto('/');
 await page.getByRole('button',{name:'Incident response',exact:true}).click();
 await page.getByRole('button',{name:/CONTROLLED investigation/}).click();
 await expect.poll(()=>subscriptions.some(channels=>channels.includes('incidents.inc-1'))).toBe(true);
});

test('reference synchronization and overlay pivot submit controlled API requests',async({page})=>{
 const mutations=await fixtures(page);
 await page.goto('/');
 await page.getByRole('button',{name:'Threat hunting',exact:true}).click();
 await expect(page.getByRole('heading',{name:'MITRE ATT&CK intelligence coverage'})).toBeVisible();
 const query=page.waitForRequest(request=>request.url().includes('/search?')&&request.url().includes('technique=T1059'));
 await page.getByRole('button',{name:'T1059 · CONTROLLED reference',exact:true}).click();
 await query;
 await page.getByRole('button',{name:'Synchronize MITRE reference',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('synchronization queued');
 expect(mutations.some(item=>item.path==='/attack/sync')).toBe(true);
});

test('historical posture stays empty until measured capture is requested',async({page})=>{
 const mutations=await fixtures(page);
 await page.goto('/');
 await page.getByRole('button',{name:'Executive overview',exact:true}).click();
 await expect(page.getByText(/No snapshots captured yet/)).toBeVisible();
 await page.getByRole('button',{name:'Capture current posture',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Snapshot request queued');
 expect(mutations.some(item=>item.path==='/dashboard/risk-snapshots')).toBe(true);
});

test('large exports queue criteria and can be cancelled without claiming completion',async({page})=>{
 const mutations=await fixtures(page,'soc_analyst');
 await page.goto('/');
 await page.getByRole('button',{name:'Reports & exports',exact:true}).click();
 await page.getByLabel('Value contains').fill('controlled');
 await page.getByLabel('Maximum included records').fill('2500');
 await page.getByRole('button',{name:'Queue background export',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Export queued');
 expect(mutations.find(item=>item.path==='/exports')?.body).toMatchObject({format:'csv',audience:'public',max_records:2500,selection:{q:'controlled',status:'active'}});
 await page.getByRole('button',{name:'Cancel export',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Export cancelled');
 expect(mutations.some(item=>item.path==='/exports/export-1/cancel')).toBe(true);
});

test('analyst narrative submits explicit handling and optimistic version',async({page})=>{
 const mutations=await fixtures(page,'soc_analyst');
 await page.goto('/');
 await page.getByRole('button',{name:'Intelligence library',exact:true}).click();
 await page.getByText('Manage IOC lifecycle, relationships and history',{exact:true}).click();
 await page.getByLabel('Managed indicator').selectOption('ioc-1');
 await page.getByLabel('Classified IOC note',{exact:true}).fill('CONTROLLED restricted note');
 await page.getByRole('combobox',{name:'Note handling',exact:true}).selectOption('red');
 await page.getByRole('button',{name:'Save classified note',exact:true}).click();
 await expect(page.getByRole('status')).toContainText('Classified IOC note saved');
 expect(mutations.find(item=>item.path==='/indicators/ioc-1')?.body).toEqual({expected_version:1,notes:'CONTROLLED restricted note',notes_tlp:'red'});
});

test('investigation drawer also sends annotation handling and version',async({page})=>{
 const mutations=await fixtures(page,'soc_analyst');
 await page.goto('/');
 await page.getByRole('button',{name:'Intelligence library',exact:true}).click();
 await page.getByRole('button',{name:'CONTROLLED.example.org',exact:true}).click();
 const dialog=page.getByRole('dialog',{name:'Indicator investigation'});
 await dialog.getByLabel('Analyst notes',{exact:true}).fill('CONTROLLED drawer narrative');
 await dialog.getByRole('combobox',{name:'Annotation handling',exact:true}).selectOption('red');
 await dialog.getByRole('button',{name:'Save annotations',exact:true}).click();
 await expect.poll(()=>mutations.some(item=>item.path==='/indicators/ioc-1')).toBe(true);
 expect(mutations.find(item=>item.path==='/indicators/ioc-1')?.body).toMatchObject({expected_version:1,annotation_tlp:'red',notes_tlp:'red'});
});
