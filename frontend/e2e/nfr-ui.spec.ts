import {test,expect,type Page,type Browser} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const RUN=process.env.NFR_UI_RUN||new Date().toISOString().replace(/[:.]/g,'-');
const OUT=path.resolve(`../artifacts/verification/${RUN}-ui-latency.json`);

async function prepare(page:Page){
  // Dashboard data is proxied to the isolated API. Basemap tiles are irrelevant
  // to interactive timing and are blocked so external network jitter cannot skew it.
  await page.route('https://*.tile.openstreetmap.org/**',route=>route.abort());
  if(process.env.E2E_API_URL)await page.route('**/api/v1/**',async route=>{
    const url=new URL(route.request().url());
    try{
      const response=await route.fetch({url:process.env.E2E_API_URL+url.pathname+url.search});
      await route.fulfill({response});
    }catch{
      await route.abort().catch(()=>{});
    }
  });
}

async function loadDashboard(browser:Browser){
  const context=await browser.newContext();
  const page=await context.newPage();
  await prepare(page);
  const started=Date.now();
  await page.goto('/');
  await page.getByLabel('Work email').fill(process.env.E2E_EMAIL!);
  await page.getByLabel('Password',{exact:true}).fill(process.env.E2E_PASSWORD!);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Executive overview'})).toBeVisible({timeout:20000});
  await expect(page.getByRole('heading',{name:'Threat origin density'})).toBeVisible({timeout:20000});
  await expect(page.locator('.leaflet-container')).toBeVisible({timeout:20000});
  await page.waitForTimeout(150);
  const interactive_ms=Date.now()-started;
  const navigation=await page.evaluate(()=>{
    const entry=performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming|undefined;
    return {dom_content_loaded_ms:entry?Math.round(entry.domContentLoadedEventEnd):null,
      load_ms:entry?Math.round(entry.loadEventEnd):null,
      response_end_ms:entry?Math.round(entry.responseEnd):null};
  });
  return {context,page,interactive_ms,navigation};
}

test('dashboard interactive load under 2s and geo heatmap renders persisted evidence',async({browser})=>{
  // This spec needs the seeded executive account and geo evidence created by
  // scripts/nfr_ui_latency.py. The standard `npm run test:e2e` seed is an
  // analyst with no geo rows, so only run when that harness enables it.
  test.skip(!process.env.NFR_UI_RUN,'Run via scripts/nfr_ui_latency.py (seeds executive + geo evidence)');
  test.setTimeout(180000);
  const warm=await loadDashboard(browser); // warm-up compile/hydration
  await warm.context.close();
  const samples:Record<string,unknown>[]=[];
  let lastPage:Page|null=null;
  for(let i=0;i<3;i++){
    const run=await loadDashboard(browser);
    lastPage=run.page;
    samples.push({iteration:i+1,interactive_ms:run.interactive_ms,...run.navigation,under_2s:run.interactive_ms<2000});
    if(i<2)await run.context.close();
  }
  const map=lastPage!.locator('.leaflet-container');
  await expect(map).toBeVisible();
  const details=lastPage!.locator('details',{hasText:'Accessible geographic observations'});
  await details.locator('summary').click();
  const rows=details.locator('tbody tr');
  await expect(rows).toHaveCount(2,{timeout:10000});
  const table=await details.innerText();
  expect(table).toContain('US');
  expect(table).toContain('DE');
  expect(table).toContain('origin');
  expect(table).toContain('target');
  const rendered_rows=await rows.count();
  await lastPage!.context().close();
  const latencies=samples.map(row=>row.interactive_ms as number).sort((a,b)=>a-b);
  const p95=latencies[Math.min(latencies.length-1,Math.round(.95*(latencies.length-1)))];
  const result={run:RUN,target:{interactive_ms:2000,requirement:'NFR-01: dashboard interactive load < 2 s'},
    samples,p50_ms:latencies[1],max_ms:latencies[latencies.length-1],p95_ms:p95,
    all_under_2s:samples.every(row=>row.under_2s),
    geo:{origin_countries:['US'],target_countries:['DE'],rendered_rows},
    isolation:{api:process.env.E2E_API_URL,ui:process.env.UI_URL||'http://127.0.0.1:3100',
      database:'threatlens_test',external_basemap_blocked:true}};
  fs.mkdirSync(path.dirname(OUT),{recursive:true});
  fs.writeFileSync(OUT,JSON.stringify(result,null,2));
  expect(result.all_under_2s).toBeTruthy();
});
