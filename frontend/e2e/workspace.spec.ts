import {test,expect} from '@playwright/test';

test.beforeEach(async({page})=>{
 if(process.env.E2E_API_URL)await page.route('**/api/v1/**',async route=>{
  const url=new URL(route.request().url());
  try{
   const response=await route.fetch({url:process.env.E2E_API_URL+url.pathname+url.search});
   await route.fulfill({response});
  }catch{
   // A request still in flight when a test finishes must not fail the test.
   await route.abort().catch(()=>{});
  }
 });
});

test('login is accessible, responsive, and reports invalid credentials',async({page})=>{
 await page.goto('/');
 await expect(page.getByRole('heading',{name:'Sign in to ThreatLens'})).toBeVisible();
 await page.getByLabel('Work email').fill('invalid@example.org');
 await page.getByLabel('Password',{exact:true}).fill('invalid-controlled-password');
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.locator('.login-card [role="alert"]')).toContainText('Invalid credentials');
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
});

test('empty queues show honest empty states against the real isolated API',async({page})=>{
 test.skip(!process.env.E2E_EMPTY_EMAIL||!process.env.E2E_EMPTY_PASSWORD,'Requires empty controlled-test account');
 await page.goto('/');
 await page.getByLabel('Work email').fill(process.env.E2E_EMPTY_EMAIL!);
 await page.getByLabel('Password',{exact:true}).fill(process.env.E2E_EMPTY_PASSWORD!);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('heading',{name:'SOC triage'})).toBeVisible();
 await expect(page.getByText('No routed alerts. Configure rules and ingest matching internal events to create evidence-backed alerts.')).toBeVisible();
 await page.getByRole('button',{name:/^Notifications/}).click();
 await expect(page.getByText('No notifications routed to your account.')).toBeVisible();
 await page.getByRole('button',{name:'Threat hunting',exact:true}).click();
 await expect(page.getByText('Save a query to make your investigation reusable.')).toBeVisible();
 await page.screenshot({path:'test-results/controlled-empty-state.png',fullPage:true});
});

test('authorized analyst can triage, enrich and escalate in four clicks',async({page})=>{
 test.skip(!process.env.E2E_EMAIL||!process.env.E2E_PASSWORD,'Requires isolated controlled-test account and routed alert fixture');
 await page.goto('/');
 await page.getByLabel('Work email').fill(process.env.E2E_EMAIL!);
 await page.getByLabel('Password',{exact:true}).fill(process.env.E2E_PASSWORD!);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('heading',{name:'SOC triage'})).toBeVisible();
 const row=page.locator('tbody tr').first();
 await row.getByRole('button',{name:'Acknowledge',exact:true}).click();
 await row.locator('td').nth(1).getByRole('button').click();
 const drawer=page.getByRole('dialog');
 await drawer.getByRole('button',{name:'Enrich',exact:true}).click();
 await drawer.getByRole('button',{name:'Escalate to incident'}).click();
 await expect(page.getByRole('status')).toContainText('Incident opened');
 await page.screenshot({path:'test-results/controlled-triage.png',fullPage:true});
});
