import {defineConfig} from '@playwright/test';

const run=process.env.VERIFICATION_RUN || new Date().toISOString().replace(/[:.]/g,'-');

export default defineConfig({
  testDir:'./e2e',
  testMatch:['offline.spec.ts','operations.spec.ts'],
  outputDir:`../artifacts/browser-${run}`,
  reporter:[['list'],['html',{outputFolder:`../artifacts/browser-report-${run}`,open:'never'}]],
  timeout:30000,
  use:{baseURL:'http://127.0.0.1:3100',trace:'retain-on-failure',launchOptions:process.env.E2E_BROWSER_PATH?{executablePath:process.env.E2E_BROWSER_PATH}:{}},
  webServer:{command:'npm run start -- --hostname 127.0.0.1 --port 3100',url:'http://127.0.0.1:3100',reuseExistingServer:false,timeout:30000},
});
