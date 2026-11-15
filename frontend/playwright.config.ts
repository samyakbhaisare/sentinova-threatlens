import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',use:{baseURL:process.env.UI_URL||'http://localhost:3000',trace:'retain-on-failure',launchOptions:process.env.E2E_BROWSER_PATH?{executablePath:process.env.E2E_BROWSER_PATH}:{}},reporter:[['list'],['html',{open:'never'}]],timeout:30000});
