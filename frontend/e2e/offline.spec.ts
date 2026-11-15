import {test,expect} from '@playwright/test';

test('offline login surface supports keyboard and laptop/mobile layouts',async({page},testInfo)=>{
 await page.goto('/');
 await expect(page.getByRole('heading',{name:'Sign in to ThreatLens'})).toBeVisible({timeout:20000});
 const email=page.getByLabel('Work email');
 await email.focus();
 await expect(email).toBeFocused();
 await page.keyboard.press('Tab');
 await expect(page.getByLabel('Password',{exact:true})).toBeFocused();
 for(const size of [{width:1366,height:768},{width:390,height:844}]){
  await page.setViewportSize(size);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeVisible();
 }
 await page.screenshot({path:testInfo.outputPath('login-mobile.png'),fullPage:true});
 await page.setViewportSize({width:1366,height:768});
 await page.screenshot({path:testInfo.outputPath('login-laptop.png'),fullPage:true});
});
