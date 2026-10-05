// Reads a PRIVATE manifest; never commit credentials or a browser storage state.
// node capture.mjs /private/capture-config.json
import {readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const config = JSON.parse(readFileSync(process.argv[2],'utf8'));
const credentials = JSON.parse(readFileSync(config.credentialsFile,'utf8'));
const base = new URL(credentials.url);
const out = dirname(fileURLToPath(import.meta.url));
const browser = await chromium.launch({headless:true});
try {
 const context = await browser.newContext({viewport:{width:1280,height:900},deviceScaleFactor:1,httpCredentials:{username:credentials.username,password:credentials.password,origin:base.origin}});
 const page = await context.newPage();
 const errors=[]; page.on('pageerror',e=>errors.push(e.message));
 const gallery=['# GUI screenshots','','Captured from disposable Oracle 23ai and 26ai testbeds. Hostnames, addresses and local paths are masked in the browser before capture; underlying case data is unchanged. Frames show the first viewport, not the entire scrollable page.','','[Bootstrap guide](../gui-bootstrap.md) · [Animated tour](tour.webp)','','| Page | Screenshot |','|---|---|'];
 for (const [i,frame] of config.pages.entries()) {
  const url = new URL(frame.path,base);
  if (url.origin !== base.origin) throw new Error('Cross-origin capture forbidden');
  const response=await page.goto(url.href,{waitUntil:'networkidle',timeout:120000});
  if (!response?.ok()) throw new Error(`Page ${frame.name}: HTTP ${response?.status()}`);
  if (frame.waitFor) await page.locator(frame.waitFor).first().waitFor();
  await page.evaluate(({password,replacements})=>{
   const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
   while(walker.nextNode()) {
    let text=walker.currentNode.nodeValue;
    if (password && text.includes(password)) throw new Error('Credential appeared in page');
    for(const [from,to] of replacements) text=text.split(from).join(to);
    // Do not mistake five-part Oracle versions (23.9.0.25.07) for IPv4.
    text=text.replace(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g,'[address]');
    walker.currentNode.nodeValue=text;
   }
  },{password:credentials.password,replacements:config.replacements||[]});
  const filename=String(i+1).padStart(2,'0')+'-'+frame.name+'.png';
  await page.screenshot({path:join(out,filename),animations:'disabled'});
  gallery.push(`| ${frame.caption} | [${filename}](${filename}) |`);
  console.log(filename);
 }
 if(errors.length) throw new Error('Browser errors: '+errors.join('; '));
 gallery.push('','Raw file/Markdown downloads, JSON endpoints and the `/` redirect are not separate GUI screens. API documentation is included. POST actions return to the case or report pages shown here.','','## Regenerate','','Install Playwright in your development environment and Chromium (`npx playwright install chromium`), plus `npm install -g sharp-cli`. Keep the capture configuration and login file outside the repository.','','The capture configuration has `credentialsFile` (JSON with `url`, `username`, `password`), `pages` (ordered `{name, caption, path, waitFor?}` objects using your current case/artifact/report IDs), and optional `replacements` (literal `[from, to]` pairs). Use only disposable test data.','','```bash','node docs/screenshots/capture.mjs /private/capture-config.json','node docs/screenshots/build-tour.mjs','```','','Inspect every PNG for sensitive data before committing. The builder verifies frame dimensions, animation count, 3.5-second delays, infinite looping and a 5 MiB size budget. The tour follows the imported `repo-carousel` skill; static frames are the non-animated alternative.','');
 writeFileSync(join(out,'README.md'),gallery.join('\n'));
} finally { await browser.close(); }
