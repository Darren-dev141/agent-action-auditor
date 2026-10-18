'use strict';
// Real Chromium tests. Install playwright OUTSIDE this runtime/repo and set
// AAA_PLAYWRIGHT_PATH to its module directory. No user Chrome profile is touched.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {pathToFileURL} = require('node:url');
let chromium = null;
try { ({chromium} = require(process.env.AAA_PLAYWRIGHT_PATH || 'playwright')); } catch { /* optional dependency */ }
const CHROME = process.env.AAA_CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const skip = !chromium ? 'playwright not found (set AAA_PLAYWRIGHT_PATH)' : !fs.existsSync(CHROME) ? 'Chrome not found (set AAA_CHROME)' : false;
const base = path.resolve(__dirname,'..');
fs.mkdirSync(path.join(base,'qa'),{recursive:true});
const AAA = require('../rules.js');
const fixture = name => fs.readFileSync(path.join(base,'fixtures',`fixture_${name}.json`),'utf8');

for (const mode of ['file', 'http']) {
  test(`real Chrome ${mode}: audit parity, errors, privacy, XSS, copy and mobile`, {skip}, async () => {
    let server;
    if (mode === 'http') {
      server = http.createServer((req,res) => {
        const name = req.url === '/' ? 'index.html' : req.url.slice(1);
        const file = path.resolve(base,name);
        if (!file.startsWith(base + path.sep)) {res.writeHead(403);res.end();return;}
        const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml'};
        if (!fs.existsSync(file)) {res.writeHead(404);res.end();return;}
        res.setHeader('Content-Type',mime[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
      });
      await new Promise(r => server.listen(0,'127.0.0.1',r));
    }
    // GitLab CI runs as root in the Playwright image, where Chromium's sandbox
    // and the default /dev/shm size are unusable. Local runs keep the defaults.
    const launch = {executablePath:CHROME,headless:true};
    if (process.env.CI) launch.args = ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage'];
    const browser = await chromium.launch(launch);
    try {
      const context = await browser.newContext({viewport:{width:1440,height:1000}});
      // Clipboard is a browser permission boundary; capture it without changing engine behavior.
      await context.addInitScript(() => {
        window.__copied = null;
        Object.defineProperty(navigator,'clipboard',{value:{writeText:async text => {window.__copied=text;}}});
      });
      const page = await context.newPage();
      const requests=[], errors=[];
      page.on('request',r=>requests.push(r.url()));
      page.on('pageerror',e=>errors.push(e.message));
      const url = mode === 'file' ? pathToFileURL(path.join(base,'index.html')).href : `http://127.0.0.1:${server.address().port}/`;
      await page.goto(url);
      assert.equal(await page.title(),'Agent Action Auditor — Local trace review');
      await page.locator('#audit').click();
      assert.match(await page.locator('#error').innerText(),/Paste a trace/);
      await page.locator('#example').click();
      assert.ok((await page.locator('#trace').inputValue()).length > 0);
      await page.locator('#audit').click();
      assert.equal(await page.locator('#headline').innerText(),'CLEAN — no findings');
      const settledRequests=requests.length;
      for (const fx of ['clean','violation','borderline']) {
        const raw=fixture(fx);
        const expected=AAA.render_report(AAA.run_rules(AAA.parse_trace(raw)));
        await page.locator('#trace').fill(raw);
        await page.locator('#audit').click();
        assert.equal(await page.locator('#headline').innerText(),expected.headline);
        assert.equal(await page.locator('.finding').count(),fx==='violation'?6:fx==='borderline'?1:0);
        assert.equal(await page.locator('#secret-warning').isVisible(),fx==='violation');
      }
      await page.locator('#trace').fill(fixture('violation'));
      await page.locator('#audit').click();
      await page.locator('#copy').click();
      const copied=await page.evaluate(()=>window.__copied);
      assert.match(copied,/DO NOT DEPLOY/);
      assert.ok(copied.includes('\n'),'copied markdown must contain real newlines');
      assert.ok(!copied.includes('\\n'),'copied markdown must not contain literal backslash-n');
      assert.doesNotMatch(copied,/ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}/);
      assert.ok(await page.locator('.decision').count() === 6);
      await page.screenshot({path:path.join(base,'qa',`desktop-${mode}.png`),fullPage:true});
      await page.locator('#trace').fill('{not json');
      await page.locator('#audit').click();
      assert.match(await page.locator('#error').innerText(),/valid JSON/);
      assert.equal(await page.locator('#copy').isDisabled(),true);
      assert.equal(await page.locator('.finding').count(),0);
      await page.locator('#trace').fill(JSON.stringify({messages:[{role:'function',name:'read_file'}]}));
      await page.locator('#audit').click();
      assert.match(await page.locator('#error').innerText(),/unsupported role/);
      await page.locator('#trace').fill('x'.repeat(1048577));
      await page.locator('#audit').click();
      assert.match(await page.locator('#error').innerText(),/1 MiB/);
      // Trace-controlled tool and call id must stay text, with secrets masked even in ids.
      const token='ghp'+'_'+'A1b2'.repeat(9);
      const attack={messages:[{role:'assistant',tool_calls:[{id:'<img src="https://invalid.test/pixel" onerror="window.pwned=1">'+token,type:'function',function:{name:'send_<svg onload="window.pwned=2">',arguments:'{"to":"ops@example.com"}'}}]},{role:'tool',tool_call_id:'<img src="https://invalid.test/pixel" onerror="window.pwned=1">'+token,content:'ok'}]};
      await page.locator('#trace').fill(JSON.stringify(attack));
      await page.locator('#audit').click();
      assert.equal(await page.evaluate(()=>window.pwned),undefined);
      assert.equal(await page.locator('#findings img, #findings svg').count(),0);
      assert.doesNotMatch(await page.locator('#report').innerText(),/ghp_[A-Za-z0-9]{36}/);
      await page.locator('#clear').click();
      assert.equal(await page.locator('#trace').inputValue(),'');
      assert.equal(await page.locator('.finding').count(),0);
      assert.equal(await page.locator('#secret-warning').isVisible(),false);
      assert.equal(await page.locator('#copy').isDisabled(),true);
      assert.deepEqual(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length,cookie:document.cookie})),{local:0,session:0,cookie:''});
      assert.equal(requests.length,settledRequests,'audits must trigger no network requests');
      assert.deepEqual(errors,[]);
      assert.equal(await page.locator('#trace').getAttribute('wrap'),'soft');
      assert.equal(await page.locator('#copy').evaluate(e=>e.getBoundingClientRect().height>=44),true);
      await page.setViewportSize({width:320,height:780});
      await page.locator('#trace').fill(fixture('violation'));
      await page.locator('#audit').click();
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth),true,'no horizontal mobile overflow');
      await page.screenshot({path:path.join(base,'qa',`mobile-${mode}.png`),fullPage:true});
      assert.equal(await page.locator('#trace').getAttribute('aria-invalid'),'false');
      await page.locator('a[href="privacy.html"]').click();
      assert.match(await page.locator('h1').innerText(),/Privacy/);
      await page.goto(url.replace(/index\.html$/,'')+(mode==='http'?'404.html':'404.html'));
      assert.match(await page.locator('h1').innerText(),/Page not found/);
      fs.writeFileSync(path.join(base,'qa',`browser-${mode}.json`),JSON.stringify({mode,requests,errors,checks:'fixture parity/errors/size/privacy/XSS/copy/mobile/pages passed'},null,2));
    } finally {
      await browser.close();
      if (server) await new Promise(r=>server.close(r));
    }
  });
}
