const { chromium } = require('playwright-core');
const BBKEY = process.env.BROWSERBASE_API_KEY;
(async () => {
  const create = await fetch('https://api.browserbase.com/v1/sessions', {
    method: 'POST',
    headers: { 'x-bb-api-key': BBKEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ projectId: 'b538600c-870b-4322-bc9a-e41c2f390ab6' })
  }).then(r => r.json());
  const sessionId = create.id;
  console.log('session:', sessionId, create.status);

  const connect = await fetch(`https://api.browserbase.com/v1/sessions/${sessionId}`, {
    headers: { 'x-bb-api-key': BBKEY }
  }).then(r => r.json());
  const cdpUrl = connect.connectUrl;
  console.log('cdp:', cdpUrl.slice(0, 60) + '...');

  const browser = await chromium.connectOverCDP(cdpUrl);
  const context = browser.contexts()[0];
  const page = context.pages()[0] || await context.newPage();
  await page.goto('https://example.com', { timeout: 30000 });
  console.log('title:', await page.title());

  // DOM XSS probe: inject and check execution
  const result = await page.evaluate(() => {
    const canary = 'bbx' + Math.random().toString(36).slice(2, 8);
    const inp = document.querySelector('input');
    return { canary, url: location.href, forms: document.forms.length, inputs: document.querySelectorAll('input').length };
  });
  console.log('page eval OK:', JSON.stringify(result));

  await page.screenshot({ path: '/tmp/bb-shot.png' });
  console.log('screenshot saved');
  await browser.close();
})().catch(e => { console.error('ERR:', e.message); process.exit(1); });
