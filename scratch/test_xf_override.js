
const fs = require('fs');
const path = require('path');

global.window = global;
global.self = global;

require(path.resolve('docs/openedr_web.js'));

async function testWithWhitelist() {
  const wasmBytes = fs.readFileSync('docs/openedr_web_bg.wasm');
  const wasm = await wasm_bindgen({ module_or_path: wasmBytes });

  // Load url_whitelist.xf
  const xfBytes = fs.readFileSync('docs/models/url_whitelist.xf');
  const pXf = wasm.web_alloc(xfBytes.length);
  new Uint8Array(wasm.memory.buffer, pXf, xfBytes.length).set(xfBytes);
  const okXf = wasm.web_load_url_whitelist(pXf, xfBytes.length);
  wasm.web_free(pXf, xfBytes.length);
  console.log('BinaryFuse16 Whitelist loaded:', okXf === 1 ? 'PASS' : 'FAIL');

  function inspect(url, livenessCode = 0) {
    const enc = new TextEncoder().encode(url);
    const p = wasm.web_alloc(enc.length);
    new Uint8Array(wasm.memory.buffer, p, enc.length).set(enc);
    const outPtr = wasm.web_inspect_url(p, enc.length, livenessCode);
    const outLen = wasm.web_output_len();
    const rep = JSON.parse(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, outPtr, outLen)));
    wasm.web_free(outPtr);
    return rep;
  }

  const normalDiscord = inspect('https://discord.com/login');
  console.log('Normal Discord (discord.com/login):', normalDiscord.verdict, '| Whitelisted:', normalDiscord.whitelisted);

  const dsc = inspect('https://discord.com/api/webhooks/12345/webhook_token');
  console.log('Discord Webhook Abuse:', dsc.verdict, '| Whitelisted:', dsc.whitelisted, '| Bypassed:', dsc.whitelist_bypassed, '| Bypass reason:', dsc.bypass_reason);

  const tg = inspect('https://api.telegram.org/bot12345:TOKEN/sendMessage');
  console.log('Telegram Bot API Abuse:', tg.verdict, '| Whitelisted:', tg.whitelisted, '| Bypassed:', tg.whitelist_bypassed, '| Bypass reason:', tg.bypass_reason);
}

testWithWhitelist().catch(console.error);
