
const fs = require('fs');
const path = require('path');

// Mock browser globals for wasm_bindgen no-modules
global.window = global;
global.self = global;

require(path.resolve('docs/openedr_web.js'));

async function run() {
  const wasmBytes = fs.readFileSync('docs/openedr_web_bg.wasm');
  const wasm = await wasm_bindgen({ module_or_path: wasmBytes });

  function inspectUrl(url, livenessCode = 0) {
    const enc = new TextEncoder().encode(url);
    const p = wasm.web_alloc(enc.length);
    new Uint8Array(wasm.memory.buffer, p, enc.length).set(enc);
    const outPtr = wasm.web_inspect_url(p, enc.length, livenessCode);
    const outLen = wasm.web_output_len();
    const jsonStr = new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, outPtr, outLen));
    wasm.web_free(outPtr);
    return JSON.parse(jsonStr);
  }

  console.log('--- TEST 1: Blacklisted IPv4 (from CIDRBlackListIPv4: 223.109.211.213 in 223.109.211.212/30) ---');
  const bl4 = inspectUrl('http://223.109.211.213:8080/path');
  console.log('Verdict:', bl4.verdict, '| Score:', bl4.risk_score, '| Hits:', bl4.detections.map(d => d.rule_id));

  console.log('\n--- TEST 2: Whitelisted IPv4 (from CIDRWhiteListIPv4: 245.1.2.3 in 245.0.0.0/8) ---');
  const wl4 = inspectUrl('http://245.1.2.3/');
  console.log('Verdict:', wl4.verdict, '| Whitelisted:', wl4.whitelisted, '| Score:', wl4.risk_score);

  console.log('\n--- TEST 3: Blacklisted IPv6 (from CIDRBlackListIPv6: 2a14:c380:12::1 in 2a14:c380:12::/48) ---');
  const bl6 = inspectUrl('http://[2a14:c380:12::1]/exploit');
  console.log('Verdict:', bl6.verdict, '| Score:', bl6.risk_score, '| Hits:', bl6.detections.map(d => d.rule_id));

  console.log('\n--- TEST 4: Whitelisted IPv6 (from CIDRWhiteListIPv6: 2c0f:ffe0::5 in 2c0f:ffe0::/29) ---');
  const wl6 = inspectUrl('http://[2c0f:ffe0::5]/api');
  console.log('Verdict:', wl6.verdict, '| Whitelisted:', wl6.whitelisted, '| Score:', wl6.risk_score);

  console.log('\n--- TEST 5: Discord Webhook Abuse ---');
  const dsc = inspectUrl('https://discord.com/api/webhooks/123456789/token_abc');
  console.log('Verdict:', dsc.verdict, '| Score:', dsc.risk_score, '| Hits:', dsc.detections.map(d => d.rule_id));

  console.log('\n--- TEST 6: Telegram Bot API Abuse ---');
  const tg = inspectUrl('https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage');
  console.log('Verdict:', tg.verdict, '| Score:', tg.risk_score, '| Hits:', tg.detections.map(d => d.rule_id));
}

run().catch(console.error);
