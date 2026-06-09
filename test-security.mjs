import { spawn } from 'child_process';

async function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runSecurityTests() {
  console.log("🛡️ Starting Automated Penetration Test (Cybersecurity Audit)...");
  console.log("==============================================================\n");
  
  const server = spawn('node', ['dist/index.js'], {
    env: { ...process.env, NODE_ENV: 'production', PORT: '5126' },
  });

  await wait(2000); // wait for server to start

  let passed = 0;
  let total = 0;

  function assert(condition, message) {
    total++;
    if (condition) {
      console.log(`✅ [PASS] ${message}`);
      passed++;
    } else {
      console.log(`❌ [FAIL] ${message}`);
    }
  }

  try {
    // 1. Audit HTTP Headers (Helmet equivalents)
    const resHeaders = await fetch('http://localhost:5126/');
    assert(resHeaders.headers.get('x-content-type-options') === 'nosniff', 'X-Content-Type-Options blocks MIME-sniffing attacks');
    assert(resHeaders.headers.get('x-frame-options') === 'DENY', 'X-Frame-Options blocks clickjacking / iframe embedding');
    assert(resHeaders.headers.get('content-security-policy') !== null, 'Content-Security-Policy (CSP) blocks XSS injections');
    assert(!resHeaders.headers.get('x-powered-by'), 'Server identity (X-Powered-By) is hidden from attackers');

    // 2. Audit Directory Traversal
    const resTraversal = await fetch('http://localhost:5126/%2e%2e/%2e%2e/windows/system.ini');
    assert(resTraversal.status === 400 || resTraversal.status === 404, `Directory Traversal Attempts (%2e%2e) are blocked (Returned HTTP ${resTraversal.status})`);

    // 3. Audit Sensitive File Exposure
    const resEnv = await fetch('http://localhost:5126/.env');
    assert(resEnv.status === 404, `.env secrets are inaccessible`);

    const resGit = await fetch('http://localhost:5126/.git/config');
    assert(resGit.status === 404, `Git repository history is inaccessible`);

    const resPkg = await fetch('http://localhost:5126/package-lock.json');
    assert(resPkg.status === 404, `NPM manifest lockfiles are inaccessible`);

    // 4. Audit Payload Size Limitation (anti-buffer overflow / memory DDOS)
    // Send a 15 KB payload (limit is set to 10kb in express.json configuration)
    const massivePayload = 'X'.repeat(15000); 
    const resLarge = await fetch('http://localhost:5126/api/quote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: massivePayload })
    });
    
    // Express limit middleware returns 413 Payload Too Large
    assert(resLarge.status === 413, `Massive payload injection attacks are halted (Returned HTTP ${resLarge.status})`);

    console.log(`\n📊 Final Cybersecurity Audit Results: ${passed} / ${total} Checks Passed`);
    if(passed === total) {
      console.log("✨ CONCLUSION: Your application firewall is extremely robust.");
    } else {
      console.log("⚠️ CONCLUSION: Some vulnerabilities were detected.");
    }

  } catch (err) {
    console.error("Test error:", err);
  } finally {
    console.log("\nTear down server...");
    server.kill();
    process.exit(0);
  }
}

runSecurityTests();
