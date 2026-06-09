import { spawn } from 'child_process';
import { performance } from 'perf_hooks';

async function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runEfficiencyTest() {
  console.log("🚀 Starting Server in Production Mode...");
  
  // Start the server from the compiled production dist path
  const server = spawn('node', ['dist/index.js'], {
    env: { ...process.env, NODE_ENV: 'production', PORT: '5123' },
    stdio: 'ignore' 
  });

  // Give the server time to spool up
  await wait(3000);

  console.log("\n⚡ Sending 500 concurrent requests to measure API and Server Efficiency...");
  const start = performance.now();
  const promises = [];
  
  // Sending 500 parallel requests to test load
  for(let i = 0; i < 500; i++) {
    // node v18+ native fetch
    promises.push(fetch('http://localhost:5123/').then(r => r.ok));
  }

  try {
    const results = await Promise.all(promises);
    const end = performance.now();
    const successfulRequests = results.filter(Boolean).length;
    
    const totalTimeMs = end - start;
    const avgTimeMs = totalTimeMs / 500;
    const reqPerSec = 500 / (totalTimeMs / 1000);

    console.log("\n✅ === EFFICIENCY TEST RESULTS ===");
    console.log(`Successfully handled: ${successfulRequests} / 500 requests`);
    console.log(`Total Time Taken:     ${totalTimeMs.toFixed(2)} ms`);
    console.log(`Average Latency:      ${avgTimeMs.toFixed(2)} ms per request`);
    console.log(`Throughput:           ${reqPerSec.toFixed(2)} requests per second (RPS)`);
    
    if (avgTimeMs < 10) {
      console.log("\n✨ CONCLUSION: Exceptional efficiency! Your front-end payload and server responses are extremely snappy.");
    } else if (avgTimeMs < 50) {
      console.log("\n👍 CONCLUSION: Good efficiency. The app can comfortably handle typical traffic loads.");
    } else {
      console.log("\n⚠️ CONCLUSION: The app is returning responses slowly under load. May need optimization or caching.");
    }

  } catch (err) {
    console.error("Test failed to complete. The server may have unexpectedly crashed under load.", err);
  } finally {
    console.log("\nClosing Server...");
    server.kill();
    process.exit(0);
  }
}

runEfficiencyTest();
