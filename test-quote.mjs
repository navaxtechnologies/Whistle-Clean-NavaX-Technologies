import { spawn } from 'child_process';

async function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function testQuote() {
  console.log("🚀 Starting Production Server...");
  const server = spawn('node', ['dist/index.js'], {
    env: { ...process.env, NODE_ENV: 'production', PORT: '5125' },
    stdio: 'pipe'
  });

  // Pipe server logs so we can see the console.log output from the endpoint
  server.stdout.on('data', (data) => process.stdout.write(`[SERVER]: ${data}`));
  server.stderr.on('data', (data) => process.stderr.write(`[SERVER ERROR]: ${data}`));

  await wait(2000);

  console.log("\n✉️ Sending mock quote request to /api/quote...");
  
  const payload = {
    name: "John Doe (Automated Test)",
    email: "johndoe@example.com",
    phone: "(210) 555-9999",
    service: "residential",
    date: "2026-05-01",
    message: "This is an automated test quote to verify the contact form endpoint is functioning!"
  };

  try {
    const response = await fetch('http://localhost:5125/api/quote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    console.log("\n✅ HTTP Status:", response.status);
    console.log("✅ Server Response JSON:", data);
  } catch (err) {
    console.error("Test connection failed:", err);
  } finally {
    console.log("\nClosing Server...");
    server.kill();
    process.exit(0);
  }
}

testQuote();
