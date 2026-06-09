import fs from 'fs';
import { spawn } from 'child_process';
import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';

async function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runLighthouse() {
  console.log("🚀 Starting Server for Lighthouse Audit...");
  const server = spawn('node', ['dist/index.js'], {
    env: { ...process.env, NODE_ENV: 'production', PORT: '5124' },
    stdio: 'ignore'
  });

  // wait for build to be accessible
  await wait(3000);

  console.log("🌟 Launching Headless Chrome...");
  const chrome = await chromeLauncher.launch({chromeFlags: ['--headless']});
  
  const options = {
    logLevel: 'info',
    output: 'html',
    onlyCategories: ['performance', 'accessibility', 'best-practices', 'seo'],
    port: chrome.port,
  };

  console.log("📊 Running Lighthouse Audit on http://localhost:5124...");
  
  // Note: lighthouse is imported as a CJS / ESM module so this will execute the audit
  const runnerResult = await lighthouse('http://localhost:5124', options);

  // Print results summary
  console.log("\n✅ === LIGHTHOUSE AUDIT RESULTS ===");
  if(runnerResult && runnerResult.lhr && runnerResult.lhr.categories) {
    const cats = runnerResult.lhr.categories;
    console.log(`Performance:    ${Math.round(cats.performance.score * 100)} / 100`);
    console.log(`Accessibility:  ${Math.round(cats.accessibility.score * 100)} / 100`);
    console.log(`Best Practices: ${Math.round(cats['best-practices'].score * 100)} / 100`);
    console.log(`SEO:            ${Math.round(cats.seo.score * 100)} / 100`);
    
    // Additional quick summary
    const overall = (cats.performance.score + cats.accessibility.score + cats['best-practices'].score + cats.seo.score) / 4 * 100;
    console.log(`\nOverall Score:  ${overall.toFixed(1)} / 100`);
    if(overall >= 90) console.log("✨ Excellent Web Efficiency & Health!");
    else if(overall >= 80) console.log("👍 Good, but has room for minor optimization.");
    else console.log("⚠️ Needs architectural improvement.");
  }

  // Handle report html
  const reportHtml = runnerResult.report;
  fs.writeFileSync('lighthouse-report.html', reportHtml);
  console.log("\n📁 Full HTML Report securely saved to: lighthouse-report.html");

  await chrome.kill();
  console.log("Closing Server...");
  server.kill();
  process.exit(0);
}

runLighthouse().catch(err => {
  console.error("Lighthouse failed:", err);
  process.exit(1);
});
