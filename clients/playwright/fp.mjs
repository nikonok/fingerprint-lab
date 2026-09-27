// Visits the endpoint with each Playwright browser engine, headless and
// headed, and prints the returned record.
//
//   node fp.mjs https://localhost:8443/ [chromium|firefox|webkit ...]
import { chromium, firefox, webkit } from "playwright";

const engines = { chromium, firefox, webkit };
const [url = "https://localhost:8443/", ...names] = process.argv.slice(2);
const selected = names.length ? names : ["chromium"];

for (const name of selected) {
  for (const headless of [true, false]) {
    const label = `playwright-${name}-${headless ? "headless" : "headed"}`;
    const browser = await engines[name].launch({ headless });
    try {
      const page = await browser.newPage({ ignoreHTTPSErrors: true });
      await page.goto(`${url}?label=${label}`);
      console.log(label, (await page.textContent("body")).slice(0, 200));
    } finally {
      await browser.close();
    }
  }
}
