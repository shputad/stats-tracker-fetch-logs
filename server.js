import express from 'express';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { Solver } from '@2captcha/captcha-solver';

const app = express();
const PORT = process.env.PORT || 8080;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

puppeteer.use(StealthPlugin());

app.use(express.json()); // Enable JSON body parsing

// Health Check Route
app.get('/', (req, res) => {
    res.send('Cloud Run service is up and running!');
});

// Fetch Logs Route (API key required)
app.post('/fetch-logs', async (req, res) => {
    const { url, api_key, link_type } = req.body;

    if (!url || !api_key || !link_type) {
        return res.status(400).json({ error: 'URL, API key and link_type are required' });
    }

    try {
        console.log(`[INFO] Fetching logs from ${url} for link type: ${link_type}`);

        // For "a" type, use captcha solving with Puppeteer
        if (link_type === 'a') {
            // Use the provided API key for 2Captcha
            const solver = new Solver(api_key);

            // Launch Puppeteer
            const browser = await puppeteer.launch({
                headless: 'new', // Use new headless mode
                executablePath: '/usr/bin/google-chrome-stable', // Use system-installed Chrome
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage', // Prevents shared memory crashes
                    '--disable-accelerated-2d-canvas',
                    '--disable-gpu',
                    '--disable-background-networking',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-breakpad',
                    '--disable-client-side-phishing-detection',
                    '--disable-default-apps',
                    '--disable-domain-reliability',
                    '--disable-extensions',
                    '--disable-hang-monitor',
                    '--disable-ipc-flooding-protection',
                    '--disable-popup-blocking',
                    '--disable-prompt-on-repost',
                    '--disable-renderer-backgrounding',
                    '--disable-speech-api',
                    '--disable-sync',
                    '--disk-cache-size=0', // Reduce memory usage by disabling cache
                    '--mute-audio',
                    '--no-first-run',
                    '--no-pings',
                    '--no-zygote',
                    '--single-process', // Ensures Puppeteer runs in a single process to use less memory
                    '--enable-automation'
                ],
            });

            console.log("[SUCCESS] Chromium started for a type.");

            const page = await browser.newPage();

            // Intercept the Turnstile CAPTCHA parameters
            await page.evaluateOnNewDocument(`
                console.clear = () => console.log('Console was cleared');
                const i = setInterval(() => {
                    if (window.turnstile) {
                        clearInterval(i);
                        window.turnstile.render = (a, b) => {
                            let params = {
                                sitekey: b.sitekey,
                                pageurl: window.location.href,
                                data: b.cData,
                                pagedata: b.chlPageData,
                                action: b.action,
                                userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                                json: 1
                            };
                            console.log('intercepted-params:' + JSON.stringify(params));
                            window.cfCallback = b.callback;
                            return;
                        };
                    }
                }, 50);
            `);

            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });

            const paramsPromise = new Promise((resolve, reject) => {
                let found = false;

                page.on('console', (msg) => {
                    const txt = msg.text();
                    if (txt.includes('intercepted-params:')) {
                        found = true;
                        resolve(JSON.parse(txt.replace('intercepted-params:', '')));
                    }
                });

                setTimeout(() => {
                    if (!found) reject(new Error('Timeout waiting for CAPTCHA parameters.'));
                }, 15000);
            });

            const params = await paramsPromise;
            console.log(`[INFO] Extracted CAPTCHA Parameters:`, params);

            const solvedCaptcha = await solver.cloudflareTurnstile(params);
            console.log(`[SUCCESS] Captcha Solved:`, solvedCaptcha);

            await page.evaluate((token) => {
                cfCallback(token);
            }, solvedCaptcha.data);

            await page.waitForNavigation({ waitUntil: 'networkidle2' });
            await page.waitForSelector('.font-weight-medium', { timeout: 20000 });

            const content = await page.content();
            const regex = /(\d+)\s*логов/;
            const match = content.match(regex);
            const logsCount = match ? parseInt(match[1], 10) : null;

            await browser.close();
            return res.json({ success: true, logsCount });
        } else if (link_type === 'b') {
            // Launch Puppeteer with simpler settings
            const browser = await puppeteer.launch({
                headless: 'new',
                executablePath: '/usr/bin/google-chrome-stable',
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage'
                ],
            });
        
            console.log("[SUCCESS] Chromium started for b type.");
        
            const page = await browser.newPage();
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
            await page.waitForSelector('#all', { timeout: 20000 });
            
            // Wait until the #all element's innerText is not empty
            await page.waitForFunction(() => {
                const el = document.querySelector('#all');
                return el && el.innerText.trim().length > 0;
            }, { timeout: 20000 });
            
            // Extract and log the raw text
            const rawText = await page.$eval('#all', el => el.innerText.trim());
            console.log(`[DEBUG] Raw text from #all: "${rawText}"`);
            
            const logsCount = parseInt(rawText, 10);
            await browser.close();
            return res.json({ success: true, logsCount });
        } else if (link_type === 'c') {
            // Launch Puppeteer with simpler settings
            const browser = await puppeteer.launch({
                headless: 'new',
                executablePath: '/usr/bin/google-chrome-stable',
                ignoreHTTPSErrors: true,
                args: [
                    '--ignore-certificate-errors',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage'
                ],
            });
            
            console.log("[SUCCESS] Chromium started for c type.");
            
            const page = await browser.newPage();
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });

            // Wait for the tabs to load
            await page.waitForSelector('div.ant-tabs-tab', { timeout: 20000 });
            
            // Click the "Detail stats" tab using evaluate
            await page.evaluate(() => {
                const tabs = Array.from(document.querySelectorAll('div.ant-tabs-tab'));
                const detailTab = tabs.find(tab => tab.textContent.trim() === 'Detail stats');
                if (detailTab) {
                    console.log("Clicking Detail stats tab via evaluate...");
                    detailTab.click();
                }
            });
            
            // Wait until the active tab is "Detail stats"
            await page.waitForFunction(() => {
                const activeTab = document.querySelector('div.ant-tabs-tab-active');
                return activeTab && activeTab.textContent.trim() === 'Detail stats';
            }, { timeout: 10000 });
            
            console.log("[INFO] Detail stats tab is now active.");
            
            // Wait for a few seconds to allow the stats to update
            await new Promise(resolve => setTimeout(resolve, 3000));

            // Wait for the statistics elements to load
            await page.waitForSelector('div.ant-statistic-title', { timeout: 20000 });
            
            // Extract the Total count using DOM evaluation
            const logsCount = await page.evaluate(() => {
                const titles = Array.from(document.querySelectorAll('div.ant-statistic-title'));
                let totalCount = null;
                titles.forEach(title => {
                    if (title.textContent.trim() === 'Total') {
                        const container = title.closest('div.ant-statistic');
                        if (container) {
                            const valueSpan = container.querySelector('span.ant-statistic-content-value-int');
                            if (valueSpan) {
                                totalCount = parseInt(valueSpan.innerText.trim(), 10);
                            }
                        }
                    }
                });
                return totalCount;
            });
            
            console.log(`[DEBUG] Total logs count for c: ${logsCount}`);
            await browser.close();
            return res.json({ success: true, logsCount });
        } else if (link_type === 'd') {
            const browser = await puppeteer.launch({
                headless: 'new',
                executablePath: '/usr/bin/google-chrome-stable',
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                ],
            });
        
            console.log("[SUCCESS] Chromium started for d type.");
        
            const page = await browser.newPage();
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
        
            // Wait for logs to actually load (i.e., not '?')
            await page.waitForFunction(() => {
                const el = document.querySelector('h6#logs_count');
                return el && el.innerText.trim() !== '?' && !isNaN(el.innerText.trim());
            }, { timeout: 20000 });
        
            const rawText = await page.$eval('h6#logs_count', el => el.innerText.trim());
            console.log(`[DEBUG] D logs text: "${rawText}"`);
        
            const logsCount = parseInt(rawText, 10);
        
            await browser.close();
            return res.json({ success: true, logsCount });
        }
    } catch (error) {
        console.error(`[ERROR]`, error.message);
        return res.status(500).json({ error: error.message });
    }
});

// Start Server & Log It
app.listen(PORT, () => {
    console.log(`[SUCCESS] Server is running on port ${PORT}`);
});
