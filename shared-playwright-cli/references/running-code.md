# Running Custom Playwright Code

Use `run-code` to execute arbitrary Playwright code for advanced scenarios not covered by CLI commands.

## Syntax

```bash
shared-playwright-cli run-code "async page => {
  // Your Playwright code here
  // Access page.context() for browser context operations
}"
```

You can also load the function from a file:

```bash
shared-playwright-cli run-code --filename=./my-script.js
```


The code must be a single function expression, it is wrapped in `(...)` and evaluated.
import/export/require syntax is not supported.

The code runs in an isolated context, not in a full Node.js environment. `require`, `process` and Node modules are not
available. Timers (`setTimeout`, `setInterval`), `fetch`, `URL`, `Buffer`, `crypto`, `AbortController`, `TextEncoder`
and `TextDecoder` are available.

## Geolocation

```bash
# Grant geolocation permission and set location
shared-playwright-cli run-code "async page => {
  await page.context().grantPermissions(['geolocation']);
  await page.context().setGeolocation({ latitude: 37.7749, longitude: -122.4194 });
}"

# Set location to London
shared-playwright-cli run-code "async page => {
  await page.context().grantPermissions(['geolocation']);
  await page.context().setGeolocation({ latitude: 51.5074, longitude: -0.1278 });
}"

# Clear geolocation override
shared-playwright-cli run-code "async page => {
  await page.context().clearPermissions();
}"
```

## Permissions

```bash
# Grant multiple permissions
shared-playwright-cli run-code "async page => {
  await page.context().grantPermissions([
    'geolocation',
    'notifications',
    'camera',
    'microphone'
  ]);
}"

# Grant permissions for specific origin
shared-playwright-cli run-code "async page => {
  await page.context().grantPermissions(['clipboard-read'], {
    origin: 'https://example.com'
  });
}"
```

## Media Emulation

```bash
# Emulate dark color scheme
shared-playwright-cli run-code "async page => {
  await page.emulateMedia({ colorScheme: 'dark' });
}"

# Emulate light color scheme
shared-playwright-cli run-code "async page => {
  await page.emulateMedia({ colorScheme: 'light' });
}"

# Emulate reduced motion
shared-playwright-cli run-code "async page => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
}"

# Emulate print media
shared-playwright-cli run-code "async page => {
  await page.emulateMedia({ media: 'print' });
}"
```

## Wait Strategies

```bash
# Wait for network idle
shared-playwright-cli run-code "async page => {
  await page.waitForLoadState('networkidle');
}"

# Wait for specific element
shared-playwright-cli run-code "async page => {
  await page.locator('.loading').waitFor({ state: 'hidden' });
}"

# Wait for function to return true
shared-playwright-cli run-code "async page => {
  await page.waitForFunction(() => window.appReady === true);
}"

# Wait with timeout
shared-playwright-cli run-code "async page => {
  await page.locator('.result').waitFor({ timeout: 10000 });
}"
```

## Frames and Iframes

```bash
# Work with iframe
shared-playwright-cli run-code "async page => {
  const frame = page.locator('iframe#my-iframe').contentFrame();
  await frame.locator('button').click();
}"

# Get all frames
shared-playwright-cli run-code "async page => {
  const frames = page.frames();
  return frames.map(f => f.url());
}"
```

## File Downloads

```bash
# Handle file download
shared-playwright-cli run-code "async page => {
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download' }).click();
  const download = await downloadPromise;
  await download.saveAs('./downloaded-file.pdf');
  return download.suggestedFilename();
}"
```

## Clipboard

```bash
# Read clipboard (requires permission)
shared-playwright-cli run-code "async page => {
  await page.context().grantPermissions(['clipboard-read']);
  return await page.evaluate(() => navigator.clipboard.readText());
}"

# Write to clipboard
shared-playwright-cli run-code "async page => {
  await page.evaluate(text => navigator.clipboard.writeText(text), 'Hello clipboard!');
}"
```

## Page Information

```bash
# Get page title
shared-playwright-cli run-code "async page => {
  return await page.title();
}"

# Get current URL
shared-playwright-cli run-code "async page => {
  return page.url();
}"

# Get page content
shared-playwright-cli run-code "async page => {
  return await page.content();
}"

# Get viewport size
shared-playwright-cli run-code "async page => {
  return page.viewportSize();
}"
```

## JavaScript Execution

```bash
# Execute JavaScript and return result
shared-playwright-cli run-code "async page => {
  return await page.evaluate(() => {
    return {
      userAgent: navigator.userAgent,
      language: navigator.language,
      cookiesEnabled: navigator.cookieEnabled
    };
  });
}"

# Pass arguments to evaluate
shared-playwright-cli run-code "async page => {
  const multiplier = 5;
  return await page.evaluate(m => document.querySelectorAll('li').length * m, multiplier);
}"
```

## Error Handling

```bash
# Try-catch in run-code
shared-playwright-cli run-code "async page => {
  try {
    await page.getByRole('button', { name: 'Submit' }).click({ timeout: 1000 });
    return 'clicked';
  } catch (e) {
    return 'element not found';
  }
}"
```

## Complex Workflows

```bash
# Login and save state
shared-playwright-cli run-code "async page => {
  await page.goto('https://example.com/login');
  await page.getByRole('textbox', { name: 'Email' }).fill('user@example.com');
  await page.getByRole('textbox', { name: 'Password' }).fill('secret');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForURL('**/dashboard');
  await page.context().storageState({ path: 'auth.json' });
  return 'Login successful';
}"

# Scrape data from multiple pages
shared-playwright-cli run-code "async page => {
  const results = [];
  for (let i = 1; i <= 3; i++) {
    await page.goto(\`https://example.com/page/\${i}\`);
    const items = await page.locator('.item').allTextContents();
    results.push(...items);
  }
  return results;
}"
```
