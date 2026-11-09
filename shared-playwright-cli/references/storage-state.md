# Storage Management

Manage cookies, localStorage, sessionStorage, and browser storage state.

## Storage State

Save and restore complete browser state including cookies and storage.

### Save Storage State

```bash
# Save to auto-generated filename (storage-state-{timestamp}.json)
shared-playwright-cli state-save

# Save to specific filename
shared-playwright-cli state-save my-auth-state.json
```

### Restore Storage State

```bash
# Load storage state from file
shared-playwright-cli state-load my-auth-state.json

# Reload page to apply cookies
shared-playwright-cli open https://example.com
```

### Storage State File Format

The saved file contains:

```json
{
  "cookies": [
    {
      "name": "session_id",
      "value": "abc123",
      "domain": "example.com",
      "path": "/",
      "expires": 1893456000,
      "httpOnly": true,
      "secure": true,
      "sameSite": "Lax"
    }
  ],
  "origins": [
    {
      "origin": "https://example.com",
      "localStorage": [
        { "name": "theme", "value": "dark" },
        { "name": "user_id", "value": "12345" }
      ]
    }
  ]
}
```

## Cookies

### List All Cookies

```bash
shared-playwright-cli cookie-list
```

### Filter Cookies by Domain

```bash
shared-playwright-cli cookie-list --domain=example.com
```

### Filter Cookies by Path

```bash
shared-playwright-cli cookie-list --path=/api
```

### Get Specific Cookie

```bash
shared-playwright-cli cookie-get session_id
```

### Set a Cookie

```bash
# Basic cookie
shared-playwright-cli cookie-set session abc123

# Cookie with options
shared-playwright-cli cookie-set session abc123 --domain=example.com --path=/ --httpOnly --secure --sameSite=Lax

# Cookie with expiration (Unix timestamp)
shared-playwright-cli cookie-set remember_me token123 --expires=1893456000
```

### Delete a Cookie

```bash
shared-playwright-cli cookie-delete session_id
```

### Clear All Cookies

```bash
shared-playwright-cli cookie-clear
```

### Advanced: Multiple Cookies or Custom Options

For complex scenarios like adding multiple cookies at once, use `run-code`:

```bash
shared-playwright-cli run-code "async page => {
  await page.context().addCookies([
    { name: 'session_id', value: 'sess_abc123', domain: 'example.com', path: '/', httpOnly: true },
    { name: 'preferences', value: JSON.stringify({ theme: 'dark' }), domain: 'example.com', path: '/' }
  ]);
}"
```

## Local Storage

### List All localStorage Items

```bash
shared-playwright-cli localstorage-list
```

### Get Single Value

```bash
shared-playwright-cli localstorage-get token
```

### Set Value

```bash
shared-playwright-cli localstorage-set theme dark
```

### Set JSON Value

```bash
shared-playwright-cli localstorage-set user_settings '{"theme":"dark","language":"en"}'
```

### Delete Single Item

```bash
shared-playwright-cli localstorage-delete token
```

### Clear All localStorage

```bash
shared-playwright-cli localstorage-clear
```

### Advanced: Multiple Operations

For complex scenarios like setting multiple values at once, use `run-code`:

```bash
shared-playwright-cli run-code "async page => {
  await page.evaluate(() => {
    localStorage.setItem('token', 'jwt_abc123');
    localStorage.setItem('user_id', '12345');
    localStorage.setItem('expires_at', Date.now() + 3600000);
  });
}"
```

## Session Storage

### List All sessionStorage Items

```bash
shared-playwright-cli sessionstorage-list
```

### Get Single Value

```bash
shared-playwright-cli sessionstorage-get form_data
```

### Set Value

```bash
shared-playwright-cli sessionstorage-set step 3
```

### Delete Single Item

```bash
shared-playwright-cli sessionstorage-delete step
```

### Clear sessionStorage

```bash
shared-playwright-cli sessionstorage-clear
```

## IndexedDB

### List Databases

```bash
shared-playwright-cli run-code "async page => {
  return await page.evaluate(async () => {
    const databases = await indexedDB.databases();
    return databases;
  });
}"
```

### Delete Database

```bash
shared-playwright-cli run-code "async page => {
  await page.evaluate(() => {
    indexedDB.deleteDatabase('myDatabase');
  });
}"
```

## Common Patterns

### Authentication State Reuse

```bash
# Step 1: Login and save state
shared-playwright-cli open https://app.example.com/login
shared-playwright-cli snapshot
shared-playwright-cli fill e1 "user@example.com"
shared-playwright-cli fill e2 "password123"
shared-playwright-cli click e3

# Save the authenticated state
shared-playwright-cli state-save auth.json

# Step 2: Later, restore state and skip login
shared-playwright-cli state-load auth.json
shared-playwright-cli open https://app.example.com/dashboard
# Already logged in!
```

### Save and Restore Roundtrip

```bash
# Set up authentication state
shared-playwright-cli open https://example.com
shared-playwright-cli eval "() => { document.cookie = 'session=abc123'; localStorage.setItem('user', 'john'); }"

# Save state to file
shared-playwright-cli state-save my-session.json

# ... later, in a new session ...

# Restore state
shared-playwright-cli state-load my-session.json
shared-playwright-cli open https://example.com
# Cookies and localStorage are restored!
```

## Security Notes

- Never commit storage state files containing auth tokens
- Add `*.auth-state.json` to `.gitignore`
- Delete state files after automation completes
- Use environment variables for sensitive data
- By default, sessions run in-memory mode which is safer for sensitive operations
