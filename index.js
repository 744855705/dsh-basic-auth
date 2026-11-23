/**
 * Username and password sign-in for the DSH Web UI.
 *
 * Host-only, zero-dependency bundle built on the 0.2.3 authentication seam:
 * a cookie verifier on `connection.authentication` and a root-page
 * interception through the `webserver/request` waterfall. Token links and QR
 * sign-in keep their original behavior because this plugin only claims the
 * unauthenticated GET/HEAD root page and never registers the `/` route.
 */
import { createHash, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto'
import { isIPv4, isIPv6 } from 'node:net'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback)

/** Stable plugin name. */
export const name = 'basic-auth'

/** Host services this bundle consumes. */
export const inject = ['connection', 'connection.authentication', 'credentials', 'webServer', 'webApp']

const ACCOUNT_KEY = 'basic-auth/account'
const SESSION_KEY = 'basic-auth/session'
const LOGIN_PATH = '/__basic-auth/login'
const SETUP_PATH = '/__basic-auth/setup'
const LOGOUT_PATH = '/__basic-auth/logout'

const COOKIE_VERSION = 1
const PAYLOAD_VERSION = 1
const RECORD_VERSION = 1
const SECRET_BYTES = 32
const SALT_BYTES = 16
const SETUP_TOKEN_BYTES = 24
const HASH_BYTES = 32

const DAY_MS = 86_400_000
const MAX_DATE_MS = 8_640_000_000_000_000
const MAX_LOCKOUT_MS = 15 * 60_000
const BODY_LIMIT_BYTES = 4 * 1024
const PASSWORD_MIN_LENGTH = 8
const PASSWORD_MAX_LENGTH = 1024
const USERNAME_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/
const SCRYPT_OPTIONS = Object.freeze({ N: 16_384, r: 8, p: 1, maxmem: 67_108_864 })

const PAGE_HEADERS = Object.freeze({
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
})

const DEFAULTS = Object.freeze({
  cookieMaxAgeDays: 180,
  pageTitle: 'DeepSeek Harness',
  maxFailures: 5,
  lockoutMs: 60_000,
})

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/**
 * Validate the row configuration without a schema dependency.
 * @param {unknown} input - row `config` object, possibly absent.
 * @returns {{ cookieMaxAgeDays: number, pageTitle: string, maxFailures: number, lockoutMs: number }}
 */
function normalizeConfig(input) {
  if (input === undefined || input === null) input = {}
  if (!isRecord(input)) throw new Error('[basic-auth] 配置必须是一个对象。')
  const cookieMaxAgeDays = integerOption(input.cookieMaxAgeDays, DEFAULTS.cookieMaxAgeDays, 1, Number.MAX_SAFE_INTEGER, 'cookieMaxAgeDays')
  const lifetimeMs = cookieMaxAgeDays * DAY_MS
  if (!Number.isSafeInteger(lifetimeMs) || Date.now() + lifetimeMs > MAX_DATE_MS) {
    throw new Error('[basic-auth] cookieMaxAgeDays 超出可支持的时间戳范围。')
  }
  return {
    cookieMaxAgeDays,
    pageTitle: titleOption(input.pageTitle),
    maxFailures: integerOption(input.maxFailures, DEFAULTS.maxFailures, 1, 1000, 'maxFailures'),
    lockoutMs: integerOption(input.lockoutMs, DEFAULTS.lockoutMs, 1, MAX_LOCKOUT_MS, 'lockoutMs'),
  }
}

function integerOption(value, fallback, min, max, field) {
  if (value === undefined) return fallback
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`[basic-auth] 配置项 ${field} 必须是 ${min}–${max} 之间的整数。`)
  }
  return value
}

function titleOption(value) {
  if (value === undefined) return DEFAULTS.pageTitle
  if (typeof value !== 'string') throw new Error('[basic-auth] 配置项 pageTitle 必须是字符串。')
  const title = value.trim()
  if (title.length === 0 || title.length > 120) throw new Error('[basic-auth] 配置项 pageTitle 长度必须是 1–120 个字符。')
  return title
}

/* ------------------------------------------------------------------ */
/* Credential records                                                  */
/* ------------------------------------------------------------------ */

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Canonical unpadded base64url text. */
function encodeBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

/** Decode only canonical, nonempty base64url text. */
function decodeBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) return undefined
  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  const bytes = Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + padding, 'base64')
  return encodeBase64Url(bytes) === value ? bytes : undefined
}

function corruptSecret() {
  return new Error('[basic-auth] 凭据记录 basic-auth/session 格式无效。请删除该记录并重启 DSH；插件会生成新的签名密钥，已签发的 cookie 将全部失效。')
}

function parseSecret(record) {
  if (record === undefined) return undefined
  if (!isRecord(record) || record.kind !== 'grant' || !isRecord(record.payload)
    || Object.keys(record.payload).length !== 2
    || record.payload.version !== RECORD_VERSION
    || typeof record.payload.secret !== 'string') throw corruptSecret()
  const secret = decodeBase64Url(record.payload.secret)
  if (secret === undefined || secret.byteLength !== SECRET_BYTES) throw corruptSecret()
  return secret
}

async function loadSecret(credentials) {
  const stored = await credentials.modifyRecord(SESSION_KEY, (current) => {
    if (current !== undefined) return undefined
    return { kind: 'grant', payload: { version: RECORD_VERSION, secret: encodeBase64Url(randomBytes(SECRET_BYTES)) } }
  })
  const secret = parseSecret(stored)
  if (secret === undefined) {
    throw new Error('[basic-auth] 无法保存凭据记录 basic-auth/session；请确认凭据存储可写后重启 DSH。')
  }
  return secret
}

function corruptAccount() {
  return new Error('[basic-auth] 凭据记录 basic-auth/account 格式无效。请删除该记录并重启 DSH，然后重新完成首次设置。')
}

function parseAccount(record) {
  if (record === undefined) return undefined
  if (!isRecord(record) || record.kind !== 'grant' || !isRecord(record.payload)
    || Object.keys(record.payload).length !== 4
    || record.payload.version !== RECORD_VERSION
    || typeof record.payload.username !== 'string'
    || typeof record.payload.salt !== 'string'
    || typeof record.payload.hash !== 'string') throw corruptAccount()
  if (!USERNAME_PATTERN.test(record.payload.username)) throw corruptAccount()
  const salt = decodeBase64Url(record.payload.salt)
  const hash = decodeBase64Url(record.payload.hash)
  if (salt === undefined || salt.byteLength < 8 || hash === undefined || hash.byteLength !== HASH_BYTES) throw corruptAccount()
  return { username: record.payload.username, salt, hash }
}

async function readAccount(credentials) {
  return parseAccount(await credentials.readRecord(ACCOUNT_KEY))
}

/* ------------------------------------------------------------------ */
/* Cookie issuer and verifier                                          */
/* ------------------------------------------------------------------ */

function headerValue(headers, name) {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const raw = headers[name]
  if (typeof raw === 'string') return raw
  if (Array.isArray(raw)) return raw.join('; ')
  return undefined
}

/**
 * The listener authority a credential is bound to, from the request Host.
 * @returns {string | undefined} origin, or undefined when Host is absent or unusable.
 */
function authorityFor(protocol, headers) {
  const host = headerValue(headers, 'host')
  if (host === undefined || host.length === 0 || /[\s/\\?#@]/u.test(host)) return undefined
  try {
    return new URL(`${protocol}//${host}`).origin
  } catch {
    return undefined
  }
}

function cookieName(authority) {
  return `dsh-basic-${encodeBase64Url(createHash('sha256').update(authority).digest())}`
}

function readCookie(headers, name) {
  const cookies = headerValue(headers, 'cookie')
  if (cookies === undefined) return undefined
  let found
  for (const part of cookies.split(';')) {
    const at = part.indexOf('=')
    if (at === -1 || part.slice(0, at).trim() !== name) continue
    if (found !== undefined) return undefined
    found = part.slice(at + 1).trim()
  }
  return found
}

function verifySession(value, secret, authority, now, lifetimeMs) {
  const parts = value.split('.')
  if (parts.length !== 3) return false
  const [version, body, signature] = parts
  if (version !== `v${COOKIE_VERSION}` || body.length === 0 || signature.length === 0) return false
  const supplied = decodeBase64Url(signature)
  if (supplied === undefined || supplied.byteLength !== SECRET_BYTES) return false
  const expected = createHmac('sha256', secret).update(body).digest()
  if (!timingSafeEqual(supplied, expected)) return false
  const bytes = decodeBase64Url(body)
  if (bytes === undefined) return false
  let payload
  try {
    payload = JSON.parse(bytes.toString('utf8'))
  } catch {
    return false
  }
  if (!isRecord(payload) || Object.keys(payload).length !== 4) return false
  if (payload.version !== PAYLOAD_VERSION || payload.authority !== authority) return false
  if (!Number.isSafeInteger(payload.issuedAt) || payload.issuedAt < 0) return false
  if (!Number.isSafeInteger(payload.expiresAt) || payload.expiresAt > MAX_DATE_MS) return false
  if (payload.issuedAt > now || payload.expiresAt <= now) return false
  if (payload.expiresAt <= payload.issuedAt) return false
  if (payload.expiresAt - payload.issuedAt > lifetimeMs) return false
  return true
}

/* ------------------------------------------------------------------ */
/* Network addresses                                                   */
/* ------------------------------------------------------------------ */

function plainAddress(value) {
  if (typeof value !== 'string' || value.length === 0) return undefined
  return value.startsWith('::ffff:') ? value.slice(7) : value
}

function isLoopback(value) {
  const address = plainAddress(value)
  if (address === undefined) return false
  if (isIPv4(address)) return address.startsWith('127.')
  return address === '::1'
}

function addressKey(request) {
  const address = plainAddress(request.socket?.remoteAddress)
  if (address === undefined) return 'unknown'
  return isIPv6(address) ? address.toLowerCase() : address
}

/* ------------------------------------------------------------------ */
/* Failure accounting                                                  */
/* ------------------------------------------------------------------ */

function lockStatus(limiters, key, now) {
  const entry = limiters.get(key)
  if (entry === undefined) return undefined
  if (entry.lockedUntil > now) {
    return { retryAfter: Math.max(1, Math.ceil((entry.lockedUntil - now) / 1000)) }
  }
  if (entry.lockedUntil !== 0) {
    entry.lockedUntil = 0
    entry.count = 0
  }
  return undefined
}

function recordFailure(limiters, key, settings, now) {
  let entry = limiters.get(key)
  if (entry === undefined) {
    entry = { count: 0, strikes: 0, lockedUntil: 0 }
    limiters.set(key, entry)
  }
  entry.count += 1
  if (entry.count < settings.maxFailures) return
  entry.count = 0
  entry.strikes += 1
  const delay = Math.min(settings.lockoutMs * 2 ** Math.min(entry.strikes - 1, 30), MAX_LOCKOUT_MS)
  entry.lockedUntil = now + delay
  if (limiters.size > 256) {
    for (const [candidate, value] of limiters) {
      if (value.lockedUntil <= now && value.count === 0) limiters.delete(candidate)
    }
  }
}

/* ------------------------------------------------------------------ */
/* HTML                                                                */
/* ------------------------------------------------------------------ */

const PAGE_STYLE = `
:root{color-scheme:light dark;--bg:#f4f6fa;--card:#ffffff;--fg:#15181e;--muted:#5c6574;--line:#dde2ea;--accent:#2563eb;--accent-fg:#ffffff;--error:#b42318;--shadow:0 18px 50px rgba(16,24,40,.10)}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#181c23;--fg:#eef1f5;--muted:#9aa4b2;--line:#2b313b;--accent:#6f9bff;--accent-fg:#0b1020;--error:#ff9b94;--shadow:0 18px 50px rgba(0,0,0,.45)}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;min-height:100dvh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Helvetica Neue",Arial,sans-serif;line-height:1.5;-webkit-font-smoothing:antialiased}
main{width:100%;max-width:380px;padding:32px 28px;background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}
.mark{width:40px;height:40px;margin-bottom:16px;color:var(--accent)}
.mark svg{display:block;width:100%;height:100%}
h1{margin:0 0 6px;font-size:20px;line-height:1.3;font-weight:600}
p{margin:0;font-size:14px;overflow-wrap:anywhere}
.sub{margin:0 0 24px;color:var(--muted)}
form{display:grid;gap:16px}
label{display:grid;gap:6px;font-size:13px;font-weight:500;color:var(--muted)}
input{width:100%;min-height:44px;padding:10px 12px;font:inherit;font-size:15px;color:var(--fg);background:transparent;border:1px solid var(--line);border-radius:10px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 20%,transparent)}
button{min-height:44px;margin-top:4px;border:0;border-radius:10px;background:var(--accent);color:var(--accent-fg);font:inherit;font-size:15px;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.05)}
button:active{transform:translateY(1px)}
.error{margin:0;color:var(--error);font-size:13px}
.hint{margin:-8px 0 0;color:var(--muted);font-size:12px}
footer{margin-top:20px;color:var(--muted);font-size:12px}
.back{margin-top:20px;font-size:14px}
a{color:var(--accent)}
@media (prefers-reduced-motion:no-preference){button{transition:filter .15s ease}}
`

const PAGE_MARK = `<div class="mark" aria-hidden="true"><svg viewBox="0 0 64 64"><path d="M32 4 54 12.5v17.2c0 13.9-8.9 24.6-22 30.3C18.9 54.3 10 43.6 10 29.7V12.5Z" fill="currentColor"/><circle cx="32" cy="26" r="7" fill="var(--card)"/><rect x="28.6" y="31" width="6.8" height="13" rx="3.4" fill="var(--card)"/></svg></div>`

function escapeHtml(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;')
}

function renderDocument(title, body) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="referrer" content="no-referrer">
<meta name="generator" content="dsh-basic-auth">
<title>${escapeHtml(title)}</title>
<style>${PAGE_STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>`
}

function renderLogin({ pageTitle, days, error }) {
  const message = error === undefined ? '' : `<p class="error" role="alert">${escapeHtml(error)}</p>`
  return renderDocument(`${pageTitle} · 登录`, `${PAGE_MARK}
<h1>${escapeHtml(pageTitle)}</h1>
<p class="sub">请输入账号与密码继续。</p>
<form method="post" action="${LOGIN_PATH}" autocomplete="on">
<label>用户名<input type="text" name="username" autocomplete="username" maxlength="64" required autofocus></label>
<label>密码<input type="password" name="password" autocomplete="current-password" required></label>
${message}
<button type="submit">登录</button>
</form>
<footer>登录状态保存在此浏览器中，最长 ${days} 天；密码不会离开这台 Host。</footer>`)
}

function renderSetup({ pageTitle, token, error }) {
  const hidden = token === undefined ? '' : `<input type="hidden" name="token" value="${escapeHtml(token)}">`
  const message = error === undefined ? '' : `<p class="error" role="alert">${escapeHtml(error)}</p>`
  return renderDocument(`${pageTitle} · 首次设置`, `${PAGE_MARK}
<h1>首次设置</h1>
<p class="sub">这台 Host 还没有账号。创建后，访问根页需要先登录。</p>
<form method="post" action="${SETUP_PATH}">
${hidden}
<label>用户名<input type="text" name="username" autocomplete="username" maxlength="64" required autofocus></label>
<p class="hint">1–64 位，可用字母、数字和 . _ @ -</p>
<label>密码<input type="password" name="password" autocomplete="new-password" minlength="8" required></label>
<label>确认密码<input type="password" name="confirm" autocomplete="new-password" minlength="8" required></label>
${message}
<button type="submit">创建账号并登录</button>
</form>
<footer>本机访问可直接设置；远程设置请使用启动日志打印的一次性设置链接。</footer>`)
}

function renderNotice({ pageTitle, heading, message, retryAfter }) {
  const retry = retryAfter === undefined ? '' : `<p class="sub">请在 ${retryAfter} 秒后重试。</p>`
  return renderDocument(`${pageTitle} · 提示`, `${PAGE_MARK}
<h1>${escapeHtml(heading)}</h1>
<p class="sub">${escapeHtml(message)}</p>
${retry}
<p class="back"><a href="/">返回登录页</a></p>`)
}

/* ------------------------------------------------------------------ */
/* HTTP helpers                                                        */
/* ------------------------------------------------------------------ */

function respondPage(response, html, status, method, extraHeaders) {
  response.writeHead(status, { ...PAGE_HEADERS, ...extraHeaders })
  response.end(method === 'HEAD' ? undefined : html)
}

function respondNotice(response, status, details, method, extraHeaders) {
  respondPage(response, renderNotice(details), status, method, extraHeaders)
}

function respondEmpty(response, status, extraHeaders) {
  response.writeHead(status, { 'cache-control': 'no-store', ...extraHeaders })
  response.end()
}

function respondRedirect(response, location, cookie) {
  const headers = { location, 'cache-control': 'no-store' }
  if (cookie !== undefined) headers['set-cookie'] = cookie
  response.writeHead(303, headers)
  response.end()
}

function isFormContentType(request) {
  const raw = headerValue(request.headers, 'content-type')
  if (raw === undefined) return false
  return raw.split(';', 1)[0].trim().toLowerCase() === 'application/x-www-form-urlencoded'
}

function sameOrigin(request, protocol) {
  const origin = headerValue(request.headers, 'origin')
  if (origin === undefined) return true
  const authority = authorityFor(protocol, request.headers)
  if (authority === undefined) return false
  try {
    return new URL(origin).origin === authority
  } catch {
    return false
  }
}

function safeEqualString(left, right) {
  const a = Buffer.from(left, 'utf8')
  const b = Buffer.from(right, 'utf8')
  return a.byteLength === b.byteLength && timingSafeEqual(a, b)
}

async function readForm(request) {
  const chunks = []
  let size = 0
  try {
    for await (const chunk of request) {
      size += chunk.byteLength
      if (size > BODY_LIMIT_BYTES) return { tooLarge: true }
      chunks.push(chunk)
    }
  } catch {
    return { aborted: true }
  }
  return { body: Buffer.concat(chunks).toString('utf8') }
}

function validateSetup(username, password, confirm) {
  if (!USERNAME_PATTERN.test(username)) return '用户名需为 1–64 位，只能包含字母、数字和 . _ @ -。'
  if (password.length < PASSWORD_MIN_LENGTH) return '密码至少需要 8 位。'
  if (password.length > PASSWORD_MAX_LENGTH) return `密码不能超过 ${PASSWORD_MAX_LENGTH} 位。`
  if (password !== confirm) return '两次输入的密码不一致。'
  return undefined
}

/* ------------------------------------------------------------------ */
/* Plugin                                                              */
/* ------------------------------------------------------------------ */

/**
 * Install the cookie provider, the root-page interception, and the three
 * anonymous form routes.
 * @param {import('@deepseek-ai/cordis').Context} ctx - plugin scope owning every registration.
 * @param {unknown} config - row configuration validated here.
 */
export async function apply(ctx, config) {
  const settings = normalizeConfig(config)
  const secret = await loadSecret(ctx.credentials)
  const account = await readAccount(ctx.credentials)
  const peer = ctx.connection.createPeer({ principal: { kind: 'owner' } })
  const lifetimeMs = settings.cookieMaxAgeDays * DAY_MS
  const limiters = new Map()
  const secure = ctx.webServer.protocol === 'https:'
  const setupToken = account === undefined ? encodeBase64Url(randomBytes(SETUP_TOKEN_BYTES)) : undefined
  let active = true

  const authenticate = (request) => {
    if (!active) return undefined
    const authority = authorityFor(ctx.webServer.protocol, request.headers)
    if (authority === undefined) return undefined
    const value = readCookie(request.headers, cookieName(authority))
    if (value === undefined) return undefined
    return verifySession(value, secret, authority, Date.now(), lifetimeMs) ? peer : undefined
  }

  const issueCookie = (request) => {
    const authority = authorityFor(ctx.webServer.protocol, request.headers)
    if (authority === undefined) return undefined
    const issuedAt = Date.now()
    const expiresAt = issuedAt + lifetimeMs
    const payload = { version: PAYLOAD_VERSION, authority, issuedAt, expiresAt }
    const body = encodeBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'))
    const signature = encodeBase64Url(createHmac('sha256', secret).update(body).digest())
    const value = `v${COOKIE_VERSION}.${body}.${signature}`
    const attributes = `Max-Age=${Math.floor(lifetimeMs / 1000)}; Path=/; Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict`
    return `${cookieName(authority)}=${value}; ${attributes}${secure ? '; Secure' : ''}`
  }

  const clearCookie = (request) => {
    const authority = authorityFor(ctx.webServer.protocol, request.headers)
    if (authority === undefined) return undefined
    return `${cookieName(authority)}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`
  }

  const setupMatches = (provided) => {
    if (setupToken === undefined || provided === undefined || provided === '') return false
    return safeEqualString(provided, setupToken)
  }

  const safeHandler = (label, run) => async (request, response) => {
    try {
      await run(request, response)
    } catch (error) {
      ctx.logger.warn(`[basic-auth] ${label} 处理失败:`, error)
      if (response.headersSent) {
        response.destroy()
        return
      }
      if (!response.destroyed) respondEmpty(response, 500)
    }
  }

  const handleLogin = async (request, response) => {
    if (request.method !== 'POST') {
      respondEmpty(response, 405, { allow: 'POST' })
      return
    }
    if (!sameOrigin(request, ctx.webServer.protocol)) {
      respondEmpty(response, 403)
      return
    }
    if (!isFormContentType(request)) {
      respondEmpty(response, 415)
      return
    }
    const declared = Number(headerValue(request.headers, 'content-length'))
    if (Number.isFinite(declared) && declared > BODY_LIMIT_BYTES) {
      respondEmpty(response, 413)
      return
    }
    const form = await readForm(request)
    if (form.aborted) return
    if (form.tooLarge) {
      respondEmpty(response, 413)
      return
    }
    const params = new URLSearchParams(form.body)
    const username = params.get('username') ?? ''
    const password = params.get('password') ?? ''
    const key = addressKey(request)
    const now = Date.now()
    const locked = lockStatus(limiters, key, now)
    if (locked !== undefined) {
      respondNotice(response, 429, { pageTitle: settings.pageTitle, heading: '尝试次数过多', message: '登录暂时被锁定。', retryAfter: locked.retryAfter }, request.method, { 'retry-after': String(locked.retryAfter) })
      return
    }
    const stored = await readAccount(ctx.credentials)
    if (stored === undefined) {
      respondNotice(response, 409, { pageTitle: settings.pageTitle, heading: '尚未设置账号', message: '请先在本机打开根地址完成首次设置。' }, request.method)
      return
    }
    const candidate = await scrypt(password, stored.salt, HASH_BYTES, SCRYPT_OPTIONS)
    const usernameOk = safeEqualString(username, stored.username)
    const passwordOk = candidate.byteLength === stored.hash.byteLength && timingSafeEqual(candidate, stored.hash)
    if (!usernameOk || !passwordOk) {
      recordFailure(limiters, key, settings, now)
      respondPage(response, renderLogin({ pageTitle: settings.pageTitle, days: settings.cookieMaxAgeDays, error: '用户名或密码错误。' }), 401, request.method)
      return
    }
    limiters.delete(key)
    respondRedirect(response, '/', issueCookie(request))
  }

  const handleSetup = async (request, response) => {
    if (request.method !== 'POST') {
      respondEmpty(response, 405, { allow: 'POST' })
      return
    }
    if (!sameOrigin(request, ctx.webServer.protocol)) {
      respondEmpty(response, 403)
      return
    }
    if (!isFormContentType(request)) {
      respondEmpty(response, 415)
      return
    }
    const existing = await readAccount(ctx.credentials)
    if (existing !== undefined) {
      respondNotice(response, 409, { pageTitle: settings.pageTitle, heading: '已完成设置', message: '该 Host 已存在账号；如需重置，请删除凭据记录后重启。' }, request.method)
      return
    }
    const declared = Number(headerValue(request.headers, 'content-length'))
    if (Number.isFinite(declared) && declared > BODY_LIMIT_BYTES) {
      respondEmpty(response, 413)
      return
    }
    const form = await readForm(request)
    if (form.aborted) return
    if (form.tooLarge) {
      respondEmpty(response, 413)
      return
    }
    const params = new URLSearchParams(form.body)
    const url = new URL(request.url ?? '/', 'http://dsh.invalid')
    const supplied = params.get('token') ?? url.searchParams.get('setup') ?? ''
    const authorised = isLoopback(request.socket?.remoteAddress) || setupMatches(supplied)
    if (!authorised) {
      respondNotice(response, 403, { pageTitle: settings.pageTitle, heading: '无法设置', message: '首次设置只能从本机发起，或使用启动日志打印的一次性设置链接。' }, request.method)
      return
    }
    const username = params.get('username') ?? ''
    const password = params.get('password') ?? ''
    const confirm = params.get('confirm') ?? ''
    const token = setupMatches(supplied) ? supplied : undefined
    const failure = validateSetup(username, password, confirm)
    if (failure !== undefined) {
      respondPage(response, renderSetup({ pageTitle: settings.pageTitle, token, error: failure }), 400, request.method)
      return
    }
    const salt = randomBytes(SALT_BYTES)
    const hash = await scrypt(password, salt, HASH_BYTES, SCRYPT_OPTIONS)
    let created = false
    await ctx.credentials.modifyRecord(ACCOUNT_KEY, (current) => {
      if (current !== undefined) return undefined
      created = true
      return {
        kind: 'grant',
        payload: { version: RECORD_VERSION, username, salt: encodeBase64Url(salt), hash: encodeBase64Url(hash) },
      }
    })
    if (!created) {
      respondNotice(response, 409, { pageTitle: settings.pageTitle, heading: '已完成设置', message: '该 Host 已存在账号。' }, request.method)
      return
    }
    respondRedirect(response, '/', issueCookie(request))
  }

  const handleLogout = async (request, response) => {
    if (request.method !== 'POST') {
      respondEmpty(response, 405, { allow: 'POST' })
      return
    }
    if (!sameOrigin(request, ctx.webServer.protocol)) {
      respondEmpty(response, 403)
      return
    }
    respondRedirect(response, '/', clearCookie(request))
  }

  ctx.effect(() => () => {
    active = false
    limiters.clear()
  }, 'basic-auth: runtime state')

  ctx.connection.authentication.register({
    authenticate(request) {
      return authenticate(request)
    },
  })

  ctx.on('webserver/request', async (request, response, next) => {
    if (request.socket?.destroyed || response.destroyed) return
    const url = new URL(request.url ?? '/', 'http://dsh.invalid')
    if (url.searchParams.has('token') || url.searchParams.get('login') === 'qr') {
      await next()
      return
    }
    if ((request.method !== 'GET' && request.method !== 'HEAD') || url.pathname !== '/') {
      await next()
      return
    }
    const disconnected = new AbortController()
    const onClose = () => disconnected.abort()
    response.once('close', onClose)
    try {
      if (!active) {
        await next()
        return
      }
      const admission = ctx.connection.authentication.authenticate({
        headers: request.headers,
        method: request.method,
        url: request.url ?? '/',
        signal: disconnected.signal,
        socket: request.socket,
      })
      if (disconnected.signal.aborted) return
      if ('peer' in admission) {
        await next()
        return
      }
      const policy = ctx.bail(ctx.webServer, 'webserver/authorize', {
        headers: request.headers, method: request.method, url, transport: 'http', signal: disconnected.signal, socket: request.socket,
      }, 'anonymous')
      if (disconnected.signal.aborted || response.destroyed) return
      if (policy?.kind === 'deny') {
        respondEmpty(response, policy.status)
        return
      }
      const stored = await readAccount(ctx.credentials)
      if (disconnected.signal.aborted || response.destroyed) return
      if (stored === undefined) {
        respondPage(response, renderSetup({ pageTitle: settings.pageTitle, token: setupMatches(url.searchParams.get('setup') ?? '') ? url.searchParams.get('setup') : undefined }), 401, request.method)
        return
      }
      respondPage(response, renderLogin({ pageTitle: settings.pageTitle, days: settings.cookieMaxAgeDays }), 401, request.method)
    } catch (error) {
      ctx.logger.warn('[basic-auth] 根页处理失败:', error)
      if (!response.headersSent) respondEmpty(response, 503)
      else response.destroy()
    } finally {
      response.off('close', onClose)
    }
  })

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: LOGIN_PATH,
    auth: 'anonymous',
    handler: safeHandler('login', handleLogin),
  }), 'basic-auth: login route')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: SETUP_PATH,
    auth: 'anonymous',
    handler: safeHandler('setup', handleSetup),
  }), 'basic-auth: setup route')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: LOGOUT_PATH,
    auth: 'anonymous',
    handler: safeHandler('logout', handleLogout),
  }), 'basic-auth: logout route')

  if (setupToken !== undefined) {
    try {
      const advertised = new URL(ctx.webApp.getAdvertisedUrl())
      advertised.searchParams.set('setup', setupToken)
      console.log(`[basic-auth] 首次设置：${advertised.href}`)
    } catch (error) {
      ctx.logger.warn('[basic-auth] 无法读取对外地址；请在本机打开根地址完成首次设置。', error)
    }
  }
}
