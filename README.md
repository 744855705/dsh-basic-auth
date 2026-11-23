# @744855705/dsh-basic-auth

给 DeepSeek Harness（DSH）Web UI 加一层**本机用户名 + 密码登录**。访问站点根地址即可：未初始化时显示设置页，初始化后显示登录页；登录成功后由插件自己签发浏览器 cookie，之后照常进入应用。原有的 `?token=` 启动链接与二维码登录保持原样。

- Host-only bundle，零依赖、零构建、无安装脚本
- 不改 DSH 源码，不注册 `/` 路由，不碰 `/api`，不禁用 remote-connection
- 单账号；密码只以 scrypt 派生值存进 DSH 凭据库，明文不落盘、不进日志
- 登录页零 JS、无外部资源，适配浅色 / 深色

最低支持 **DSH 0.2.3-alpha.1**（`engines.dsh: ^0.2.3-alpha.1`），在 `0.2.3-alpha.1` 与 `0.2.3-alpha.2` 上验证。

## 安装

前置条件：本机能访问 GitHub，且已安装 `git` 与 `pnpm`。仓库是公开的，安装时不需要凭据。

推荐钉到 40 位 commit，这样插件列表会提供 git 更新：

```text
https://github.com/744855705/dsh-basic-auth.git#ed82a684f9fb06b33586b7d8697328e99e5b4f7a
github:744855705/dsh-basic-auth#ed82a684f9fb06b33586b7d8697328e99e5b4f7a
```

两种安装入口等价：

1. **Plugins → Add plugin**，粘贴上面的 git spec。
2. 让 Agent / 工具调用 `plugin_manager`，`action: install_bundle`，`target` 为 git spec。

安装器会把 bundle 加入当前 profile 的选择列表。有 HMR 时立即生效；否则重启 DSH。

> 用分支名（如 `#main`）也能装，但后续不会提示 git 更新；正式使用建议钉 commit。

开发时也可以直接装本地目录：`plugin_manager` → `install_bundle`，`target` 指向本仓库的绝对路径；本地目录安装是链接，改文件后重新启用该行即可热重载。

## 首次设置

安装后不需要任何命令或一次性链接：直接打开站点根地址（如 `http://<host>:3080/`）。

- 还没有账号时，根页显示设置表单；填用户名、密码、确认密码并提交即可。
- 设置页字段：用户名 1–64 位，可用字母、数字和 `. _ @ -`；密码至少 8 位。
- 提交成功后会写入账号、立即签发 cookie，并跳回应用根页。
- 账号写入后，根页自动变为登录页；再访问 `POST /__basic-auth/setup` 固定返回 `409`。

> **先到先得**：设置账号之前，任何能访问该端口的人都可以创建第一个账号。首次启动后请立即设置，或用防火墙 / 安全组限制来源网络。

## 日常使用

- 未登录访问根页会看到登录页（`401`），输入用户名密码后进入应用。
- 登录状态是一个自签 cookie：默认最长 **180 天**，固定到期，**不会因为访问而续期**。
- 浏览器 cookie 名为 `dsh-basic-<authority 哈希>`，`HttpOnly; SameSite=Strict`，HTTPS 下再加 `Secure`。
- 退出登录（可选接口）：

  ```sh
  curl -si -X POST http://127.0.0.1:3080/__basic-auth/logout
  ```

  它会清除当前 authority 的 cookie 并 `303` 回 `/`；其他设备上的登录不受影响。

## 配置

在 profile 的插件行里配置（安装器写入 `cordis.patch.yml`）：

| 配置项 | 默认 | 说明 |
|---|---:|---|
| `cookieMaxAgeDays` | `180` | cookie 绝对有效期（天），正整数 |
| `pageTitle` | `'DeepSeek Harness'` | 登录页标题，1–120 字符 |
| `maxFailures` | `5` | 同一来源连续失败多少次后锁定 |
| `lockoutMs` | `60000` | 首次锁定时长；之后指数退避，上限 15 分钟 |

配置在插件加载时校验；非法值会让插件加载失败并在插件列表里显示原因。

## 重置

账号与签名密钥是两条凭据记录：

- `basic-auth/account`：用户名、salt、scrypt hash
- `basic-auth/session`：cookie 签名密钥

重置步骤：

1. 在 `~/.dsh/.credentials.yaml`（或凭据管理界面）删除这两条记录。
2. 重启 DSH。
3. 再次打开根地址就会回到首次设置页，重新创建账号（不需要命令）。

只删 `account` 不删 `session` 时，旧 cookie 在到期前仍然有效；要彻底失效，请两条都删。签名密钥记录损坏时插件会**报错并停止启用**，不会静默重建；按上面的步骤删除后重启即可。

## 安全说明

- **必须用 HTTPS 对外提供服务。** 登录表单和 cookie 在明文 HTTP 下会被同网段的人截获。仅限本机或受信网络临时使用 HTTP。
- 密码用 `scrypt(N=16384, r=8, p=1)` 加盐派生，只保存 salt 与 32 字节 hash；明文只在请求体内存中存在。
- 登录失败统一提示「用户名或密码错误」，不区分账号是否存在；任何路径都不记录密码。
- 按来源 IP 归一化限流；锁定期间不再比对密码，返回 `429` + `Retry-After`。
- 页面响应带 `Cache-Control: no-store`、`Referrer-Policy: same-origin`、`X-Content-Type-Options: nosniff` 与严格 CSP，不发送 `WWW-Authenticate`（避免浏览器原生 Basic 弹窗）。`no-referrer` 会让 Chromium 对表单 POST 发送 `Origin: null`，被 DSH 的请求 fence 拒绝为 `forbidden`，因此不能使用。
- 登录 POST 带 `Origin` 时要求与请求自身同源，跨站表单会被拒绝。
- 首次设置是**先到先得**：账号写入后该接口固定返回 `409`。初始化窗口内请限制谁能访问该端口。
- 这是单账号的本地防护，不做多用户、找回密码、OIDC/LDAP。需要更强身份体系请用 DSH 自带的 token / 二维码远程登录，或在前置反向代理上做认证。
- 反向代理场景：`Host` 与 `Origin` 必须与浏览器实际访问的源一致，否则 cookie authority 不匹配、登录不会生效。

## 卸载

在 Plugins 里移除该 bundle，或：

```text
plugin_manager action: remove_bundle, target: @744855705/dsh-basic-auth
```

卸载后：

- 根页恢复官方 `401` 登录/连接页；
- `?token=` 链接与二维码登录照常可用；
- 两条 `basic-auth/*` 凭据记录会保留（不删也不影响其他功能），需要时按「重置」里的路径手动删除。

## 升级 DSH 后重跑验收

DSH 升级后先在插件列表确认本插件状态为 `applied`（不是 `failed` / `overridden`），再跑一遍下面的命令。把 `http://127.0.0.1:3080` 换成你的实际地址；未设置账号时先完成首次设置。

```sh
# 1 未登录根页：401 + text/html + 含 username 输入框
curl -si http://127.0.0.1:3080/ | head -20

# 2 首次设置（裸根页，无需 token），期望 303 + Set-Cookie
curl -si -c /tmp/jar -X POST http://127.0.0.1:3080/__basic-auth/setup \
  -d 'username=admin&password=S3cret-pass&confirm=S3cret-pass'

# 3 错误密码：401，统一文案
curl -si -X POST http://127.0.0.1:3080/__basic-auth/login -d 'username=admin&password=wrong'

# 4 限流：第 6 次起 429 + Retry-After
for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:3080/__basic-auth/login -d 'username=admin&password=wrong'; done

# 5 正确密码：303 + Set-Cookie；带 cookie 根页 200（应用 HTML）
curl -si -c /tmp/jar -X POST http://127.0.0.1:3080/__basic-auth/login \
  -d 'username=admin&password=S3cret-pass'
curl -si -b /tmp/jar http://127.0.0.1:3080/ | head -5

# 6 带 cookie 调 API 不是 401；不带是 401
curl -s -o /dev/null -w '%{http_code}\n' -b /tmp/jar http://127.0.0.1:3080/api/
curl -s -o /dev/null -w '%{http_code}\n'           http://127.0.0.1:3080/api/

# 7 原有登录方式未被劫持：响应里不含本插件标记
curl -s 'http://127.0.0.1:3080/?token=bogus' | grep -c 'basic-auth'   # 期望 0
curl -s 'http://127.0.0.1:3080/?login=qr'    | grep -c 'basic-auth'   # 期望 0

# 8 已初始化后 setup 关闭，期望 409
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3080/__basic-auth/setup \
  -d 'username=hacker&password=whatever&confirm=whatever'
```

再人工确认：浏览器登录后应用完整可用（含 WebSocket 流）、刷新与重开浏览器免登录、插件列表标题/描述/图标正常。

## 工作原理

- **认证扩展点**：`ctx.connection.authentication.register(provider)` 注册一个校验器。DSH 按注册顺序尝试，第一个返回活 Peer 的胜出。本插件排在内置 token / 二维码 / Desktop 之后，只认自己的 cookie。
- **根页拦截**：监听 `webserver/request` 瀑布，在命名路由与 fallback 分发**之前**处理未登录的 `GET/HEAD /`。带 `?token=` 或 `?login=qr` 的请求直接放行给原插件。
- **共享 owner Peer**：`ctx.connection.createPeer({ principal: { kind: 'owner' } })` 只创建一次，认证通过后返回同一个 Peer。
- **cookie**：`v1.<base64url(JSON)>.<base64url(HMAC-SHA256(secret, body))>`，绑定当前监听 authority；密钥存在 `basic-auth/session`，记录损坏时报错而不是重建。
- **页面**：单文件内联 CSS，零 JS、无外部资源，`prefers-color-scheme` 适配。

## 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| 根页仍显示官方 401 纯文本 | 插件未加载或状态不是 `applied`；看插件列表与控制台日志 |
| 登录成功但仍回到登录页 | 反向代理下 `Host` / `Origin` 与访问源不一致，cookie authority 不匹配 |
| `429` 且 `Retry-After` 很长 | 该来源连续失败触发锁定；等待或重启 Host 清空内存计数 |
| 插件加载失败，提示 `basic-auth/session` 或 `basic-auth/account` 格式无效 | 凭据记录损坏；按「重置」删除记录并重启 |
| 安装报 `ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION` | 这是 pnpm 对**现有 profile lockfile** 的供应链校验（与插件无关）：lockfile 里有发布未满 24 小时的包。等该条目过观察期后重试，或临时把 profile `pnpm-workspace.yaml` 的 `minimumReleaseAge` 设为 `0`、装完立即恢复 |
| 安装报 `incompatible-version` | DSH 版本低于 0.2.3-alpha.1，或高于 0.3.0 |
| 安装时 git 拉取失败 | 检查 `git ls-remote <spec>` 能否在本机完成；公开仓库不需要 token |
| 浏览器提交设置/登录返回纯 `forbidden` | 页面 `Referrer-Policy` 为 `no-referrer` 时 Chromium 会发 `Origin: null`；本插件 1.0.3 起改用 `same-origin` |

## 许可

[MIT](./LICENSE)
