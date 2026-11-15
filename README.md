# pixiv-token

一键获取你自己的 **Pixiv refresh_token**：本机起一个网页，登录 Pixiv，粘贴回调地址，token 就出来了。

- 纯 Python 标准库，**零依赖**，单文件
- 全程只和 `pixiv.net` 官方接口通信，不经过任何第三方服务器
- 自动探测本地代理（Clash / v2rayN / sing-box 等），适合国内网络环境
- token 自动保存到本地 `pixiv_token.json`（已加入 `.gitignore`）

> refresh_token 等同于你的账号凭证，**不要提交到仓库、不要发给别人**。

---

## 下载（免安装）

不想 clone 的话，直接去 [Releases](https://github.com/AmeliaOWO/pixiv-token-get/releases) 下载
`pixiv-token-1.1.0.zip`，解压后：

| 系统 | 操作 |
| --- | --- |
| Windows | 双击 `一键获取Token.bat` |
| macOS | 双击 `一键获取Token.command`（首次可能要 `chmod +x`，或在「隐私与安全性」里放行） |
| Linux | `bash run.sh` |

---

## 快速开始

```bash
python pixiv_token.py
```

脚本会自动打开 <http://127.0.0.1:17777/>，然后：

1. 点「**打开 Pixiv 登录页**」，登录你的账号（浏览器已登录过会直接跳转）。
2. 浏览器会跳到一个空白页，地址栏是这样的：

   ```
   https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback?state=...&code=...
   ```

3. 马上复制整条地址，粘贴到工具页面第 2 步，点「**换取 Refresh Token**」。
4. 页面上会显示 refresh_token，同时写入同目录的 `pixiv_token.json`。

`code` 的有效期只有几十秒，**拿到后要立刻粘贴**。

### 拿到 callback 地址的两种方式

| 情况 | 做法 |
| --- | --- |
| 登录后停在空白页 | 直接复制地址栏 |
| 地址被 `pixiv://` 弹窗拦掉、或停在 `accounts.pixiv.net/post-redirect` | `F12` → Network → 勾 **Preserve log** → 过滤 `callback` → 右键请求 → Copy link address |

---

## 参数

```
python pixiv_token.py [--port 17777] [--proxy http://127.0.0.1:7890] [--no-browser]
```

| 参数 | 说明 |
| --- | --- |
| `--port` | 本地监听端口，默认 `17777`；被占用时自动往后找 |
| `--proxy` | 指定 HTTP 代理；`direct` 表示强制直连。不传则先读环境变量，再探测常见本地代理端口 |
| `--no-browser` | 不自动打开浏览器 |
| `--version` | 显示版本 |

只监听 `127.0.0.1`，并且校验 `Host` 头，外部网页无法跨站调用本地服务。

---

## 工作原理

标准 OAuth 2.0 Authorization Code + PKCE 流程，使用 Pixiv Android 客户端的公开参数：

| 步骤 | 端点 |
| --- | --- |
| 授权页 | `https://app-api.pixiv.net/web/v1/login?code_challenge=...&code_challenge_method=S256&client=pixiv-android` |
| 回调 | `https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback?code=...` |
| 换 token | `POST https://oauth.secure.pixiv.net/auth/token`（`grant_type=authorization_code`） |

`code_verifier` 由本地随机生成（43 字符），`code_challenge = BASE64URL(SHA256(verifier))`，只有持有 verifier 的本地进程才能把 code 换成 token。

> `client_id` / `client_secret` 是 Pixiv App 内置的公开参数，不是你的账号密码。Pixiv 更换版本时这两个值可能失效，见下方 FAQ。

---

## FAQ

**1. 打开 `.../users/auth/pixiv/start?...` 显示「您所指定的端点不存在」**

正常。`start` 是服务端内部跳转用的，不接受浏览器直接访问（GET 一定 404）。不要手动打开它，按上面第 3 步抓 `callback` 地址即可。

**2. 换 token 报 403「不正なOAuthクライアントです」**

`client_id` 过期了。Pixiv 已经把 `MOBrBDS8blbauoSck0Zf` 换成 `MOBrBDS8blbauoSck0ZfDbtuzpyT`，如果将来又变，改脚本顶部的 `CLIENT_ID` / `CLIENT_SECRET` 即可。

**3. 换 token 报 400「不正なリクエストです」/ `invalid_request`**

`code` 过期，或者和你当前这次登录会话不匹配（比如用了上一次留下的旧地址）。回到工具页面点一次「换一个登录链接」，重新登录再抓。

**4. 提示连不上 Pixiv**

脚本本身已自动探测本地代理；如果代理端口不常见，显式指定：

```bash
python pixiv_token.py --proxy http://127.0.0.1:7890
```

浏览器那侧也要走代理，否则登录页打不开。

**5. token 存哪儿？会不会被提交？**

存在脚本同目录的 `pixiv_token.json`，已在 `.gitignore` 中排除。这个文件等于账号密码，别外传。

---

## 用到 refresh_token 的地方

大多数 Pixiv 第三方库（`pixivpy`、`pixiv-api-client` 等）都接受 refresh_token：

```python
from pixivpy3 import AppPixivAPI

api = AppPixivAPI()
api.auth(refresh_token="你的 refresh_token")
```

---

## 免责声明

本项目仅用于获取**你自己的** Pixiv 账号凭证，方便个人使用第三方客户端。请遵守 [Pixiv 服务条款](https://www.pixiv.net/terms_of_service)，不要用于自动化滥用、爬取限流接口或任何侵犯他人权益的行为。使用风险自负。

## License

[MIT](LICENSE)
