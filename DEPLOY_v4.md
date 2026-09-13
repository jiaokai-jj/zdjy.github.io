# v4.0 部署说明

## 一、服务端部署（Cloudflare Worker）

### 1. 安装 Wrangler CLI
```bash
npm install -g wrangler
wrangler login
```

### 2. 创建 KV 命名空间
```bash
cd 你的本地仓库目录
wrangler kv:namespace create STATS
```
将返回的 `id` 填入 `wrangler.toml` 中的 `YOUR_KV_NAMESPACE_ID`

### 3. 设置管理员密钥
```bash
wrangler secret put ADMIN_KEY
```
输入你自定义的管理员密钥（例如: `jyt-admin-2025-your-secret-key`）

### 4. 部署 Worker
```bash
wrangler deploy
```

### 5. 配置路由
在 Cloudflare Dashboard 中，为 `www.jyt.cc.cd/api/*` 配置 Worker 路由：
- 路由: `www.jyt.cc.cd/api/*`
- Worker: `jyt-license-server`

---

## 二、GitHub Pages 部署（静态文件）

GitHub Pages 文件已自动推送到 main 分支，GitHub 会自动部署。

### version.txt 格式
```
版本号|强制更新(0/1)|文件哈希(可选)
```
当前: `4.0.0|0|`

---

## 三、客户端构建

### 1. 生成新的完整性哈希
```bash
cd 你的客户端构建目录
python update_hash.py
```

### 2. 使用 Nuitka + VMP 构建
```bash
build.bat
```

### 3. 生成 RSA 签名的注册码
使用服务端 `/api/generate` 端点获取待签名的 payload，然后用私钥签名：

```python
# 离线签名脚本（需要RSA私钥）
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64, json

# 加载私钥（妥善保管，不要泄露）
private_key = RSA.import_key(open("private_key.pem").read())

# 注册码payload
payload = {
    "lid": "LID-XXXX",
    "mh": "客户机器码hash",
    "tier": "premium",
    "exp": 0,  # 0=永久, 或 Unix时间戳
    "iat": int(time.time())
}

payload_str = json.dumps(payload, separators=(",", ":"))
payload_b64 = base64.b64encode(payload_str.encode()).decode()
h = SHA256.new(payload_str.encode())
sig = pkcs1_15.new(private_key).sign(h)
sig_b64 = base64.b64encode(sig).decode()

license_key = payload_b64 + "." + sig_b64
print("注册码:", license_key)
```

---

## 四、管理操作

### 吊销许可证
```bash
curl -X POST https://www.jyt.cc.cd/api/revoke \
  -H "Content-Type: application/json" \
  -H "X-API-Key: 你的管理员密钥" \
  -d '{"license": "LID-XXXX"}'
```

### 强制更新
```bash
curl -X POST https://www.jyt.cc.cd/api/force_update \
  -H "Content-Type: application/json" \
  -H "X-API-Key: 你的管理员密钥" \
  -d '{"force": true}'
```

### 查看统计
```bash
curl https://www.jyt.cc.cd/api/stats
```

---

## 五、v4.0 安全升级清单

- [x] 服务端 RSA 签名验证
- [x] 机器码绑定验证
- [x] KV 存储吊销列表
- [x] 短期令牌（7天有效）
- [x] 客户端移除 HMAC 格式
- [x] 许可证文件使用安全加密（替代XOR）
- [x] 会话文件使用安全加密
- [x] VersionManager 强制交易限制
- [x] 风控 qty 变量修复
- [x] 风控 on_tick 注释bug修复
- [x] 风控 _intraday sn 变量修复
- [x] 大盘评分多维度增强
- [x] 个股监控修复
- [x] 重复 test_monitor 合并

---

## 六、推广链接与在线激活（新增）

### 1. 推广链接（代理归因）
- 推广链接格式：`https://www.jyt.cc.cd/?ref=代理码`
- 访客打开带 `?ref=` 的链接后，网站自动记录该代理，其**下载 / 激活 / 下单**均归属该代理（存于 KV）。
- 代理申请：在"在线领取激活码"区块填代理码点"生成推广链接"，或调用 `POST /api/agent/apply {"code":"AG123"}` 返回 `promo_url`。
- 后台统计：管理后台 → **代理** Tab（`/api/admin/agents`）查看各代理的下载/访问/激活/订单数。

### 2. 在线领取激活码（已关闭）
- `SELF_ISSUE_ENABLED = false`：自助领取入口已关闭，客户统一走客服人工发放。
- 接口 `POST /api/issue` 现直接返回 403「自助领取已关闭，请添加客服QQ 290144665」。
- 试用码也**不再由服务端签发**，与正式码一样由本地注册机离线签发后发放。

### 3. 购买下单
- 价格页"立即购买 / 立即选用"→ 生成订单 → 提示联系客服付款。
- 接口：`POST /api/order {"name","contact","tier","agent?","machine_code?"}`

### 4. 激活码签发：本地离线批量签发（服务端签发已永久停用）
> **2026-09-14 安全整改**：云端 `PRIVATE_KEY` 已删除。
> 原因：私钥留在云端 = 服务器一旦被攻破，攻击者可签发与合法码**无法区分**的授权码（断根级风险）。
> 现在服务端**不具备签发能力**，只保留"登记 / 核查"职能。

**签发流程**
1. 本地注册机离线签发（私钥只在本机 `_PRIVATE_KEY_DO_NOT_SHIP/`，永不上云）：
   ```bash
   python batch_issue.py --template          # 生成名单模板 roster.csv
   python batch_issue.py roster.csv          # 批量签发 -> 授权码清单_时间戳.csv
   python batch_issue.py roster.csv --push   # 签发后逐条推送线上登记（可选）
   ```
2. 推送登记走 `POST /api/admin/issue/register`：服务端用内置**公钥**验签，通过才写入台账。
   **登记只是备案，不是授权** —— 客户能否激活只取决于本地 RSA 验签。

**服务端现状**
- `POST /api/admin/issue`、`POST /api/admin/orders/issue` 已返回 `410 server_signing_disabled`。
- 线上 secret 仅剩 `ADMIN_KEY`、`TIME_TICKET_PRIVATE_KEY`（后者只用于签时间锚，不参与签发）。

**非法账户识别**
- 验签通过但**从未登记**的授权码，会自动记入 KV `unregistered_hits`。
- 后台：`GET /api/admin/unregistered` 查看；`POST /api/admin/unregistered/resolve {"lid","action"}`
  处置（action = `register` 登记为合法 / `revoke` 加入吊销 / `ignore` 忽略）。
- 放行逻辑不受影响：判定始终只看 RSA 验签，不会误伤正常客户。

### 5. 部署
```bash
wrangler deploy
```
静态页由 GitHub Pages 随 `git push` 自动上线；Worker 需 `wrangler deploy` 手动部署（改 `worker.js` 后再次 deploy 即可）。

### 6. 下载包更新
本机 `compile_fix.bat` 编译出新单 exe 后，将 `downloads/智能交易系统.7z` 替换为新包再 push。
