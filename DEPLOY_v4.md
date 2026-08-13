# v4.0 部署说明

## 一、服务端部署（Cloudflare Worker）

### 1. 安装 Wrangler CLI
```bash
npm install -g wrangler
wrangler login
```

### 2. 创建 KV 命名空间
```bash
cd C:\Users\wf\Documents\GitHub\zdjy.github.io
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
cd F:\SmartTradingSystem_v3_build
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

### 2. 在线领取激活码
- 客户在网站"在线领取激活码"填**机器码 + 版本**：
  - **体验试用 (trial)**：服务端即时签发 7 天激活码，页面直接显示可复制，无需客服。
  - **付费版（体验/标准/专业）**：生成订单，提示加客服 QQ `290144665` 付款；管理员在后台**订单** Tab 点"签发"后发放。
- 接口：`POST /api/issue {"machine_code","tier","agent?","days?"}`

### 3. 购买下单
- 价格页"立即购买 / 立即选用"→ 生成订单 → 提示联系客服付款。
- 接口：`POST /api/order {"name","contact","tier","agent?","machine_code?"}`

### 4. 服务端签发依赖私钥（必须配置）
Worker 用私钥（`env.PRIVATE_KEY`）在线签发激活码，私钥**仅存于 Cloudflare Secret，绝不进仓库 / 前端**。
- WebCrypto 要求 **PKCS#8** 格式私钥。若你的私钥是 PKCS#1（`BEGIN RSA PRIVATE KEY`），先转换：
  ```bash
  python -c "from Crypto.PublicKey import RSA; k=RSA.import_key(open(r'C:\Users\jk\Desktop\wk\zmjyzcm\_PRIVATE_KEY_DO_NOT_SHIP\_rsa_priv.pem','rb').read()); open('priv_pkcs8.pem','wb').write(k.export_key('PEM', pkcs=8))"
  ```
- 设置密钥（粘贴 `priv_pkcs8.pem` 全文）：
  ```bash
  wrangler secret put PRIVATE_KEY
  ```
- 未配置时 `/api/issue` 的 trial 签发会返回 500（明确提示 PRIVATE_KEY 未配置）。

### 5. 部署
```bash
wrangler deploy
```
静态页由 GitHub Pages 随 `git push` 自动上线；Worker 需 `wrangler deploy` 手动部署（改 `worker.js` 后再次 deploy 即可）。

### 6. 下载包更新
本机 `compile_fix.bat` 编译出新单 exe 后，将 `downloads/智能交易系统.7z` 替换为新包再 push。
