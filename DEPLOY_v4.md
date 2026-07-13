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
