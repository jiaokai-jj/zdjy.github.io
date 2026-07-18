# deploy_worker.ps1 - 一键用 Cloudflare REST API 部署 Worker (jyt-license-server)
#
# 用法(推荐: 环境变量方式, 真正一键):
#   $env:CF_API_TOKEN = "cfr_你的新Token"
#   $env:CF_ADMIN_KEY  = "dm7jvKiX1U64n3Ual0RVcpwDQzxtljE3"   # 可选, 线上已设过可省略
#   cd 到本脚本所在目录, 然后:  .\deploy_worker.ps1
#
# 或直接运行, 按提示掩码粘贴 Token(交互式, 非一键但同样安全)。
#
# 安全说明:
#   - 本脚本不硬编码任何密钥; Token/ADMIN_KEY 仅来自环境变量或运行时掩码输入, 不写入任何文件。
#   - Token 是最高权限凭证, 创建后只显示一次, 请存密码管理器, 不要提交到 git / 粘贴到聊天。
#
# 网络说明:
#   - 经本机 Karing 代理 (127.0.0.1:3067) 出网; curl 加 -k 跳过代理的 TLS 拦截证书。
#   - 若你已关闭 Karing, 把下面两行 HTTP(S)_PROXY 注释掉即可直连。

$ErrorActionPreference = "Stop"

$accountId  = "9d3c1b75930d4d34eb68ab9334f78ce3"
$scriptName = "jyt-license-server"
$kvNsId     = "3c284ff71077458fa15188a2c23034b9"
$workerPath = Join-Path $PSScriptRoot "worker.js"

# ---------- 读取 CF API Token ----------
$token = $env:CF_API_TOKEN
if (-not $token) {
    $secure = Read-Host -Prompt "请输入 Cloudflare API Token" -AsSecureString
    $token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if (-not $token) { Write-Error "未提供 CF_API_TOKEN, 退出"; exit 1 }

# ---------- ADMIN_KEY (可选, 默认沿用线上已有值) ----------
$adminKey = $env:CF_ADMIN_KEY
if (-not $adminKey) {
    $ans = Read-Host -Prompt "ADMIN_KEY 留空=沿用线上已有值; 或输入新值覆盖"
    if ($ans.Trim().Length -gt 0) { $adminKey = $ans.Trim() }
}

# ---------- 代理 + 跳过代理证书 ----------
$env:HTTP_PROXY  = "http://127.0.0.1:3067"
$env:HTTPS_PROXY = "http://127.0.0.1:3067"
$env:NO_PROXY    = "localhost,127.0.0.1"

if (-not (Test-Path $workerPath)) { Write-Error "找不到 worker.js: $workerPath"; exit 1 }

$metadata = '{"main_module":"worker.js","compatibility_date":"2024-09-01","bindings":[{"type":"kv_namespace","name":"STATS","namespace_id":"' + $kvNsId + '"}]}'

$curl = "curl.exe"

Write-Host ">>> [1/2] 上传 worker.js ..." -ForegroundColor Cyan
& $curl -k -S -f -X PUT "https://api.cloudflare.com/client/v4/accounts/$accountId/workers/scripts/$scriptName" `
    -H "Authorization: Bearer $token" `
    -F "metadata=$metadata;type=application/json" `
    -F "worker.js=@$workerPath;type=application/javascript+module"
if ($LASTEXITCODE -ne 0) { Write-Error "上传失败 (检查 Token 是否有效 / 代理是否可达)"; exit 1 }

if ($adminKey) {
    Write-Host ">>> [2/2] 设置 ADMIN_KEY 密钥 ..." -ForegroundColor Cyan
    $secretBody = "{`"text`":`"$adminKey`",`"type`":`"secret_text`"}"
    & $curl -k -S -f -X PUT "https://api.cloudflare.com/client/v4/accounts/$accountId/workers/scripts/$scriptName/secrets/ADMIN_KEY" `
        -H "Authorization: Bearer $token" `
        -H "Content-Type: application/json" `
        --data $secretBody
    if ($LASTEXITCODE -ne 0) { Write-Error "设置 ADMIN_KEY 失败"; exit 1 }
} else {
    Write-Host ">>> [2/2] 跳过 ADMIN_KEY (沿用线上已有值)" -ForegroundColor Yellow
}

Write-Host ">>> 部署完成。验证: https://www.jyt.cc.cd/api/health" -ForegroundColor Green
