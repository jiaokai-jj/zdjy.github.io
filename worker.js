// Cloudflare Worker - JYT License v4.0 + Stats + RSA Verification
// v4.0 - 全面安全升级：RSA签名验证 + 机器码绑定 + KV存储吊销列表

// RSA公钥（与客户端 crypto.py 中的公钥一致）
const RSA_PUB_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlKpzCR6EPo/71ywpIrDF
uOkFCMD422+EzjK1rXprsS5OXxfyqSIJZkGB0TF6zAwcLpkLQzC4I+iFES/PVi6I
rw1Lz8o8bKPrJawvD/pVdIgCvWjaBImIDew7t/Bd+jJSxAFe+vj6mf4rB9mE493r
bQ3z3mu/ud4EJjAKnauEfPMUX6a5Nfw40p2djEzOMWnd6x0FK9T4DsYQzqEW6pPZ
E6S06CR+EoKO7cERtfEeZdDRewQSAmuXVeatw5cPivVYx7MNxiHfM3y+WtKwJnAF
po/n0CqDgjcqoQSw9BL0FjyazIEGkbELmDHEQoAOtVmFkN1aC8WQauE3rrP7PxBf
PQIDAQAB
-----END PUBLIC KEY-----`;

// 版本比较: "final-2" >= "final-1" -> true; 用于 min_build 版本闸门(新版本放行, 旧版本清退)。
// 兼容 "final-N" 数字后缀; 严格解析 ^final-(\d+)$, 并加一个合理上限, 拒绝异常极大值。
// 注意: 客户端可自行上报 ver, 本函数只能防"格式异常/极端值", 无法防伪造——真正的根治是把
// 版本号绑进 RSA 签名 payload(license 生成时写入 ver 字段), 服务端比对已验签的 payload.ver。
function buildAtLeast(clientVer, minBuild) {
  try {
    const m1 = /^final-(\d+)$/.exec(String(clientVer).trim());
    const m2 = /^final-(\d+)$/.exec(String(minBuild).trim());
    if (m1 && m2) {
      const a = parseInt(m1[1], 10);
      const b = parseInt(m2[1], 10);
      // 上限: 拒收异常极大的虚构版本号(如 final-999999), 简化对"暴力抬高版本绕过闸门"的抵御。
      if (Number.isFinite(a) && a >= 0 && a <= 99999) return a >= b;
    }
  } catch {}
  // 无法按 final-N 解析时一律视为"未达下限"(fail towards outdated), 不再用精确相等放行。
  return false;
}

// 版本号"另类验证"解码: gen_license.py 把真实构建号随机拆成 "基数+增量" 存进已验签的 payload.ver,
// 这里"基数+增量 求和"才还原真实构建号 —— Agent 看到 5.0 / 改成 999 都命中不了真实值。
// 老授权(无 ver 字段)返回 -1, 由调用方回退 body.ver 兼容。
function decodeLicVer(payload) {
  try {
    const s = (payload && payload.ver || "").toString().trim();
    if (!s) return -1;
    const m = /^(\d+)\+(\d+)$/.exec(s);           // "基数+增量"
    if (m) return parseInt(m[1], 10) + parseInt(m[2], 10);
    const n = parseInt(s, 10);                    // 兼容纯数字(意外情形)
    if (!isNaN(n)) return n;
  } catch {}
  return -1;
}

// 轻量 IP 级速率限制(KV 滑动窗口)。用于管理后台登录等无鉴权入口, 抵御暴力尝试。
// 失败时返回 true(放行), 命中上限返回 false。任何异常都放行, 不阻断正常调用。
async function rateLimit(env, key, limit, windowSec) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const k = "rl:" + key;
    const cur = (env && env.STATS) ? (await env.STATS.get(k)) : null;
    let arr = [];
    try { arr = cur ? JSON.parse(cur) : []; } catch { arr = []; }
    arr = arr.filter(t => now - t < windowSec);
    if (arr.length >= limit) return false;
    arr.push(now);
    await env.STATS.put(k, JSON.stringify(arr), { expirationTtl: windowSec });
    return true;
  } catch { return true; }
}

// 管理员密钥（部署后请通过 wrangler secret 设置）
// wrangler secret put ADMIN_KEY
// H-06 修复：不再使用硬编码弱默认密钥。若未通过 secret 配置，
// 则在 KV 中自动生成并持久化随机密钥，避免被攻击者利用已知默认值接管管理接口。
async function getAdminKey(env) {
  if (env && env.ADMIN_KEY) return env.ADMIN_KEY;
  try {
    const kv = env && env.STATS;
    if (kv) {
      let k = await kv.get("__admin_key_v4");
      if (!k) {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        k = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
        await kv.put("__admin_key_v4", k);
        console.warn("[worker] ADMIN_KEY 未配置，已自动生成随机密钥并存入 KV");
      }
      return k;
    }
  } catch (e) {
    console.error("[worker] getAdminKey error:", e);
  }
  // 极端情况（无 KV 也无 secret）：返回 null，管理接口将被拒绝
  return null;
}

// v4.0 版本信息
const CURRENT_VERSION = "5.0.1";
const DOWNLOAD_URL = "https://www.jyt.cc.cd/";

// 自助领取开关: false=关闭(一律转人工客服, 改回 true 并重新部署可重新开放)。
// 关闭原因(运营决策): 自助试用可无限续领且客户不接触客服/社群, 影响转化。
const SELF_ISSUE_ENABLED = false;

// ========== 管理后台页 (HTML, 由 Worker 直接返回) ==========
const ADMIN_HTML = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JYT 管理后台</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
  .wrap{max-width:1000px;margin:0 auto;padding:20px}
  h1{font-size:18px;margin:0 0 4px}
  .muted{color:#94a3b8;font-size:13px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;margin:12px 0}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
  .stat{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px}
  .stat .n{font-size:22px;font-weight:700;color:#38bdf8}
  .stat .l{font-size:12px;color:#94a3b8}
  input{width:100%;padding:10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:14px}
  button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:10px 16px;font-size:14px;cursor:pointer}
  button.ghost{background:#334155}
  button.danger{background:#dc2626}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #334155}
  th{color:#94a3b8;font-weight:500}
  .ok{color:#4ade80}.fail{color:#f87171}
  .alert{background:#7f1d1d;border:1px solid #dc2626;color:#fecaca;padding:10px 14px;border-radius:8px;margin:10px 0}
  .tabs{display:flex;gap:8px;margin:10px 0}
  .tab{padding:8px 14px;border-radius:8px;background:#1e293b;border:1px solid #334155;cursor:pointer}
  .tab.active{background:#2563eb;border-color:#2563eb}
  .hidden{display:none}
  .row{display:flex;gap:10px;align-items:center}
  code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:12px}
</style>
</head>
<body>
<script>
/* [兼容自检] 纯 ES5 实现：老浏览器(IE/360兼容/微信内置)无法运行本页现代 JS,
   此处先做特性检测 + 全局错误兜底, 直接给出可读原因, 避免“点登录没反应”。*/
(function(){
  function show(msg){
    try{
      if(document.getElementById('compatWarn')) return;
      var d=document.createElement('div');
      d.id='compatWarn';
      d.style.cssText='background:#7f1d1d;border:1px solid #dc2626;color:#fecaca;padding:12px 16px;border-radius:8px;margin:12px 0;font-size:14px;line-height:1.7';
      d.innerHTML=msg;
      var w=document.querySelector('.wrap')||document.body;
      w.insertBefore(d,w.firstChild);
    }catch(e){}
  }
  window.__jytCompatFail=function(reason){
    show('<b>【浏览器不兼容】本页在此浏览器上无法使用</b><br>'+
         '原因：'+reason+'<br>'+
         '请用 <b>Chrome 或 Edge 最新版</b> 打开（手机同理）。<br>'+
         '不要用 IE、360安全浏览器“兼容模式”、微信/QQ 内置浏览器打开。<br>'+
         '若暂时无法换浏览器，可直接使用“后台管理_终端版.bat”，功能完全一样。');
  };
  var miss=[];
  try{ if(!window.Promise) miss.push('Promise'); }catch(e){ miss.push('Promise'); }
  try{ if(!window.fetch) miss.push('fetch'); }catch(e){ miss.push('fetch'); }
  try{ if(!Object.assign) miss.push('Object.assign'); }catch(e){ miss.push('Object.assign'); }
  try{ if(!('includes' in Array.prototype)) miss.push('Array.includes'); }catch(e){ miss.push('Array.includes'); }
  try{ new Function('return async function(){await 0}')(); }catch(e){ miss.push('async/await'); }
  if(miss.length){ window.__jytCompatFail('缺少 '+miss.join('、')); }
  window.addEventListener('error',function(ev){
    var m=(ev && ev.message) ? String(ev.message) : '';
    if(/SyntaxError/i.test(m) || /Unexpected|Invalid or unexpected/i.test(m)){
      window.__jytCompatFail('脚本语法错误（'+m+'）');
    }
  },true);
})();
</script>
<div class="wrap">
  <div id="login" class="card">
    <h1>JYT 管理后台</h1>
    <p class="muted">输入 ADMIN_KEY 登录</p>
    <div class="row" style="margin-top:10px">
      <input id="key" type="password" placeholder="ADMIN_KEY">
      <button onclick="login()">登录</button>
    </div>
    <p id="lerr" class="fail" style="min-height:18px"></p>
  </div>
  <div id="dash" class="hidden">
    <div class="row" style="justify-content:space-between">
      <div><h1>控制台</h1><p class="muted" id="who"></p></div>
      <button class="ghost" onclick="logout()">退出</button>
    </div>
    <div id="alertBox"></div>
    <div class="grid" id="stats"></div>
    <div class="tabs">
      <div class="tab active" id="tdev" onclick="showTab('dev')">设备</div>
      <div class="tab" id="tlog" onclick="showTab('log')">审计日志</div>
      <div class="tab" id="tiss" onclick="showTab('iss')">已签发</div>
      <div class="tab" id="tord" onclick="showTab('ord')">订单</div>
      <div class="tab" id="tag" onclick="showTab('ag')">代理</div>
    </div>
    <div id="dev" class="card">
      <div class="row" style="justify-content:space-between">
        <strong>在线 / 已激活设备</strong>
        <button class="ghost" onclick="loadAll()">刷新</button>
      </div>
      <table id="devTable"><thead><tr><th>注册码ID</th><th>机器码</th><th>版本</th><th>首次</th><th>最近活跃</th><th>IP</th><th></th></tr></thead><tbody></tbody></table>
      <div style="margin-top:16px;padding-top:12px;border-top:1px solid #334155">
        <div class="row" style="justify-content:space-between">
          <strong>封禁名单（机器码前缀 或 ip:地址）</strong>
          <button class="ghost" onclick="loadBanned()">刷新</button>
        </div>
        <div class="row" style="margin:8px 0">
          <input id="banInput" placeholder="如 abcd123456 或 ip:1.2.3.4" style="flex:1">
          <button class="danger" onclick="banFromInput()">封禁</button>
        </div>
        <table id="banTable"><thead><tr><th>条目</th><th>加入时间</th><th>来源</th><th>原因</th><th></th></tr></thead><tbody></tbody></table>
      </div>
    </div>
    <div id="log" class="card hidden">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <strong>登录审计</strong>
        <select id="filter" onchange="renderLog()">
          <option value="all">全部</option><option value="ok">成功</option><option value="fail">失败</option>
        </select>
      </div>
      <table id="logTable"><thead><tr><th>时间</th><th>IP</th><th>注册码ID</th><th>机器码</th><th>结果</th><th>原因</th></tr></thead><tbody></tbody></table>
    </div>
    <div id="iss" class="card hidden">
      <div class="row" style="justify-content:space-between">
        <strong>已签发许可证</strong>
        <button class="ghost" onclick="loadAll()">刷新</button>
        <button class="ghost" onclick="backfillIssued()">回填台账</button>
      </div>
      <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px;margin:0 0 10px">
        <div class="row" style="flex-wrap:wrap;gap:8px">
          <input id="qMh" placeholder="机器码(32位)" style="flex:1;min-width:260px">
          <select id="qTier" style="padding:10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:14px">
            <option value="premium">专业版 premium</option>
            <option value="standard">标准版 standard</option>
            <option value="flagship">旗舰版 flagship</option>
            <option value="basic">基础版 basic</option>
            <option value="trial">试用 trial</option>
          </select>
          <input id="qDays" value="365" style="width:90px" title="有效期天数，0=永久">
          <input id="qBuyer" placeholder="客户备注(可选)" style="width:150px">
          <button onclick="manualIssue()">签发</button>
        </div>
        <div id="qOut" class="hidden" style="margin-top:8px">
          <textarea id="qLic" readonly style="width:100%;height:70px;font-family:monospace;background:#0f172a;color:#4ade80;border:1px solid #334155;border-radius:8px;padding:8px"></textarea>
          <div class="row" style="margin-top:6px"><button class="ghost" onclick="copyLic()">复制激活码</button><span id="qMsg" class="muted"></span></div>
        </div>
      </div>
      <table id="issTable"><thead><tr><th>注册码ID</th><th>客户</th><th>档位</th><th>机器码</th><th>签发时间</th><th>到期</th><th>操作</th></tr></thead><tbody></tbody></table>
    </div>
    <div id="ord" class="card hidden">
      <div class="row" style="justify-content:space-between"><strong>订单（待付款 / 已签发）</strong><button class="ghost" onclick="loadOrders()">刷新</button></div>
      <table id="ordTable"><thead><tr><th>订单号</th><th>客户</th><th>版本</th><th>机器码</th><th>代理</th><th>状态</th><th>时间</th><th>操作</th></tr></thead><tbody></tbody></table>
    </div>
    <div id="ag" class="card hidden">
      <div class="row" style="justify-content:space-between"><strong>代理归因</strong><button class="ghost" onclick="loadAgents()">刷新</button></div>
      <table id="agTable"><thead><tr><th>代理码</th><th>名称</th><th>下载</th><th>访问</th><th>激活</th><th>订单</th><th>最近</th></tr></thead><tbody></tbody></table>
      <div style="margin-top:14px;padding:12px;border:1px solid #2a3a4d;border-radius:8px;background:#0e1726">
        <div style="margin-bottom:8px;color:#68d4f0;font-weight:600">➕ 手动补记业绩（归因丢失时人工核对后补登）</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <input id="crCode" placeholder="代理码" style="width:120px;padding:6px;border-radius:6px;border:1px solid #2a3a4d;background:#0b1220;color:#e6f0fa">
          <select id="crField" style="padding:6px;border-radius:6px;border:1px solid #2a3a4d;background:#0b1220;color:#e6f0fa">
            <option value="visits">访问</option>
            <option value="downloads">下载</option>
            <option value="activations">激活</option>
            <option value="orders">订单</option>
          </select>
          <input id="crAmount" type="number" min="1" value="1" style="width:70px;padding:6px;border-radius:6px;border:1px solid #2a3a4d;background:#0b1220;color:#e6f0fa">
          <button class="btn btn-primary" style="padding:6px 14px" onclick="creditAgent()">补记</button>
          <span id="crMsg" style="color:#fbbf24;font-size:.85rem"></span>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
const API='/api/admin';
let TOKEN=localStorage.getItem('jyt_admin')||'';
// [登录健壮性] 任何接口 401 -> 清会话并退回登录页(排除 /login 自身, 避免误触发)
(function(){var _of=window.fetch;window.fetch=async function(u,o){var r=await _of.apply(this,arguments);try{if(r&&r.status===401&&String(u).indexOf('/login')<0){try{localStorage.removeItem('jyt_admin');localStorage.setItem('jyt_relogin','1');}catch(e){}location.reload();}}catch(e){}return r;};})();
function auth(h={}){return Object.assign({'X-Admin-Token':TOKEN},h);}
async function login(){
  const k=document.getElementById('key').value.trim();
  document.getElementById('lerr').textContent='';
  try{
    const r=await fetch(API+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k})});
    const j=await r.json();
    if(j.ok){TOKEN=j.token;localStorage.setItem('jyt_admin',TOKEN);enter();}
    else document.getElementById('lerr').textContent='登录失败: '+(j.error||'');
  }catch(e){document.getElementById('lerr').textContent='请求失败: '+e.message;}
}
function logout(){TOKEN='';localStorage.removeItem('jyt_admin');location.reload();}
function enter(){document.getElementById('login').classList.add('hidden');document.getElementById('dash').classList.remove('hidden');loadAll();}
function showTab(t){
  document.getElementById('tdev').classList.toggle('active',t==='dev');
  document.getElementById('tlog').classList.toggle('active',t==='log');
  document.getElementById('tiss').classList.toggle('active',t==='iss');
  document.getElementById('tord').classList.toggle('active',t==='ord');
  document.getElementById('tag').classList.toggle('active',t==='ag');
  document.getElementById('dev').classList.toggle('hidden',t!=='dev');
  document.getElementById('log').classList.toggle('hidden',t!=='log');
  document.getElementById('iss').classList.toggle('hidden',t!=='iss');
  document.getElementById('ord').classList.toggle('hidden',t!=='ord');
  document.getElementById('ag').classList.toggle('hidden',t!=='ag');
}
async function loadAll(){await stats();await devices();await logs();await issued();await loadOrders();await loadAgents();await loadBanned();}
async function stats(){
  try{
    const r=await fetch(API+'/stats',{headers:auth()});const j=await r.json();
    if(!j.ok){if(r.status===401)logout();return;}
    document.getElementById('who').textContent='已登录';
    const s=j.data;
    document.getElementById('stats').innerHTML=
      stat(s.active,'活跃设备')+stat(s.ok_today,'今日成功')+stat(s.fail_today,'今日失败')+stat(s.brute,'疑似暴力IP');
    let ab='';
    if(s.brute>0)ab='<div class="alert">[警告] 检测到 '+s.brute+' 个IP在10分钟内失败次数超过阈值，疑似暴力尝试</div>';
    document.getElementById('alertBox').innerHTML=ab;
  }catch(e){}
}
function stat(n,l){return '<div class="stat"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>';}
async function devices(){
  try{
    const r=await fetch(API+'/devices',{headers:auth()});const j=await r.json();
    if(!j.ok)return;
    const tb=document.querySelector('#devTable tbody');tb.innerHTML='';
    (j.data||[]).forEach(d=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td><code>'+(d.lid||'')+'</code></td><td>'+(d.machine||'').slice(0,12)+'...</td><td>'+(d.tier||'')+'</td><td>'+fmt(d.first_seen)+'</td><td>'+fmt(d.last_seen)+'</td><td>'+(d.ip||'')+'</td><td><button class="danger" onclick="revoke(\\''+(d.lid||'')+'\\')">吊销</button></td>';
      tb.appendChild(tr);
    });
  }catch(e){}
}
async function revoke(lid){
  if(!confirm('确认吊销 '+lid+' ？'))return;
  const r=await fetch(API+'/revoke',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:JSON.stringify({license:lid})});
  const j=await r.json();alert(j.ok?'已吊销':'失败: '+(j.error||''));loadAll();
}
async function manualIssue(){
  const mh=document.getElementById("qMh").value.trim();
  const tier=document.getElementById("qTier").value;
  const days=parseInt(document.getElementById("qDays").value||"365");
  const buyer=document.getElementById("qBuyer").value.trim();
  const msg=document.getElementById("qMsg");msg.textContent="";
  if(!mh){msg.textContent="请填写机器码";return;}
  if(!confirm("为机器码 "+mh+" 签发 "+tier+"（"+days+"天，0=永久）？"))return;
  try{
    const r=await fetch(API+"/issue",{method:"POST",headers:auth({"Content-Type":"application/json"}),body:JSON.stringify({machine_code:mh,tier:tier,days:days,buyer:buyer})});
    const j=await r.json();
    if(j.ok){
      document.getElementById("qOut").classList.remove("hidden");
      document.getElementById("qLic").value=j.license;
      document.getElementById("qMsg").textContent="已签发 lid="+j.lid+"，已登记进台账（已尝试复制）";
      try{navigator.clipboard.writeText(j.license);}catch(e){}
      issued();
    } else { msg.textContent="失败: "+(j.error||""); }
  }catch(e){msg.textContent="错误: "+e.message;}
}
function copyLic(){
  const t=document.getElementById("qLic");
  try{t.select();document.execCommand("copy");}catch(e){}
  try{navigator.clipboard.writeText(t.value);}catch(e){}
  document.getElementById("qMsg").textContent="已复制到剪贴板";
}
async function backfillIssued(){
  try{
    if(!confirm('用历史设备表补齐【已签发】台账？(只增不减，可重复执行)'))return;
    const r=await fetch(API+'/issued/backfill',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:'{}'});
    const j=await r.json();
    alert(j.ok?('回填完成：新增 '+j.added+' 条，当前共 '+j.total+' 条'):('回填失败：'+(j.error||'')));
    await issued();
  }catch(e){alert('回填请求失败: '+e);}
}
async function delIssued(lid){
  if(!confirm('确认删除签发记录 '+lid+' ？此操作不可恢复'))return;
  const r=await fetch(API+'/issued/delete',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:JSON.stringify({lid:lid})});
  const j=await r.json();alert(j.ok?'已删除':'失败: '+(j.error||''));loadAll();
}
async function logs(){
  try{
    const r=await fetch(API+'/audit?limit=300',{headers:auth()});const j=await r.json();
    if(!j.ok)return;window._log=j.data;renderLog();
  }catch(e){}
}
async function issued(){
  try{
    const r=await fetch(API+'/issued',{headers:auth()});const j=await r.json();
    if(!j.ok)return;
    const tb=document.querySelector('#issTable tbody');tb.innerHTML='';
    (j.data||[]).forEach(d=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td><code>'+(d.lid||'')+'</code></td><td>'+(d.buyer||'-')+'</td><td>'+(d.tier||'')+'</td><td>'+(d.mh||'').slice(0,12)+'...</td><td>'+fmt(d.issued_at)+'</td><td>'+fmtExp(d.exp,d.source)+'</td><td><button class="danger" onclick="delIssued(\\''+(d.lid||'')+'\\')">删除</button></td>';
      tb.appendChild(tr);
    });
  }catch(e){}
}
function fmtExp(t,src){if(!t)return src==='backfill'?'未知':'永久';try{const d=new Date(t*1000);return d.toLocaleString('zh-CN',{hour12:false});}catch(e){return String(t);}}
function renderLog(){
  const f=document.getElementById('filter').value;const arr=(window._log||[]).filter(e=>f==='all'||e.result===f);
  const tb=document.querySelector('#logTable tbody');tb.innerHTML='';
  arr.forEach(e=>{
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+fmt(e.ts)+'</td><td>'+(e.ip||'')+'</td><td><code>'+(e.lid||'')+'</code></td><td>'+(e.machine||'').slice(0,10)+'</td><td class="'+(e.result==='ok'?'ok':'fail')+'">'+(e.result==='ok'?'成功':'失败')+'</td><td>'+(e.reason||'')+'</td>';
    tb.appendChild(tr);
  });
}
async function loadOrders(){
  try{
    const r=await fetch(API+'/orders',{headers:auth()});const j=await r.json();if(!j.ok)return;
    const tb=document.querySelector('#ordTable tbody');tb.innerHTML='';
    (j.data||[]).forEach(d=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td><code>'+(d.order_id||'')+'</code></td><td>'+(d.name||d.contact||'-')+'</td><td>'+(d.tier||'')+'</td><td>'+(d.machine_code||'').slice(0,12)+'...</td><td>'+(d.agent||'-')+'</td><td>'+(d.status||'')+'</td><td>'+fmt(d.created_at)+'</td><td><button onclick="issueOrder(\\''+(d.order_id||'')+'\\',\\''+(d.machine_code||'')+'\\',\\''+(d.tier||'')+'\\')">签发</button> <button class="danger" onclick="delOrder(\\''+(d.order_id||'')+'\\')">删除</button></td>';
      tb.appendChild(tr);
    });
  }catch(e){}
}
async function issueOrder(orderId,mh,tier){
  const mc=prompt('机器码（可修改）:',mh||'');if(mc===null)return;
  const days=prompt('有效期天数（默认365）:','365')||'365';
  try{
    const r=await fetch(API+'/orders/issue',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:JSON.stringify({order_id:orderId,machine_code:mc,tier:tier,days:parseInt(days)||365})});
    const j=await r.json();
    if(j.ok){alert('激活码已生成（已尝试复制到剪贴板）：\\n'+j.license);try{navigator.clipboard.writeText(j.license);}catch(e){}loadOrders();}
    else alert('失败: '+(j.error||''));
  }catch(e){alert('错误: '+e.message);}
}
async function delOrder(orderId){
  if(!confirm('确认删除订单 '+orderId+' ？此操作不可恢复'))return;
  try{
    const r=await fetch(API+'/orders/delete',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:JSON.stringify({order_id:orderId})});
    const j=await r.json();alert(j.ok?'已删除':'失败: '+(j.error||''));loadOrders();
  }catch(e){alert('错误: '+e.message);}
}
async function loadAgents(){
  try{
    const r=await fetch(API+'/agents',{headers:auth()});const j=await r.json();if(!j.ok)return;
    const tb=document.querySelector('#agTable tbody');tb.innerHTML='';
    (j.data||[]).forEach(d=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td><code>'+(d.code||'')+'</code></td><td>'+(d.name||'-')+'</td><td>'+(d.downloads||0)+'</td><td>'+(d.visits||0)+'</td><td>'+(d.activations||0)+'</td><td>'+(d.orders||0)+'</td><td>'+(d.last_seen||'').slice(0,10)+'</td>';
      tb.appendChild(tr);
    });
  }catch(e){}
}
async function creditAgent(){
  const code=document.getElementById('crCode').value.trim();
  const field=document.getElementById('crField').value;
  const amount=parseInt(document.getElementById('crAmount').value)||0;
  const msg=document.getElementById('crMsg');
  msg.textContent='';
  if(!code){msg.textContent='请填写代理码';return;}
  if(amount<=0){msg.textContent='数量需>0';return;}
  try{
    const r=await fetch(API+'/agents/credit',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:JSON.stringify({code,field,amount})});
    const j=await r.json();
    if(j.ok){msg.textContent='已补记 '+j.added+'（'+field+' 现 '+j.total+'）';loadAgents();}
    else msg.textContent='失败: '+(j.error||'');
  }catch(e){msg.textContent='错误: '+e.message;}
}
async function loadBanned(){
  try{
    const r=await fetch(API+'/banned',{headers:auth()});const j=await r.json();if(!j.ok)return;
    const tb=document.querySelector('#banTable tbody');tb.innerHTML='';
    (j.data||[]).forEach(x=>{
      const k=(typeof x==='object')?(x.key||''):String(x||'');
      const at=(typeof x==='object'&&x.at)?fmt(x.at):'';
      const src=(typeof x==='object')?(x.source||''):'';
      const why=(typeof x==='object')?(x.reason||''):'';
      const tr=document.createElement('tr');
      tr.innerHTML='<td><code>'+k+'</code></td><td>'+at+'</td><td>'+src+'</td><td>'+why+'</td><td><button class="ghost" onclick="unban(\\''+k+'\\')">解封</button></td>';
      tb.appendChild(tr);
    });
  }catch(e){}
}
async function banFromInput(){
  const v=(document.getElementById('banInput').value||'').trim();
  if(!v){alert('请填写机器码或 ip:地址');return;}
  await banMachine(v);
}
async function banMachine(k0){
  let k=k0;
  if(!k){k=prompt('要封禁的机器码（或 ip:1.2.3.4）:');}
  if(!k)return;
  if(!confirm('确认封禁 '+k+' ？该机器将无法通过任何授权校验'))return;
  try{
    const r=await fetch(API+'/ban',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:JSON.stringify({key:k,reason:'manual'})});
    const j=await r.json();alert(j.ok?'已封禁':'失败: '+(j.error||''));loadAll();
  }catch(e){alert('错误: '+e.message);}
}
async function unban(k){
  if(!confirm('确认解封 '+k+' ？'))return;
  try{
    const r=await fetch(API+'/unban',{method:'POST',headers:auth({'Content-Type':'application/json'}),body:JSON.stringify({key:k})});
    const j=await r.json();alert(j.ok?'已解封':'失败: '+(j.error||''));loadAll();
  }catch(e){alert('错误: '+e.message);}
}
function fmt(t){if(!t)return'';const d=new Date(t);return d.toLocaleString('zh-CN',{hour12:false});}
(function(){try{if(localStorage.getItem('jyt_relogin')==='1'){localStorage.removeItem('jyt_relogin');var _e=document.getElementById('lerr');if(_e)_e.textContent='会话已过期，请重新登录';var _k=document.getElementById('key');if(_k)_k.value='';}}catch(e){}})();
if(TOKEN)enter();
</script>
</body></html>`;

// ========== 工具函数 ==========
function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
    .replace(/-----END [A-Z0-9 ]+-----/g, '')
    .replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function importRsaKey() {
  const keyData = pemToArrayBuffer(RSA_PUB_KEY_PEM);
  return await crypto.subtle.importKey(
    'spki', keyData,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']
  );
}

async function rsaVerify(payloadBytes, sigBytes) {
  try {
    const key = await importRsaKey();
    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key, sigBytes, payloadBytes
    );
  } catch (e) {
    return false;
  }
}

function b64decode(str) {
  const binary = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function jsonSafeStringify(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// 生成短期令牌（HMAC签名，密钥为ADMIN_KEY）
async function generateToken(payload, secret) {
  const payloadStr = JSON.stringify(payload);
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payloadStr));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return btoa(payloadStr) + '.' + sigB64;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const payloadStr = atob(parts[0]);
    const sigBytes = b64decode(parts[1]);
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payloadStr));
    if (!valid) return null;
    return JSON.parse(payloadStr);
  } catch { return null; }
}

// ========== 激活签发（服务端用私钥签名；私钥仅来自 env.PRIVATE_KEY 密钥，绝不进仓库/前端） ==========
// 格式严格对齐 zmjyzcm/gen_license.py: payload={mh,tier,exp,lid,gen}, JSON(ASCII) -> base64 -> RSASSA-PKCS1-v1_5(SHA-256) 签名
// 注意：WebCrypto importKey 仅支持 PKCS#8 私钥，请用 `wrangler secret put PRIVATE_KEY` 填入 PKCS#8 PEM。
async function signLicense(payload, env) {
  const pem = env && env.PRIVATE_KEY;
  if (!pem) throw new Error("PRIVATE_KEY 未配置：请执行 `wrangler secret put PRIVATE_KEY` 填入 RSA 私钥(PKCS#8 PEM)");
  const keyData = pemToArrayBuffer(pem);
  const key = await crypto.subtle.importKey(
    "pkcs8", keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const jsonStr = JSON.stringify(payload); // 值为 ASCII，与 gen_license.py 输出逐字节一致
  const data = new TextEncoder().encode(jsonStr);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
  const payloadB64 = btoa(jsonStr);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return payloadB64 + "." + sigB64;
}

// P0-1(可选): 可复现的 server_secret = HMAC(SERVER_SECRET_KEY, lid|mh|当日) 前 32 位十六进制。
// 仅当配置了独立的 SERVER_SECRET_KEY 时才下发(显式启用, 默认关闭 -> 对现有客户零影响);
// 未配置返回空串, 客户端 `d.get("server_secret") or None` 视为无 -> 走原有纯机器码密钥。
// 注意: 一旦启用, 客户端会用该值派生金库密钥并在下次落盘时改写金库 -> 之后不宜撤下该 secret。
async function genServerSecret(env, lid, mh) {
  const ssKey = env && env.SERVER_SECRET_KEY;
  if (!ssKey) return "";
  try {
    const day = new Date().toISOString().slice(0, 10); // YYYY-MM-DD, 每日轮换
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(ssKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(lid + "|" + mh + "|" + day));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
  } catch (e) {
    console.error("[genServerSecret]", e);
    return "";
  }
}

// P1-1: 由档位推导服务端权限视图, 作为时间锚票据下发的 perms。
// 客户端 get_perm() 会对本地签名权限取交集(布尔与、数值取小) -> 服务端只能收权, 不能越权升级。
// 口径与客户端 _build_perm 完全一致; 不含 daban/daban_manual -> 不会误伤旗舰隐藏功能。
function permsForTier(tier) {
  const isPaid = tier === "premium" || tier === "standard" || tier === "flagship";
  return {
    can_trade: tier !== "trial",
    cond_order: tier === "premium" || tier === "flagship",
    risk_control: tier === "premium" || tier === "flagship",
    max_buys: isPaid ? 999999 : (tier === "basic" ? 10 : 0),
    max_shares: isPaid ? 999999 : (tier === "basic" ? 1000 : 0),
  };
}

// 时间锚专用签发: 与激活私钥(PRIVATE_KEY, 严格离线)隔离, 使用独立的 TIME_TICKET_PRIVATE_KEY。
// 仅签发 {iat, lid, mh} 时间锚票据, 客户端用内置的专用公钥(_RSA_PUB_TT)验签。
// 即便该密钥泄露, 也绝无法伪造激活授权(激活私钥始终离线), 符合最小权限。
async function signTimeTicket(payload, env) {
  const pem = env && env.TIME_TICKET_PRIVATE_KEY;
  if (!pem) throw new Error("TIME_TICKET_PRIVATE_KEY 未配置：请执行 `wrangler secret put TIME_TICKET_PRIVATE_KEY` 填入 RSA 私钥(PKCS#8 PEM)");
  const keyData = pemToArrayBuffer(pem);
  const key = await crypto.subtle.importKey(
    "pkcs8", keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const jsonStr = JSON.stringify(payload);
  const data = new TextEncoder().encode(jsonStr);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
  const payloadB64 = btoa(jsonStr);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return payloadB64 + "." + sigB64;
}

async function buildLicense(machineCode, tier, expireDays, env) {
  const now = Math.floor(Date.now() / 1000);
  const exp = expireDays > 0 ? now + expireDays * 86400 : 0;
  const payload = {
    mh: machineCode,
    tier: tier,
    exp: exp,
    lid: "L" + now.toString(16).toUpperCase(),
    gen: now,
  };
  const license = await signLicense(payload, env);
  return { license, payload, exp };
}

// 记录签发（写入已签发库 + 活跃集合）
async function recordIssued(env, license, info) {
  try {
    if (!env || !env.STATS) return;
    // 解析 payload 提取真实 lid(原实现取 payload base64 前缀, 与 verify 侧的真实 lid 不一致, 导致账本/活跃集键错乱)
    let realLid = "";
    try {
      const p = String(license || "").split(".");
      if (p.length === 2) {
        const pl = JSON.parse(atob(p[0]));
        realLid = pl.lid || pl.auth_id || "";
      }
    } catch {}
    const rec = Object.assign({
      lid: realLid || String(license || "").split(".")[0].slice(0, 50),
      issued_at: new Date().toISOString(),
    }, info);
    const arr = JSON.parse(await env.STATS.get("issued_licenses") || "[]");
    if (!arr.find(x => x.lid === rec.lid)) {
      arr.unshift(rec);
      await env.STATS.put("issued_licenses", JSON.stringify(arr));
    }
    const as = JSON.parse(await env.STATS.get("active_license_set") || "[]");
    if (!as.includes(rec.lid)) {
      as.push(rec.lid);
      await env.STATS.put("active_license_set", JSON.stringify(as));
      await env.STATS.put("active_licenses", String(as.length));
    }
  } catch (e) { console.error("[recordIssued]", e); }
}

// ========== 代理归因（KV） ==========
async function touchAgent(env, code, field) {
  try {
    const kv = env && env.STATS;
    if (!kv || !code) return;
    code = String(code).slice(0, 40);
    let set = [];
    try { set = JSON.parse(await kv.get("agent_set") || "[]"); } catch {}
    if (!set.includes(code)) { set.push(code); await kv.put("agent_set", JSON.stringify(set)); }
    if (field) {
      const cur = parseInt(await kv.get("agent:" + code + ":" + field) || "0") || 0;
      await kv.put("agent:" + code + ":" + field, String(cur + 1));
    }
    const info = JSON.parse(await kv.get("agent:" + code) || "null") || { code };
    info.code = code;
    info.last_seen = new Date().toISOString();
    await kv.put("agent:" + code, JSON.stringify(info));
  } catch (e) { console.error("[agent]", e); }
}

// H-07 修复：限制跨域来源，避免任意站点调用
const ALLOWED_ORIGIN = "https://www.jyt.cc.cd";

const CORS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-License, X-Machine",
};

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" }
  });
}

// ========== 实时行情 (代理腾讯/新浪, 解决浏览器直连 CORS) ==========
const INDEX_CODES = [
  ["sh000001", "sz"], // 上证指数
  ["sz399001", "sc"], // 深证成指
  ["sz399006", "cy"], // 创业板指
  ["sh000688", "kc"], // 科创50
];
let _idxCache = { ts: 0, data: null };
async function getMarketIndices() {
  const now = Date.now();
  if (_idxCache.data && now - _idxCache.ts < 15000) return _idxCache.data; // 15s 缓存
  const symbols = INDEX_CODES.map(c => c[0]).join(",");
  const dec = new TextDecoder("gb18030");
  let data = {};
  // 1) 腾讯行情 (格式清晰: f[3]=当前, f[4]=昨收)
  try {
    const r = await fetch("https://qt.gtimg.cn/q=" + symbols, {
      headers: { "User-Agent": "Mozilla/5.0", "Referer": "https://gu.qq.com/" }
    });
    const txt = dec.decode(await r.arrayBuffer());
    for (const [code, key] of INDEX_CODES) {
      const m = txt.match(new RegExp("v_" + code + '="([^"]*)"'));
      if (m) {
        const f = m[1].split("~");
        const cur = parseFloat(f[3]);
        const prev = parseFloat(f[4]);
        const chg = prev ? (cur - prev) / prev * 100 : 0;
        data[key] = { name: f[1], value: cur, change: chg };
      }
    }
  } catch (e) { console.error("[index] tencent fail:", e); }
  // 2) 新浪兜底
  if (Object.keys(data).length < 4) {
    try {
      const r2 = await fetch("https://hq.sinajs.cn/list=" + symbols, {
        headers: { "User-Agent": "Mozilla/5.0", "Referer": "https://finance.sina.com.cn/" }
      });
      const txt2 = dec.decode(await r2.arrayBuffer());
      for (const [code, key] of INDEX_CODES) {
        if (data[key]) continue;
        const m = txt2.match(new RegExp("hq_str_" + code + '="([^"]*)"'));
        if (m) {
          const f = m[1].split(",");
          // 新浪字段: [0]=名称 [1]=今开 [2]=昨收 [3]=现价。原实现把 f[1](今开) 当现价,
          // 导致新浪兜底时指数"当前值"实为开盘价, 涨跌幅算错。
          const cur = parseFloat(f[3]);
          const prev = parseFloat(f[2]);
          const chg = prev ? (cur - prev) / prev * 100 : 0;
          data[key] = { name: f[0], value: cur, change: chg };
        }
      }
    } catch (e) { console.error("[index] sina fail:", e); }
  }
  if (Object.keys(data).length > 0) { _idxCache = { ts: now, data }; }
  return data;
}

// 安全 JSON 解析: 防御 UTF-8 BOM / 前导空白 / 解析异常 (BOM 静默致命, 曾致 loyal_machines 白名单从 8/27 起完全失效)
function safeJSON(raw, def) {
  try {
    if (raw == null) return def;
    let s = String(raw);
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    return JSON.parse(s);
  } catch (e) { return def; }
}

// 老客户白名单 (长期/年费授权自动登记, 后台可导出复核; 白名单内机器豁免清扫)
async function addLoyal(env, mh, lid, tier) {
  try {
    if (!env || !env.STATS || !mh) return;
    const arr = safeJSON(await env.STATS.get("loyal_machines"), []);
    if (!arr.some(x => x.mh === mh)) {
      arr.push({ mh, lid: lid || "", tier: tier || "", ts: Date.now() });
      await env.STATS.put("loyal_machines", JSON.stringify(arr));
    }
  } catch (e) { console.error("[loyal-add]", e); }
}
async function isLoyal(env, mh) {
  try {
    if (!env || !env.STATS || !mh) return false;
    const arr = safeJSON(await env.STATS.get("loyal_machines"), []);
    return arr.some(x => x.mh === mh);
  } catch { return false; }
}

// 排除清单: KV ignore_machines 中的机器码不记设备/不计活跃(自测机不污染后台清单)
async function isMachineIgnored(env, mh) {
  try {
    if (!env || !env.STATS || !mh) return false;
    const list = JSON.parse(await env.STATS.get("ignore_machines") || "[]");
    // 过滤空串/空值: 空串会导致 startsWith("") 恒为 true, 把所有机器都判成"忽略",
    // 进而设备不登记、活跃数不更新、后台设备页全部被过滤隐藏 —— 这就是"后台看不到数据"的根因之一。
    return list.some(x => !!x && String(mh).startsWith(x));
  } catch { return false; }
}

// ========== 封禁名单 (KV: banned_machines) ==========
// 条目支持两种：机器码前缀(如 "abcd123456") 或 IP 精确值(如 "ip:1.2.3.4")；
// 也兼容 {key,at,source,reason} 对象形式。命中即无条件拒绝，客户端会锁定并退出。
async function getBanned(env) {
  try { return JSON.parse(await (env && env.STATS ? env.STATS.get("banned_machines") : "[]") || "[]") || []; }
  catch { return []; }
}
function banKeyOf(x) { return (x && typeof x === "object") ? String(x.key || "") : String(x || ""); }
function matchBanned(list, machineCode, ip) {
  try {
    const m = String(machineCode || ""), i = String(ip || "");
    return (list || []).some(x => {
      const k = banKeyOf(x).trim();
      if (!k) return false;
      if (k.slice(0, 3) === "ip:") return !!i && i === k.slice(3);
      return !!m && m.startsWith(k);
    });
  } catch { return false; }
}
async function isBanned(env, machineCode, ip) {
  return matchBanned(await getBanned(env), machineCode, ip);
}
async function banAdd(env, key, source, reason) {
  try {
    const k = String(key || "").trim();
    if (!k || !(env && env.STATS)) return false;
    const list = await getBanned(env);
    if (list.some(x => banKeyOf(x) === k)) return false;
    list.push({ key: k, at: Date.now(), source: source || "", reason: reason || "" });
    await env.STATS.put("banned_machines", JSON.stringify(list));
    return true;
  } catch (e) { console.error("[banAdd]", e); return false; }
}

// ========== 软警告名单 (KV: warned_machines) ==========
// 与 banned_machines 平行: 命中只「标记 + 下发警告」(response.warn), 不锁客户端。
// 客户端(新构建)可据此展示非阻塞警告横幅; 旧构建忽略该字段(向后兼容)。
async function getWarned(env) {
  try { return JSON.parse(await (env && env.STATS ? env.STATS.get("warned_machines") : "[]") || "[]") || []; }
  catch { return []; }
}
async function isWarned(env, machineCode, ip) {
  return matchBanned(await getWarned(env), machineCode, ip);
}
async function warnAdd(env, key, source, reason) {
  try {
    const k = String(key || "").trim();
    if (!k || !(env && env.STATS)) return false;
    const list = await getWarned(env);
    if (list.some(x => banKeyOf(x) === k)) return false;
    list.push({ key: k, at: Date.now(), source: source || "", reason: reason || "" });
    await env.STATS.put("warned_machines", JSON.stringify(list));
    return true;
  } catch (e) { console.error("[warnAdd]", e); return false; }
}
async function warnRemove(env, key) {
  try {
    const k = String(key || "").trim();
    if (!k || !(env && env.STATS)) return false;
    const list = await getWarned(env);
    const nx = list.filter(x => banKeyOf(x) !== k);
    if (nx.length === list.length) return false;
    await env.STATS.put("warned_machines", JSON.stringify(nx));
    return true;
  } catch (e) { console.error("[warnRemove]", e); return false; }
}

// ========== 防降级封杀 (KV: ver_floor) ==========
// 记录每台机器"实际用过的最高构建号"。一旦用过新版本, 旧版本再联网一律 403,
// 彻底堵死"拿新授权回滚到旧漏洞版"的漏洞。升级本身不强制(见 min_build 软提示);
// 只有"用过新版再回退"才封杀。排除清单(自测机)不参与, 避免开发自测被锁死。
function verToInt(v) {
  try {
    const _s = String(v == null ? "" : v).trim();
    if (!_s) return -1;
    if (/^\d+$/.test(_s)) return parseInt(_s, 10);
    let _m = _s.match(/^final-(\d+)$/i); if (_m) return parseInt(_m[1], 10);
    _m = _s.match(/^(\d+)\s*\+\s*(\d+)$/); if (_m) return parseInt(_m[1], 10) + parseInt(_m[2], 10);
    return -1;
  } catch (e) { return -1; }
}
async function verFloorGet(env, machineCode) {
  try {
    const _m = JSON.parse((await env.STATS.get("ver_floor")) || "{}");
    return parseInt(_m[String(machineCode || "")] || 0, 10) || 0;
  } catch (e) { return 0; }
}
async function verFloorBump(env, machineCode, verStr) {
  try {
    const _n = verToInt(verStr);
    const _k = String(machineCode || "");
    if (_n < 0 || !_k || !(env && env.STATS)) return false;
    if (await isMachineIgnored(env, _k)) return false;
    const _m = JSON.parse((await env.STATS.get("ver_floor")) || "{}");
    if ((parseInt(_m[_k] || 0, 10) || 0) >= _n) return false;
    _m[_k] = _n;
    await env.STATS.put("ver_floor", JSON.stringify(_m));
    return true;
  } catch (e) { return false; }
}
// 返回 >0 = 已用过更高版本(需至少该构建号) -> 降级拒绝; 0 = 放行
async function verFloorBlocked(env, machineCode, verStr) {
  try {
    const _k = String(machineCode || "");
    if (!_k) return 0;
    if (await isMachineIgnored(env, _k)) return 0;
    const _fl = await verFloorGet(env, _k);
    if (_fl <= 0) return 0;
    const _n = verToInt(verStr);
    if (_n < 0) return 0;
    return (_n < _fl) ? _fl : 0;
  } catch (e) { return 0; }
}
// ========== 全局清退闸门 (KV: kill_build) ==========
// 默认留空 = 不生效(老客户可继续用旧版, 只提示升级, 不硬封)。
// 设成 "final-7" 后: 所有低于该构建号的客户端一律 403 硬封, 必须升级才能用。
// 用途: 新版发布稳定运行一段时间后, 后台一键彻底清退旧版/漏洞版。
// 排除清单(自测机)不参与, 免得开发自测被锁死。
async function killBuildGet(env) {
  try { if (env && env.STATS) return ((await env.STATS.get("kill_build")) || "").trim(); } catch (e) {}
  return "";
}
async function killBuildHit(env, machineCode, verStr) {
  try {
    const _kb = await killBuildGet(env);
    if (!_kb) return "";
    const _k = String(machineCode || "");
    if (_k && await isMachineIgnored(env, _k)) return "";
    const _n = verToInt(verStr);
    const _kn = verToInt(_kb);
    if (_n < 0 || _kn < 0) return "";
    return (_n < _kn) ? _kb : "";
  } catch (e) { return ""; }
}
// ========== 自动封禁 ==========
// 只针对"伪造/无效授权"类失败；expired / not_longterm / machine_mismatch 等正常商业状态一律不计。
const _AB_REASONS = ["invalid_token", "signature_invalid", "invalid_payload"];
// 由 logAudit 统一驱动：result==="ok" 清零；命中 _AB_REASONS 才累计。
async function autoBanTick(env, entry) {
  try {
    const kv = env && env.STATS;
    if (!kv || !entry) return;
    const mh = String(entry.machine || "").trim();
    if (!mh) return;
    const key = "failw:" + mh;
    if (String(entry.result || "") === "ok") {
      try { await kv.delete(key); } catch {}
      return;
    }
    if (_AB_REASONS.indexOf(String(entry.reason || "")) < 0) return;
    let thr = 40;
    try { const t = parseInt(await kv.get("auto_ban_threshold") || "", 10); if (t > 0) thr = t; } catch {}
    if (thr <= 0) return;   // 阈值<=0 = 关闭自动封禁
    const now = Date.now(), win = 24 * 3600 * 1000;
    let rec = { t: [] };
    try { rec = JSON.parse(await kv.get(key) || "null") || rec; } catch {}
    rec.t = (rec.t || []).filter(x => now - x < win);
    // 5 分钟去重：避免被高频伪造请求放大 KV 写入
    if (rec.t.length && now - rec.t[rec.t.length - 1] < 300000) return;
    rec.t.push(now);
    await kv.put(key, JSON.stringify(rec), { expirationTtl: 3 * 24 * 3600 });
    if (rec.t.length >= thr) await banAdd(env, mh, "auto", "fail_" + entry.reason + "x" + rec.t.length);
  } catch (e) { console.error("[autoBanTick]", e); }
}

// ========== 审计 & 设备注册表 (KV) ==========
async function logAudit(env, entry) {
  try {
    const kv = env && env.STATS;
    if (!kv) return;
    // [排除清单] 自测机不写审计日志, 也不参与自动封禁统计(避免自己的机器被误封)
    if (entry && entry.machine && await isMachineIgnored(env, entry.machine)) return;
    let arr = [];
    try { arr = JSON.parse(await kv.get("audit_log") || "[]"); } catch {}
    arr.unshift(entry);
    if (arr.length > 2000) arr = arr.slice(0, 2000);
    await kv.put("audit_log", JSON.stringify(arr));
    await autoBanTick(env, entry);   // 自动封禁：同一机器码反复"伪造/无效授权"尝试 -> 达阈值自动封禁
  } catch (e) { console.error("[audit]", e); }
}

// [2026-09-14] 未登记授权观察清单：验签通过但从未经 register 推送登记的授权码。
// 用途：识别非法/来源不明的账户（如私钥历史泄露后被伪造、旧注册机流出等）。
// 只记录，不影响放行（放行由 RSA 验签决定）。
async function recordUnregistered(env, info) {
  try {
    if (!env || !env.STATS || !info || !info.lid) return;
    const kv = env.STATS;
    let map = {};
    try { map = JSON.parse(await kv.get("unregistered_hits") || "{}"); } catch { map = {}; }
    const cur = map[info.lid];
    map[info.lid] = {
      lid: info.lid,
      tier: info.tier || "",
      mh: info.mh || "",
      ip: info.ip || "",
      exp: Number(info.exp || 0),
      first_seen: cur ? cur.first_seen : Date.now(),
      last_seen: Date.now(),
      count: (cur ? Number(cur.count || 0) : 0) + 1,
    };
    // 上限保护：最多保留 2000 条，超量丢弃最旧的
    const ks = Object.keys(map);
    if (ks.length > 2000) {
      ks.sort((a, b) => (map[a].last_seen || 0) - (map[b].last_seen || 0));
      for (let i = 0; i < ks.length - 2000; i++) delete map[ks[i]];
    }
    await kv.put("unregistered_hits", JSON.stringify(map));
  } catch (e) { console.error("[unregistered]", e); }
}

async function touchDevice(env, info) {
  try {
    const kv = env && env.STATS;
    if (!kv) return;
    let map = {};
    try { map = JSON.parse(await kv.get("devices") || "{}"); } catch {}
    const lid = info.lid;
    const now = Date.now();
    if (!map[lid]) {
      map[lid] = { lid, machine: info.machine, tier: info.tier, first_seen: now, count: 0, ip: info.ip };
    }
    map[lid].last_seen = now;
    map[lid].machine = info.machine || map[lid].machine;
    map[lid].tier = info.tier || map[lid].tier;
    map[lid].ip = info.ip || map[lid].ip;
    map[lid].count = (map[lid].count || 0) + 1;
    await kv.put("devices", JSON.stringify(map));
  } catch (e) { console.error("[device]", e); }
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP")
      || (request.headers.get("x-forwarded-for") || "").split(",")[0].trim()
      || "unknown";
}

// 管理员会话：接受 X-API-Key(原始密钥) 或 X-Admin-Token(登录后会话)
async function isAdmin(request, env) {
  const adminKey = await getAdminKey(env);
  if (!adminKey) return false;
  const apiKey = request.headers.get("X-API-Key") || "";
  if (apiKey && apiKey === adminKey) return true;
  const token = request.headers.get("X-Admin-Token") || "";
  if (token) {
    const p = await verifyToken(token, adminKey);
    if (p && p.admin) return true;
  }
  return false;
}

// ========== 主处理 ==========
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---------- 腾讯(QQ/微信)网站安全验证文件 ----------
    // 申诉"QQ/微信内打开被拦截"时, 腾讯要求在网站根目录放置该 TXT 校验所有权。
    // 仅对这一个精确路径 early-return, 其它路径(含 /api/* 全部业务)完全不受影响。
    if (path === "/60627da6ede98243d045634efe4bbaf7.txt") {
      return new Response("e1e4f4fce1d58565d73d87125165730a3ce9daef", {
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    // ---------- 裸域名 jyt.cc.cd -> 统一 301 到 www ----------
    // [2026-09-13] 裸域名此前没有 DNS 记录, 在 QQ/微信/浏览器里打开就是"网页无法打开"
    // (不是被拦截, 是根本解析不了)。现把裸域名作为本 Worker 的自定义域名接入,
    // Cloudflare 会自动补 DNS 记录并签发证书; 这里把它整体 301 到 www, 保证:
    //   1) 只有一套正式站点(www), 不会两套域名各自缓存/证书/备案不一致;
    //   2) 上面的验证 TXT 已 early-return, 仍以 200 直出, 腾讯校验不受重定向影响。
    if (url.hostname === "jyt.cc.cd") {
      return Response.redirect("https://www.jyt.cc.cd" + path + url.search, 301);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    const adminKey = await getAdminKey(env);

    // ---------- 版本检查 ----------
    if (path === "/api/version") {
      // 读取强制更新标记
      let forceUpdate = "0";
      try {
        if (env && env.STATS) {
          forceUpdate = (await env.STATS.get("force_update")) || "0";
        }
      } catch {}
      return jsonResp({
        version: CURRENT_VERSION,
        url: DOWNLOAD_URL,
        force_update: forceUpdate === "1"
      });
    }

    // ---------- 健康检查 ----------
    if (path === "/api/health") {
      return jsonResp({ status: "ok", version: CURRENT_VERSION });
    }

    // ---------- 实时行情 ----------
    if (path === "/api/index") {
      try {
        const data = await getMarketIndices();
        return jsonResp({ ok: true, updated: Date.now(), indices: data });
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 统计 ----------
    if (path === "/api/stats") {
      const visits = (await env?.STATS?.get("visits")) || "0";
      const downloads = (await env?.STATS?.get("downloads")) || "0";
      const activeLicenses = (await env?.STATS?.get("active_licenses")) || "0";
      return jsonResp({
        visits: parseInt(visits), downloads: parseInt(downloads),
        active_licenses: parseInt(activeLicenses)
      });
    }

    // ---------- 访问/下载统计（含代理归因） ----------
    if (path === "/api/track" && request.method === "POST") {
      try {
        const body = await request.json();
        const type = body.type;
        const agent = (body.agent || "").toString().trim().slice(0, 40);
        if (type === "visit" || type === "download") {
          const cur = await env?.STATS?.get(type === "visit" ? "visits" : "downloads") || "0";
          const n = (parseInt(cur) || 0) + 1;
          await env?.STATS?.put(type === "visit" ? "visits" : "downloads", String(n));
          if (agent) ctx.waitUntil(touchAgent(env, agent, type === "visit" ? "visits" : "downloads"));
          return jsonResp({ ok: true, count: n });
        }
        return jsonResp({ ok: false, error: "unknown type" }, 400);
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 许可证验证（核心） ----------
    if (path === "/api/verify" && request.method === "POST") {
      const _ip = clientIp(request);
      const _log = (lid, machine, result, reason) =>
        ctx.waitUntil(logAudit(env, { ts: new Date().toISOString(), ip: _ip, lid: lid || "", machine: machine || "", result, reason }));
      try {
        const body = await request.json();
        const licenseKey = body.license || "";
        const machineCode = body.machine_code || "";

        // [封禁闸门: 最高优先级] 命中 banned_machines -> 直接拒绝(客户端会锁定并退出)
        if (await isBanned(env, machineCode, _ip)) {
          _log("", machineCode, "fail", "banned");
          return jsonResp({ ok: false, error: "banned", banned: true }, 403);
        }
        const _warnMsg = await isWarned(env, machineCode, _ip) ? "您的机器存在异常登录行为，已被系统标记，请联系客服核实(www.jyt.cc.cd)。" : null;

        if (!licenseKey || !machineCode) {
          _log("", machineCode, "fail", "missing_params");
          return jsonResp({ ok: false, error: "missing parameters" }, 400);
        }

        // 终结版版本闸门已移到【RSA 验签之后】, 改用已验签的 payload.ver(反伪造),
        // 见下方签名验证通过后的 _gate_version()。这里不再用客户端上报的 body.ver。
        const dotIdx = licenseKey.lastIndexOf(".");
        if (dotIdx < 0) {
          _log("", machineCode, "fail", "invalid_format");
          return jsonResp({ ok: false, error: "invalid format" }, 400);
        }

        const payloadB64 = licenseKey.substring(0, dotIdx);
        const sigB64 = licenseKey.substring(dotIdx + 1);

        let payloadStr, payload;
        try {
          payloadStr = atob(payloadB64);
          payload = JSON.parse(payloadStr);
        } catch {
          _log("", machineCode, "fail", "invalid_payload");
          return jsonResp({ ok: false, error: "invalid payload" }, 400);
        }

        // 3b. 换机授权(transfer): 不绑定固定机器, 由服务端按 auth_id 维持唯一在线机器
        const isTransfer = !!(payload.transfer || payload.dv);
        const authId = isTransfer ? (payload.auth_id || payload.lid || "") : "";
        if (isTransfer && !authId) {
          _log("", machineCode, "fail", "transfer_no_auth");
          return jsonResp({ ok: false, error: "transfer license missing auth_id" }, 400);
        }

        // 2. RSA签名验证
        const sigBytes = b64decode(sigB64);
        const payloadBytes = new TextEncoder().encode(payloadStr);
        const sigValid = await rsaVerify(payloadBytes, sigBytes);
        if (!sigValid) {
          _log(payload.lid || "", machineCode, "fail", "signature_invalid");
          return jsonResp({ ok: false, error: "signature invalid" }, 403);
        }

        // ===== 版本闸门(已验签 payload, 反伪造) =====
        // 优先用已验签的 payload.ver(随机拆分的构建号,decodeLicVer 求和还原);
        // 老授权无 ver 字段则回退客户端上报 body.ver(兼容旧客户, 不强改登录)。
        let _upgradeNotice = false;
        let _graceUntil = 0;
        {
          let _minBuild = "final-6";
          try {
            if (env && env.STATS) { const _kv = (await env.STATS.get("min_build")) || ""; if (_kv) _minBuild = _kv; }
          } catch {}
          const _real = decodeLicVer(payload);
          const _clientVer = (_real >= 0) ? ("final-" + _real) : ((body.ver || "").toString().trim());
          // 防降级封杀: 以"客户端实际上报的构建号" body.ver 为准。
          // 不能用 payload.ver(授权码里的构建号): 那只代表"签发时对应版本",
          // 挡不住"拿新签发的授权码 + 旧版客户端"回滚的漏洞。
          const _bodyVer = (body.ver || "").toString().trim();
          { const _fl = await verFloorBlocked(env, machineCode, _bodyVer);
            if (_fl > 0) {
              _log("", machineCode, "fail", "version_outdated");
              return jsonResp({ ok: false, error: "version_outdated", reason: "downgrade_blocked", min_required: "final-" + _fl }, 403);
            } }
          // 全局清退闸门: 低于 kill_build 一律硬封
          { const _kb = await killBuildHit(env, machineCode, _bodyVer);
            if (_kb) {
              _log("", machineCode, "fail", "version_outdated");
              return jsonResp({ ok: false, error: "version_outdated", reason: "build_retired", min_required: _kb }, 403);
            } }
          if (_minBuild) {
            if (!_clientVer) {
              return jsonResp({ ok: false, error: "license revoked", reason: "version_outdated" }, 403);
            }
            if (!buildAtLeast(_clientVer, _minBuild)) {
              // 【老客户不受影响】版本号低于 min_build 只算"提示升级", 绝不硬停用/强制重激活。
              // 是否真正"下线(非法/短期/非试用)" 由下方 6g 授权类型闸门(永久/年费/试用 放行, 其余判非法)决定。
              _upgradeNotice = true;
              try { const _g = parseInt(await env.STATS.get("min_build_grace_until") || "0", 10) || 0; _graceUntil = _g; } catch {}
            }
          }
        }

        // 3. 机器码绑定验证
        const licenseMh = payload.mh || payload.machine_id || "";
        if (!isTransfer && licenseMh && licenseMh !== machineCode) {
          _log(payload.lid || "", machineCode, "fail", "machine_mismatch");
          return jsonResp({ ok: false, error: "machine mismatch" }, 403);
        }

        // 4. 过期检查
        const exp = payload.exp || 0;
        const now = Math.floor(Date.now() / 1000);
        if (exp > 0 && now > exp) {
          _log(payload.lid || "", machineCode, "fail", "expired");
          return jsonResp({ ok: false, error: "license expired" }, 403);
        }

        // 5. 吊销检查（KV存储）
        const lid = isTransfer ? authId : (payload.lid || payload.machine_id?.substring(0, 16) || "");
        let revoked = false;
        try {
          if (env && env.STATS) {
            const revokedList = await env.STATS.get("revoked_licenses") || "[]";
            const revokedArr = JSON.parse(revokedList);
            // M-05 修复：仅按 lid 前缀精确匹配，移除易被滥用的子串包含匹配
            revoked = revokedArr.some(r => lid.startsWith(r));
          }
        } catch {}
        if (revoked) {
          _log(lid, machineCode, "fail", "revoked");
          return jsonResp({ ok: false, error: "license revoked" }, 403);
        }

        // 6c. 试用码"一码一机一版"校验: 每个【版本】仅可试用一次/机器(专业版、标准版各一次, 互不冲突,
        //     便于客户对比两个版本后决定购买; 同版本二次试用则拒绝)。记录首次试用的 lid;
        //     同一试用(同 lid)再次在线校验放行; 换一个同版本的全新试用码(不同 lid)则拒绝。
        //     即使客户删本地 license/标记文件也绕不过(服务端按 机器码+版本 记)。
        if (payload.trial === 1) {
          try {
            if (env && env.STATS) {
              const trialKey = "trial:" + machineCode + ":" + (payload.tier || "trial");
              const hadLid = await env.STATS.get(trialKey);
              const thisLid = payload.lid || "";
              if (hadLid && hadLid !== thisLid) {
                _log(lid, machineCode, "fail", "already_trialed");
                return jsonResp({ ok: false, error: "already_trialed (该机器已使用过此版本的试用码，无法再次试用)" }, 403);
              }
              if (!hadLid && thisLid) {
                await env.STATS.put(trialKey, thisLid);
              }
            }
          } catch (e) { console.error("[trial-check]", e); }
        }

        // 6g. 合法性判定: 白名单豁免 + 一年/永久/试用 放行, 其余(短期付费)判非法 not_longterm。
        //     - 试用码(trial===1): 由 6c 试用逻辑承担, 合法;
        //     - 老客户白名单(loyal_machines)内机器: 豁免, 直接放行(不卡天数);
        //     - 永久(exp==0): 放行; 一年授权(exp-gen >= 360天): 放行并登记白名单;
        //     - 其余(非一年非试用): 拒绝 -> 非法, 可吊销。
        try {
          if (payload.trial !== 1) {
            const _loyal = await isLoyal(env, machineCode);
            if (!_loyal) {
              const _gen = payload.gen || 0;
              const _exp = payload.exp || 0;
              const _isPermanent = _exp === 0;
              const _isYear = _exp > 0 && _gen > 0 && (_exp - _gen) >= 360 * 86400;
              if (!_isPermanent && !_isYear) {
                _log(lid, machineCode, "fail", "not_longterm");
                return jsonResp({ ok: false, error: "not_longterm (非一年/非试用授权, 判非法)" }, 403);
              }
              await addLoyal(env, machineCode, lid, tier);   // 一年/永久 登记老客户白名单
            }
          }
        } catch (e) { console.error("[longterm-check]", e); }

        // 6b. 换机授权: 已废弃旧机器(machineCode 在作废集合中) -> 拒绝重新激活,
        //     杜绝"两台机器来回转移绑定"薅授权(原实现只在 verify_token 校验, 激活接口可反复重绑)。
        if (isTransfer) {
          try {
            if (env && env.STATS) {
              let rmh0 = [];
              try { rmh0 = JSON.parse(await env.STATS.get("transfer_revoked_mh") || "[]"); } catch {}
              if (rmh0.includes(machineCode)) {
                _log(authId, machineCode, "fail", "machine_revoked");
                return jsonResp({ ok: false, error: "machine revoked (该机器已被转移替换)" }, 403);
              }
            }
          } catch (e) { console.error("[transfer-check]", e); }
        }
        if (isTransfer) {
          try {
            if (env && env.STATS) {
              const prev = await env.STATS.get("transfer_binding:" + authId);
              if (prev && prev !== machineCode) {
                let rmh = [];
                try { rmh = JSON.parse(await env.STATS.get("transfer_revoked_mh") || "[]"); } catch {}
                if (!rmh.includes(prev)) {
                  rmh.push(prev);
                  await env.STATS.put("transfer_revoked_mh", JSON.stringify(rmh));
                }
              }
              await env.STATS.put("transfer_binding:" + authId, machineCode);
            }
          } catch (e) { console.error("[transfer]", e); }
        }

        // 6. 生成短期令牌（7天有效）
        // 安全加固: 缺 tier 字段时默认 trial(最低权限), 与客户端一致, 严禁默认 premium 防止越权。
        const tier = payload.tier || payload.version || "trial";
        const tokenPayload = {
          lid: lid,
          tier: tier,
          mh: machineCode,
          iat: now,
          exp: now + 7 * 86400,  // 7天有效
          perms: {
            can_trade: tier !== "trial",
            cond_order: tier === "premium" || tier === "flagship",
            max_buys: (tier === "premium" || tier === "standard" || tier === "flagship") ? 999999 : (tier === "basic" ? 10 : 0),
            max_shares: (tier === "premium" || tier === "standard" || tier === "flagship") ? 999999 : (tier === "basic" ? 1000 : 0),
          }
        };

        const token = await generateToken(tokenPayload, adminKey);

        // 7. 设备注册表 + 审计 + 活跃计数(排除清单内的机器不登记, 避免自测记录污染后台)
        const _ignored = await isMachineIgnored(env, machineCode);
        _log(lid, machineCode, "ok", "verified");
        if (!_ignored) {
          await touchDevice(env, { lid, machine: machineCode, tier, ip: _ip });
          try {
            if (env && env.STATS) {
              const activeSet = JSON.parse(await env.STATS.get("active_license_set") || "[]");
              if (!activeSet.includes(lid)) {
                activeSet.push(lid);
                await env.STATS.put("active_license_set", JSON.stringify(activeSet));
                await env.STATS.put("active_licenses", String(activeSet.length));
              }
            }
          } catch {}
        }

        // [2026-09-14 安全整改] 台账只做"补正已登记授权"，不再把未知授权码自动登记为合法。
        //   未登记的授权码写入 unregistered_hits 供后台核查（识别非法/来源不明的账户）；
        //   放行逻辑完全不受影响 —— 判定仍只依赖 RSA 验签，不会误伤正常客户。
        try {
          if (env && env.STATS && lid && !_ignored) {
            const _iss = JSON.parse(await env.STATS.get("issued_licenses") || "[]");
            const _ex = _iss.find(x => x && x.lid === lid);
            if (_ex) {
              // 已存在(多为 backfill 写入, exp 恒为 0) -> 用授权码内真实 payload.exp 补正
              let _ch = false;
              if (payload.exp && Number(payload.exp) > 0 && Number(_ex.exp || 0) !== Number(payload.exp)) { _ex.exp = Number(payload.exp); _ch = true; }
              if (!_ex.tier && tier) { _ex.tier = tier; _ch = true; }
              if (!_ex.mh && machineCode) { _ex.mh = machineCode; _ch = true; }
              if (_ch) await env.STATS.put("issued_licenses", JSON.stringify(_iss.slice(-2000)));
            } else {
              // 未登记: 不自动登记为合法, 记入待核查清单(用于识别非法/来源不明账户)
              await recordUnregistered(env, { lid, tier, mh: machineCode,
                ip: (typeof _ip !== "undefined" ? _ip : ""), exp: payload.exp || 0 });
              }
          }
        } catch (e) { console.error("[issued:register]", e); }

        // 时间锚票据: 服务端独立私钥签名 {iat, lid, mh}, 客户端用内置专用公钥验签(不可伪造)。
        let timeTicket = "";
        try {
          timeTicket = await signTimeTicket({
            iat: now, lid: lid, mh: machineCode,
            ver: (payload.ver != null ? String(payload.ver) : ((body.ver || "").toString().trim())) || "",
            cap: 1, perms: tokenPayload.perms,
          }, env);
        } catch (e) {
          console.error("[time_ticket:verify]", e);
        }
        await verFloorBump(env, machineCode, body.ver);
        const serverSecret = await genServerSecret(env, lid, machineCode);
        return jsonResp({
          ok: true,
          upgrade_notice: _upgradeNotice,      // 宽限期内 => 客户端弹"请升级新版本"
          grace_until: _graceUntil,            // 宽限期截止时间戳(0=无)
          data: {
            token: token,
            tier: tier,
            lid: lid,
            exp: tokenPayload.exp,
            perms: tokenPayload.perms,
            server_secret: serverSecret,
            time_ticket: timeTicket, warn: _warnMsg,           // 服务端RSA签名时间锚(空串=签发失败, 客户端回退旧行为)
          }
        });

      } catch (e) {
        _log("", "", "fail", "exception:" + e.message);
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 24小时能力票据（客户端离线宽限的最终依据） ----------
    // 与 /api/verify 同源校验(签名/机器码/过期/吊销), 但颁发的是 24h 短命票据。
    // 客户端离线超过 24 小时拿不到新票据 -> 交易功能锁定, 联网刷新即恢复。
    if (path === "/api/ticket" && request.method === "POST") {
      const _ip = clientIp(request);
      const _log = (lid, machine, result, reason) =>
        ctx.waitUntil(logAudit(env, { ts: new Date().toISOString(), ip: _ip, lid: lid || "", machine: machine || "", result, reason }));
      try {
        const body = await request.json();
        const licenseKey = body.license || "";
        const machineCode = body.machine_code || "";

        // [封禁闸门] 命中 banned_machines -> 直接拒绝
        if (await isBanned(env, machineCode, _ip)) {
          _log("", machineCode, "fail", "banned");
          return jsonResp({ ok: false, error: "banned", banned: true }, 403);
        }
        const _warnMsg = await isWarned(env, machineCode, _ip) ? "您的机器存在异常登录行为，已被系统标记，请联系客服核实(www.jyt.cc.cd)。" : null;

        if (!licenseKey || !machineCode) {
          _log("", machineCode, "fail", "missing_params");
          return jsonResp({ ok: false, error: "missing parameters" }, 400);
        }

        // 终结版版本闸门(与 /api/verify 同口径: 数值 >= 放行, 避免误锁比自己更新的合法构建)
        let _minBuild = "";
        try { if (env && env.STATS) _minBuild = (await env.STATS.get("min_build")) || ""; } catch {}
        const _clientVer = (body.ver || "").toString().trim();
        // 防降级封杀: 本机已用过更高版本 -> 旧版本一律拒绝(与 min_build 是否设置无关)
        { const _fl = await verFloorBlocked(env, machineCode, _clientVer);
          if (_fl > 0) {
            _log("", machineCode, "fail", "version_outdated");
            return jsonResp({ ok: false, error: "version_outdated", reason: "downgrade_blocked", min_required: "final-" + _fl }, 403);
          } }
        // 全局清退闸门: 低于 kill_build 一律硬封
        { const _kb = await killBuildHit(env, machineCode, _clientVer);
          if (_kb) {
            _log("", machineCode, "fail", "version_outdated");
            return jsonResp({ ok: false, error: "version_outdated", reason: "build_retired", min_required: _kb }, 403);
          } }
        if (_minBuild) {
          // [2026-09-11 放宽] 缺 ver 不再吊销：老版客户端可能不上报 ver，会误杀"我签发的合法客户"。
          // 仅当客户端明确上报了 ver 且低于 min_build 时，才提示版本过旧。
          if (_clientVer && !buildAtLeast(_clientVer, _minBuild)) {
            return jsonResp({ ok: false, error: "version_outdated", min_build: _minBuild }, 403);
          }
        }

        const dotIdx = licenseKey.lastIndexOf(".");
        if (dotIdx < 0) {
          _log("", machineCode, "fail", "invalid_format");
          return jsonResp({ ok: false, error: "invalid format" }, 400);
        }
        const payloadB64 = licenseKey.substring(0, dotIdx);
        const sigB64 = licenseKey.substring(dotIdx + 1);

        let payloadStr, payload;
        try {
          payloadStr = atob(payloadB64);
          payload = JSON.parse(payloadStr);
        } catch {
          _log("", machineCode, "fail", "invalid_payload");
          return jsonResp({ ok: false, error: "invalid payload" }, 400);
        }

        // RSA 签名验证
        const sigBytes = b64decode(sigB64);
        const payloadBytes = new TextEncoder().encode(payloadStr);
        const sigValid = await rsaVerify(payloadBytes, sigBytes);
        if (!sigValid) {
          _log(payload.lid || "", machineCode, "fail", "signature_invalid");
          return jsonResp({ ok: false, error: "signature invalid" }, 403);
        }

        // 机器码绑定(换机版 transfer 由服务端绑定管理, 此处同 /api/verify 口径)
        const isTransfer = !!(payload.transfer || payload.dv);
        const licenseMh = payload.mh || payload.machine_id || "";
        if (!isTransfer && licenseMh && licenseMh !== machineCode) {
          _log(payload.lid || "", machineCode, "fail", "machine_mismatch");
          return jsonResp({ ok: false, error: "machine mismatch" }, 403);
        }

        // 过期检查
        const exp = payload.exp || 0;
        const now = Math.floor(Date.now() / 1000);
        if (exp > 0 && now > exp) {
          _log(payload.lid || "", machineCode, "fail", "expired");
          return jsonResp({ ok: false, error: "license expired" }, 403);
        }

        // 吊销检查
        const lid = isTransfer ? (payload.auth_id || payload.lid || "") : (payload.lid || "");
        let revoked = false;
        try {
          if (env && env.STATS) {
            const revokedList = await env.STATS.get("revoked_licenses") || "[]";
            const revokedArr = JSON.parse(revokedList);
            revoked = revokedArr.some(r => lid.startsWith(r));
          }
        } catch {}
        if (revoked) {
          _log(lid, machineCode, "fail", "revoked");
          return jsonResp({ ok: false, error: "license revoked" }, 403);
        }

        // 换机授权: 已作废旧机器拒绝发票
        if (isTransfer) {
          try {
            if (env && env.STATS) {
              let rmh0 = [];
              try { rmh0 = JSON.parse(await env.STATS.get("transfer_revoked_mh") || "[]"); } catch {}
              if (rmh0.includes(machineCode)) {
                _log(lid, machineCode, "fail", "machine_revoked");
                return jsonResp({ ok: false, error: "machine revoked (该机器已被转移替换)" }, 403);
              }
            }
          } catch (e) { console.error("[ticket-transfer]", e); }
        }

        // 颁发 24 小时能力票据(HMAC, 密钥=adminKey, 与令牌同源)
        const tier = payload.tier || payload.version || "trial";
        const tktPayload = { lid, tier, mh: machineCode, iat: now, exp: now + 86400, cap: 1 };
        const ticket = await generateToken(tktPayload, adminKey);

        // P0-2 补全: 与 /api/verify 同源下发 RSA 签名的时间锚票据(客户端用内置 _RSA_PUB_TT 验签)。
        let timeTicket = "";
        try {
          timeTicket = await signTimeTicket({
            iat: now, lid: lid, mh: machineCode,
            ver: (payload.ver != null ? String(payload.ver) : ((body.ver || "").toString().trim())) || "",
            cap: 1, perms: permsForTier(tier),
          }, env);
        } catch (e) {
          console.error("[time_ticket:ticket]", e);
        }
        const serverSecret = await genServerSecret(env, lid, machineCode);

        // 审计 + 设备活跃(排除清单内机器不登记)
        _log(lid, machineCode, "ok", "ticket");
        if (!(await isMachineIgnored(env, machineCode))) {
          await touchDevice(env, { lid, machine: machineCode, tier, ip: _ip });
        }

        await verFloorBump(env, machineCode, body.ver);
        return jsonResp({ ok: true, data: { ticket, exp: tktPayload.exp, tier, lid, server_secret: serverSecret, time_ticket: timeTicket, warn: _warnMsg } });
      } catch (e) {
        _log("", "", "fail", "exception:" + e.message);
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 令牌验证（客户端定期调用） ----------
    if (path === "/api/verify_token" && request.method === "POST") {
      const _ip = clientIp(request);
      const _log = (lid, machine, result, reason) =>
        ctx.waitUntil(logAudit(env, { ts: new Date().toISOString(), ip: _ip, lid: lid || "", machine: machine || "", result, reason }));
      try {
        const body = await request.json();
        const token = body.token || "";
        const machineCode = body.machine_code || "";

        // [封禁闸门] 命中 banned_machines -> 直接拒绝(这就是堵住"反复刷验证"的那一类机器)
        if (await isBanned(env, machineCode, _ip)) {
          _log("", machineCode, "fail", "banned");
          return jsonResp({ ok: false, error: "banned", banned: true }, 403);
        }
        const _warnMsg = await isWarned(env, machineCode, _ip) ? "您的机器存在异常登录行为，已被系统标记，请联系客服核实(www.jyt.cc.cd)。" : null;

        if (!token) {
          _log("", machineCode, "fail", "missing_token");
          return jsonResp({ ok: false, error: "missing token" }, 400);
        }

        // 终结版版本闸门(与 /api/verify 同口径: 数值 >= 放行, 避免误锁比自己更新的合法构建)
        let _minBuild = "";
        try { if (env && env.STATS) _minBuild = (await env.STATS.get("min_build")) || ""; } catch {}
        const _clientVer = (body.ver || "").toString().trim();
        // 防降级封杀: 本机已用过更高版本 -> 旧版本一律拒绝(与 min_build 是否设置无关)
        { const _fl = await verFloorBlocked(env, machineCode, _clientVer);
          if (_fl > 0) {
            _log("", machineCode, "fail", "version_outdated");
            return jsonResp({ ok: false, error: "version_outdated", reason: "downgrade_blocked", min_required: "final-" + _fl }, 403);
          } }
        // 全局清退闸门: 低于 kill_build 一律硬封
        { const _kb = await killBuildHit(env, machineCode, _clientVer);
          if (_kb) {
            _log("", machineCode, "fail", "version_outdated");
            return jsonResp({ ok: false, error: "version_outdated", reason: "build_retired", min_required: _kb }, 403);
          } }
        if (_minBuild) {
          // [2026-09-11 放宽] 缺 ver 不再吊销：老版客户端可能不上报 ver，会误杀"我签发的合法客户"。
          // 仅当客户端明确上报了 ver 且低于 min_build 时，才提示版本过旧。
          if (_clientVer && !buildAtLeast(_clientVer, _minBuild)) {
            return jsonResp({ ok: false, error: "version_outdated", min_build: _minBuild }, 403);
          }
        }

        const payload = await verifyToken(token, adminKey);
        if (!payload) {
          _log("", machineCode, "fail", "invalid_token");
          return jsonResp({ ok: false, error: "invalid token" }, 403);
        }

        // 检查机器码
        if (payload.mh && payload.mh !== machineCode) {
          _log(payload.lid || "", machineCode, "fail", "machine_mismatch");
          return jsonResp({ ok: false, error: "machine mismatch" }, 403);
        }

        // 换机授权: 被替换的旧机器(其 machine_code 在 transfer_revoked_mh 中) -> 吊销
        let mhRevoked = false;
        try {
          if (env && env.STATS) {
            const rmh = JSON.parse(await env.STATS.get("transfer_revoked_mh") || "[]");
            if (rmh.includes(machineCode)) mhRevoked = true;
          }
        } catch {}
        if (mhRevoked) {
          _log(payload.lid || "", machineCode, "fail", "transfer_revoked");
          return jsonResp({ ok: false, error: "license revoked" }, 403);
        }

        // 检查过期
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && now > payload.exp) {
          _log(payload.lid || "", machineCode, "fail", "token_expired");
          return jsonResp({ ok: false, error: "token expired" }, 403);
        }

        // 检查吊销
        let revoked = false;
        try {
          if (env && env.STATS) {
            const revokedList = await env.STATS.get("revoked_licenses") || "[]";
            const revokedArr = JSON.parse(revokedList);
            revoked = revokedArr.some(r => (payload.lid || "").startsWith(r));
          }
        } catch {}
        if (revoked) {
          _log(payload.lid || "", machineCode, "fail", "revoked");
          return jsonResp({ ok: false, error: "license revoked" }, 403);
        }

        // 成功：刷新设备最近活跃时间（用于"在线设备"; 排除清单内的机器不登记）
        if (!(await isMachineIgnored(env, machineCode))) {
          await touchDevice(env, { lid: payload.lid || "", machine: machineCode, tier: payload.tier, ip: _ip });
        }
        _log(payload.lid || "", machineCode, "ok", "token_ok");

        // 时间锚票据(与 /api/verify 同源): 服务端RSA签名 {iat, lid, mh}, 客户端用内置公钥验签。
        let timeTicket = "";
        try {
          timeTicket = await signTimeTicket({
            iat: now, lid: payload.lid || "", mh: machineCode,
            ver: (payload.ver != null ? String(payload.ver) : "") || "",
            cap: 1, perms: payload.perms || permsForTier(payload.tier || "trial"),
          }, env);
        } catch (e) {
          console.error("[time_ticket:verify_token]", e);
        }
        await verFloorBump(env, machineCode, body.ver);
        const serverSecret = await genServerSecret(env, payload.lid || "", machineCode);
        return jsonResp({
          ok: true,
          data: {
            tier: payload.tier,
            lid: payload.lid,
            exp: payload.exp,
            perms: payload.perms,
            server_secret: serverSecret,
            time_ticket: timeTicket, warn: _warnMsg,
          }
        });

      } catch (e) {
        _log("", "", "fail", "exception:" + e.message);
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 吊销许可证 ----------
    if (path === "/api/revoke" && request.method === "POST") {
      const apiKey = request.headers.get("X-API-Key") || "";
      if (!adminKey) {
        return jsonResp({ ok: false, error: "admin key not configured" }, 503);
      }
      if (apiKey !== adminKey) {
        return jsonResp({ ok: false, error: "unauthorized" }, 401);
      }
      try {
        const body = await request.json();
        const lid = (body.license || body.lid || "").substring(0, 50);
        if (!lid) {
          return jsonResp({ ok: false, error: "missing license id" }, 400);
        }
        // 存储到KV
        if (env && env.STATS) {
          const revokedList = await env.STATS.get("revoked_licenses") || "[]";
          const revokedArr = JSON.parse(revokedList);
          if (!revokedArr.includes(lid)) {
            revokedArr.push(lid);
            await env.STATS.put("revoked_licenses", JSON.stringify(revokedArr));
          }
          // 从活跃列表移除
          const activeSet = JSON.parse(await env.STATS.get("active_license_set") || "[]");
          const newSet = activeSet.filter(l => !l.startsWith(lid));
          await env.STATS.put("active_license_set", JSON.stringify(newSet));
          await env.STATS.put("active_licenses", String(newSet.length));
        }
        return jsonResp({ ok: true, msg: "revoked", lid: lid });
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 撤销吊销（管理员自愈: 误吊销的码一键恢复, 与 /api/revoke 同前缀语义对称） ----------
    if (path === "/api/admin/unrevoke" && request.method === "POST") {
      const apiKey = request.headers.get("X-API-Key") || "";
      if (!adminKey) {
        return jsonResp({ ok: false, error: "admin key not configured" }, 503);
      }
      if (apiKey !== adminKey) {
        return jsonResp({ ok: false, error: "unauthorized" }, 401);
      }
      try {
        const body = await request.json();
        const lid = (body.license || body.lid || "").substring(0, 50);
        if (!lid) {
          return jsonResp({ ok: false, error: "missing license id" }, 400);
        }
        if (env && env.STATS) {
          const revokedList = await env.STATS.get("revoked_licenses") || "[]";
          let revokedArr = [];
          try { revokedArr = JSON.parse(revokedList); } catch { revokedArr = []; }
          revokedArr = revokedArr.filter(r => r !== lid && !r.startsWith(lid));
          await env.STATS.put("revoked_licenses", JSON.stringify(revokedArr));
        }
        return jsonResp({ ok: true, msg: "unrevoked", lid: lid });
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 终结版版本闸门开关（管理员设置最低客户端版本） ----------
    // body.build 为客户端上报的 ver 值(如 "final-1"); 传空串=关闭闸门。
    if (path === "/api/admin/min_build" && request.method === "POST") {
      const apiKey = request.headers.get("X-API-Key") || "";
      if (!adminKey) {
        return jsonResp({ ok: false, error: "admin key not configured" }, 503);
      }
      if (apiKey !== adminKey) {
        return jsonResp({ ok: false, error: "unauthorized" }, 401);
      }
      try {
        const body = await request.json();
        const build = (body.build || "").toString().trim().substring(0, 40);
        if (env && env.STATS) {
          await env.STATS.put("min_build", build);
        }
        return jsonResp({ ok: true, min_build: build });
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 强制更新开关 ----------
    if (path === "/api/force_update" && request.method === "POST") {
      const apiKey = request.headers.get("X-API-Key") || "";
      if (!adminKey) {
        return jsonResp({ ok: false, error: "admin key not configured" }, 503);
      }
      if (apiKey !== adminKey) {
        return jsonResp({ ok: false, error: "unauthorized" }, 401);
      }
      try {
        const body = await request.json();
        const force = body.force ? "1" : "0";
        if (env && env.STATS) {
          await env.STATS.put("force_update", force);
        }
        return jsonResp({ ok: true, force_update: force === "1" });
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 生成许可证（仅管理员） ----------
    if (path === "/api/generate" && request.method === "POST") {
      const apiKey = request.headers.get("X-API-Key") || "";
      if (!adminKey) {
        return jsonResp({ ok: false, error: "admin key not configured" }, 503);
      }
      if (apiKey !== adminKey) {
        return jsonResp({ ok: false, error: "unauthorized" }, 401);
      }
      try {
        const body = await request.json();
        // 注意：此端点仅返回待签名的payload，实际签名需要私钥（不在Worker中）
        // 私钥应保存在安全的离线环境中
        const payload = {
          lid: body.lid || ("LID-" + Date.now().toString(36)),
          mh: body.machine_code || "",
          tier: body.tier || "premium",
          exp: body.exp || 0,
          iat: Math.floor(Date.now() / 1000),
        };
        const payloadB64 = btoa(JSON.stringify(payload));
        // 登记签发记录（已签发数据库）
        try {
          if (env && env.STATS) {
            const rec = {
              lid: payload.lid, mh: payload.mh, tier: payload.tier,
              exp: payload.exp, buyer: body.buyer || "", note: body.note || "",
              issued_at: new Date().toISOString()
            };
            const arr = JSON.parse(await env.STATS.get("issued_licenses") || "[]");
            if (!arr.find(x => x.lid === rec.lid)) {
              arr.unshift(rec);
              await env.STATS.put("issued_licenses", JSON.stringify(arr));
            }
          }
        } catch (e) {}
        return jsonResp({
          ok: true,
          payload: payload,
          payload_b64: payloadB64,
          note: "使用私钥对此payload_b64进行RSA-SHA256签名，然后拼接为 payload_b64.signature_b64"
        });
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 手工签发记录上报（本地注册机签码后上报, 进入后台"已签发"清单） ----------
    if (path === "/api/issued/record" && request.method === "POST") {
      const apiKey = request.headers.get("X-API-Key") || "";
      if (!adminKey) {
        return jsonResp({ ok: false, error: "admin key not configured" }, 503);
      }
      if (apiKey !== adminKey) {
        return jsonResp({ ok: false, error: "unauthorized" }, 401);
      }
      try {
        const body = await request.json().catch(() => ({}));
        const lid = (body.lid || "").toString().trim().slice(0, 50);
        const mh = (body.mh || "").toString().trim();
        if (!lid || !mh) return jsonResp({ ok: false, error: "missing lid/mh" }, 400);
        // 排除清单内的机器(自测机)不入"已签发"清单
        if (await isMachineIgnored(env, mh)) {
          return jsonResp({ ok: true, msg: "ignored", lid: lid });
        }
        const rec = {
          lid: lid,
          mh: mh,
          tier: (body.tier || "").toString().trim(),
          exp: parseInt(body.exp || "0") || 0,
          buyer: (body.customer || "").toString().trim(),
          note: (body.source || "").toString().trim(),
          issued_at: (body.ts || "").toString().trim() || new Date().toISOString(),
        };
        if (env && env.STATS) {
          const arr = JSON.parse(await env.STATS.get("issued_licenses") || "[]");
          if (!arr.find(x => x.lid === rec.lid)) {
            arr.unshift(rec);
            await env.STATS.put("issued_licenses", JSON.stringify(arr));
          }
        }
        return jsonResp({ ok: true, msg: "recorded", lid: lid });
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 代理申请（生成推广链接） ----------
    if (path === "/api/agent/apply" && request.method === "POST") {
      try {
        const body = await request.json().catch(() => ({}));
        const code = (body.code || "").toString().trim().slice(0, 40);
        if (!code) return jsonResp({ ok: false, error: "missing agent code" }, 400);
        if (env?.STATS) {
          let set = [];
          try { set = JSON.parse(await env.STATS.get("agent_set") || "[]"); } catch {}
          if (!set.includes(code)) set.push(code);
          await env.STATS.put("agent_set", JSON.stringify(set));
          const info = JSON.parse(await env.STATS.get("agent:" + code) || "{}");
          info.code = code;
          info.name = body.name || info.name || "";
          info.contact = body.contact || info.contact || "";
          info.applied_at = new Date().toISOString();
          await env.STATS.put("agent:" + code, JSON.stringify(info));
        }
        const promo = (new URL(request.url).origin) + "/?ref=" + encodeURIComponent(code);
        return jsonResp({ ok: true, code, promo_url: promo });
      } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
    }

    // ---------- 在线领取激活码（客户自助；SELF_ISSUE_ENABLED=false 时关闭） ----------
    if (path === "/api/issue" && request.method === "POST") {
      if (!SELF_ISSUE_ENABLED) {
        return jsonResp({ ok: false, error: "自助领取已关闭，请添加客服QQ 290144665 人工领取试用或购买激活码" }, 403);
      }
      try {
        const body = await request.json().catch(() => ({}));
        const machineCode = (body.machine_code || "").toString().trim();
        const tier = (body.tier || "trial").toString().trim();
        const agent = (body.agent || "").toString().trim().slice(0, 40);
        const days = parseInt(body.days || "0") || 0;
        if (!machineCode) return jsonResp({ ok: false, error: "请填写机器码" }, 400);
        // 机器码格式校验: 客户端 mh = sha256 hex 前 32 位。明显非法的值直接拒绝,
        // 防止垃圾数据写入 KV / 误签发无主试用码。
        if (!/^[0-9a-fA-F]{32}$/.test(machineCode)) {
          return jsonResp({ ok: false, error: "机器码格式不正确(应为32位十六进制, 请从软件激活对话框复制)" }, 400);
        }
        const PAID = ["basic", "standard", "premium"];
        if (!PAID.includes(tier) && tier !== "trial") return jsonResp({ ok: false, error: "未知版本" }, 400);
        if (agent) ctx.waitUntil(touchAgent(env, agent, "activations"));
        // 体验试用：即时签发"7天免费试用高级版"（premium 等级 + 7天过期），无需付款
        // exe 端按 payload.tier 给权限: premium=全功能+条件单; exp 过期即自动收回。
        // 安全: 每台机器限领一次试用, 防止同一机器反复白嫖(改机器码仍可绕过, 属最低成本风控)。
        if (tier === "trial") {
          // [2026-09-14 安全整改] 签发私钥已下线，服务端不再具备签发能力。
          // 试用码同样改由本地注册机离线签发后发放；此处显式拦截，避免开关被打开后抛出难懂的 500。
          if (!(env && env.PRIVATE_KEY)) {
            return jsonResp({ ok: false, error: "server_signing_disabled",
              msg: "服务端签发已停用（私钥已下线）。试用码请由本地注册机离线签发后发放。" }, 410);
          }
          if (env && env.STATS) {
            try {
              const tKey = "trial:" + machineCode;
              const had = await env.STATS.get(tKey);
              if (had) {
                return jsonResp({ ok: false, error: "该机器码已领取过免费试用, 如需继续使用请购买正式版" }, 403);
              }
            } catch (e) { console.error("[trial-check]", e); }
          }
          const expDays = days > 0 ? days : 7;
          const { license, exp } = await buildLicense(machineCode, "premium", expDays, env);
          if (env && env.STATS) { try { await env.STATS.put("trial:" + machineCode, String(exp)); } catch (e) {} }
          await recordIssued(env, license, { mh: machineCode, tier: "premium", exp, agent, buyer: machineCode, order_id: "", trial: true });
          return jsonResp({ ok: true, license, tier: "premium", exp, trial: true });
        }
        // 付费版：先建订单（待付款），由管理员收款后签发，避免白嫖
        const orderId = "O" + Date.now().toString(36).toUpperCase();
        if (env?.STATS) {
          const orders = JSON.parse(await env.STATS.get("orders") || "[]");
          orders.unshift({
            order_id: orderId, name: body.name || "", contact: body.contact || "",
            tier, machine_code: machineCode, agent,
            status: "pending", created_at: new Date().toISOString(),
            pay_hint: "添加客服QQ 290144665 并提供订单号 " + orderId + " 与机器码完成付款",
          });
          await env.STATS.put("orders", JSON.stringify(orders));
          if (agent) await touchAgent(env, agent, "orders");
        }
        return jsonResp({
          ok: true, need_pay: true, order_id: orderId, tier,
          pay_hint: "已生成订单 " + orderId + "，请添加客服QQ 290144665 完成付款，并提供机器码与订单号，客服确认后为您签发激活码。",
          qq: "290144665",
        });
      } catch (e) {
        // 私钥未配置等情况给出明确提示
        const msg = (e && e.message) || String(e);
        return jsonResp({ ok: false, error: msg }, 500);
      }
    }

    // ---------- 购买下单 ----------
    if (path === "/api/order" && request.method === "POST") {
      try {
        const body = await request.json().catch(() => ({}));
        const tier = (body.tier || "premium").toString().trim();
        const agent = (body.agent || "").toString().trim().slice(0, 40);
        const name = (body.name || "").toString().trim();
        const contact = (body.contact || "").toString().trim();
        const machineCode = (body.machine_code || "").toString().trim();
        const TIERS = { basic: "体验版", standard: "标准版", premium: "专业版" };
        if (!TIERS[tier]) return jsonResp({ ok: false, error: "未知版本" }, 400);
        const orderId = "O" + Date.now().toString(36).toUpperCase();
        if (agent) ctx.waitUntil(touchAgent(env, agent, "orders"));
        if (env?.STATS) {
          const orders = JSON.parse(await env.STATS.get("orders") || "[]");
          orders.unshift({
            order_id: orderId, name, contact, tier, machine_code: machineCode, agent,
            status: "pending", created_at: new Date().toISOString(),
            pay_hint: "添加客服QQ 290144665 并提供订单号 " + orderId + " 完成付款",
          });
          await env.STATS.put("orders", JSON.stringify(orders));
        }
        return jsonResp({
          ok: true, order_id: orderId, tier,
          pay_hint: "已生成订单 " + orderId + "（" + TIERS[tier] + "），请添加客服QQ 290144665 完成付款，客服将为您签发激活码。",
          qq: "290144665",
        });
      } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
    }

    // ---------- 管理后台：登录（无需先鉴权，用原始 ADMIN_KEY） ----------
    if (path === "/api/admin/login" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const key = body.key || "";
      const _ip = clientIp(request);
      // IP 级限流: 300 秒内超过 5 次失败尝试即拒绝(抵御暴力爆破)
      if (!(await rateLimit(env, "admin_login:" + _ip, 5, 300))) {
        return jsonResp({ ok: false, error: "too many attempts, try later" }, 429);
      }
      const ak = await getAdminKey(env);
      if (key && ak && key === ak) {
        const token = await generateToken(
          { admin: true, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 7200 },
          ak
        );
        return jsonResp({ ok: true, token });
      }
      return jsonResp({ ok: false, error: "invalid key" }, 401);
    }

    // ---------- 管理后台：其余接口（需登录会话） ----------
    if (path.startsWith("/api/admin/")) {
      const authed = await isAdmin(request, env);
      if (!authed) return jsonResp({ ok: false, error: "unauthorized" }, 401);

      // 封禁名单：查看
      if (path === "/api/admin/banned") {
        const arr = await getBanned(env);
        return jsonResp({ ok: true, data: arr });
      }

      // 封禁名单：添加（key = 机器码前缀 或 ip:<addr>）
      if (path === "/api/admin/ban" && request.method === "POST") {
        try {
          const body = await request.json().catch(() => ({}));
          const key = (body.key || body.machine || "").toString().trim();
          if (!key) return jsonResp({ ok: false, error: "缺少 key" }, 400);
          const reason = (body.reason || "manual").toString().trim().slice(0, 60);
          const ok = await banAdd(env, key, "manual", reason);
          return jsonResp({ ok: true, key: key, added: ok });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }

      // 封禁名单：移除（解封）
      if (path === "/api/admin/unban" && request.method === "POST") {
        try {
          const body = await request.json().catch(() => ({}));
          const key = (body.key || "").toString().trim();
          if (!key) return jsonResp({ ok: false, error: "缺少 key" }, 400);
          const list = await getBanned(env);
          const nx = list.filter(x => banKeyOf(x) !== key);
          if (env && env.STATS) await env.STATS.put("banned_machines", JSON.stringify(nx));
          return jsonResp({ ok: true, key: key, removed: list.length - nx.length });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }

      // 防降级台账: 查看 / 清空(运维用)
      if (path === "/api/admin/ver_floor") {
        try {
          const _m = JSON.parse((await env.STATS.get("ver_floor")) || "{}");
          return jsonResp({ ok: true, data: _m });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }
      if (path === "/api/admin/ver_floor/clear" && request.method === "POST") {
        try {
          await env.STATS.put("ver_floor", "{}");
          return jsonResp({ ok: true, cleared: true });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }
      // 全局清退闸门: 查看 / 设置(value 留空 = 关闭硬封)
      if (path === "/api/admin/kill_build") {
        try {
          return jsonResp({ ok: true, kill_build: await killBuildGet(env), current: CURRENT_VERSION });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }
      if (path === "/api/admin/kill_build/set" && request.method === "POST") {
        try {
          let _v = "";
          try { const _b = await request.json(); _v = String((_b && _b.value) || "").trim(); } catch (e) {}
          await env.STATS.put("kill_build", _v);
          return jsonResp({ ok: true, kill_build: _v });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }
      // 软警告名单：列表
      if (path === "/api/admin/warned") {
        const arr = await getWarned(env);
        return jsonResp({ ok: true, data: arr });
      }
      // 软警告名单：添加（key = 机器码前缀 或 ip:<addr>）
      if (path === "/api/admin/warn" && request.method === "POST") {
        try {
          const body = await request.json().catch(() => ({}));
          const key = (body.key || body.machine || "").toString().trim();
          if (!key) return jsonResp({ ok: false, error: "缺少 key" }, 400);
          const reason = (body.reason || "manual").toString().trim().slice(0, 60);
          const ok = await warnAdd(env, key, "manual", reason);
          return jsonResp({ ok: true, key: key, added: ok });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }
      // 软警告名单：移除（解警告）
      if (path === "/api/admin/unwarn" && request.method === "POST") {
        try {
          const body = await request.json().catch(() => ({}));
          const key = (body.key || "").toString().trim();
          if (!key) return jsonResp({ ok: false, error: "缺少 key" }, 400);
          const ok = await warnRemove(env, key);
          return jsonResp({ ok: true, key: key, removed: ok ? 1 : 0 });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }

      // 设备（在线/已激活注册码; 排除清单内的机器不显示）
      if (path === "/api/admin/devices") {
        const map = JSON.parse(await env?.STATS?.get("devices") || "{}");
        let list = Object.values(map).sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
        try {
          const ign = JSON.parse(await env?.STATS?.get("ignore_machines") || "[]");
          // 过滤空串/空值, 避免空串 startsWith("") 恒真把设备页全部隐藏
          list = list.filter(d => !ign.some(x => !!x && String(d.machine || "").startsWith(x)));
        } catch {}
        return jsonResp({ ok: true, data: list });
      }

      // 老客户白名单导出(长期/年费授权自动登记; 供复核/备份, 防误扫稳定付费客户)
      if (path === "/api/admin/loyal") {
        try {
          const arr = safeJSON(await env?.STATS?.get("loyal_machines"), []);
          return jsonResp({ ok: true, data: arr });
        } catch (e) {
          // 极端兜底: KV 损坏/解析失败时返回空数组而非 500, 便于后台自我排查
          return jsonResp({ ok: true, data: [], warn: "loyal_machines 解析失败: " + (e.message || String(e)) }, 200);
        }
      }

      // 老客户白名单: 手动添加(后台人工把某机器码/某客户加进白名单, 永久豁免清扫)
      //     请求体: { mhs: ["46...","46..."], tier, lid, note }  (mhs 必填, 可多个)
      if (path === "/api/admin/loyal/add" && request.method === "POST") {
        const apiKey = request.headers.get("X-API-Key") || "";
        if (!adminKey) return jsonResp({ ok: false, error: "admin key not configured" }, 503);
        if (apiKey !== adminKey) return jsonResp({ ok: false, error: "unauthorized" }, 401);
        try {
          const body = await request.json().catch(() => ({}));
          const mhs = (body.mhs || []).map(x => String(x).trim()).filter(Boolean);
          const tier = (body.tier || "").toString().trim();
          const lid = (body.lid || "").toString().trim();
          const note = (body.note || "").toString().trim();
          if (!mhs.length) return jsonResp({ ok: false, error: "缺少 mhs 机器码列表" }, 400);
          if (env && env.STATS) {
            const arr = safeJSON(await env.STATS.get("loyal_machines"), []);
            for (const m of mhs) {
              if (!arr.some(x => x.mh === m)) {
                arr.push({ mh: m, lid, tier, note, ts: Date.now(), manual: true });
              }
            }
            await env.STATS.put("loyal_machines", JSON.stringify(arr));
          }
          return jsonResp({ ok: true, added: mhs.length });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }

      // 老客户白名单: 手动移除
      if (path === "/api/admin/loyal/remove" && request.method === "POST") {
        const apiKey = request.headers.get("X-API-Key") || "";
        if (!adminKey) return jsonResp({ ok: false, error: "admin key not configured" }, 503);
        if (apiKey !== adminKey) return jsonResp({ ok: false, error: "unauthorized" }, 401);
        try {
          const body = await request.json().catch(() => ({}));
          const mhs = (body.mhs || []).map(x => String(x).trim()).filter(Boolean);
          if (!mhs.length) return jsonResp({ ok: false, error: "缺少 mhs 机器码列表" }, 400);
          if (env && env.STATS) {
            const arr = safeJSON(await env.STATS.get("loyal_machines"), []);
            const nx = arr.filter(x => !mhs.includes(x.mh));
            await env.STATS.put("loyal_machines", JSON.stringify(nx));
          }
          return jsonResp({ ok: true, removed: mhs.length });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }

      // 统计（含今日成功/失败、疑似暴力IP数）
      if (path === "/api/admin/stats") {
        const visits = (await env?.STATS?.get("visits")) || "0";
        const downloads = (await env?.STATS?.get("downloads")) || "0";
        const active = (await env?.STATS?.get("active_licenses")) || "0";
        const audit = safeJSON(await env?.STATS?.get("audit_log"), []);
        const today = new Date().toISOString().slice(0, 10);
        let ok_today = 0, fail_today = 0;
        audit.forEach(e => {
          if ((e.ts || "").startsWith(today)) {
            if (e.result === "ok") ok_today++;
            else if (e.result === "fail") fail_today++;
          }
        });
        const since = Date.now() - 10 * 60 * 1000;
        const bf = {};
        audit.filter(e => e.result === "fail" && new Date(e.ts).getTime() > since)
          .forEach(e => { bf[e.ip] = (bf[e.ip] || 0) + 1; });
        const brute = Object.values(bf).filter(c => c >= 5).length;
        return jsonResp({ ok: true, data: { visits: +visits, downloads: +downloads, active: +active, ok_today, fail_today, brute } });
      }

      // 审计日志 + 暴力尝试告警
      if (path === "/api/admin/audit") {
        const u = new URL(request.url);
        const limit = Math.min(parseInt(u.searchParams.get("limit") || "300"), 2000);
        const audit = safeJSON(await env?.STATS?.get("audit_log"), []);
        const since = Date.now() - 10 * 60 * 1000;
        const bf = {};
        audit.filter(e => e.result === "fail" && new Date(e.ts).getTime() > since)
          .forEach(e => { bf[e.ip] = (bf[e.ip] || 0) + 1; });
        const alerts = Object.entries(bf).filter(([, c]) => c >= 5).map(([ip, count]) => ({ ip, count }));
        return jsonResp({ ok: true, data: audit.slice(0, limit), alerts });
      }

      // 已签发许可证（签发数据库）
      // [台账回填] 以 devices(成功激活过的许可证)为源，补齐 issued_licenses 中缺失的 lid。
      // 场景：老客户的授权码由【离线注册机】签发，服务端事前无从登记；此端点把历史上
      // 已成功激活过的机器一次性补进"已签发"台账，使该页立即可用。（只增不减，可重复调用）
      if (path === "/api/admin/issued/backfill" && request.method === "POST") {
        try {
          const kv = env && env.STATS;
          if (!kv) return jsonResp({ ok: false, error: "no kv" }, 500);
          let devs = {};
          try { devs = JSON.parse(await kv.get("devices") || "{}"); } catch {}
          const arr = JSON.parse(await kv.get("issued_licenses") || "[]");
          const seen = {};
          arr.forEach(x => { if (x && x.lid) seen[x.lid] = 1; });
          let added = 0;
          const _ign = JSON.parse(await kv.get("ignore_machines") || "[]").filter(Boolean);
          Object.keys(devs).forEach(k => {
            const d = devs[k] || {};
            const lid = d.lid || k;
            if (!lid || seen[lid]) return;
            if (_ign.some(x => d.machine && String(d.machine).startsWith(x))) return;  // 排除清单内不建台账
            arr.push({ lid, tier: d.tier || "", mh: d.machine || "", issued_at: d.first_seen || Date.now(), exp: 0, source: "backfill" });
            seen[lid] = 1; added++;
          });
          if (added) await kv.put("issued_licenses", JSON.stringify(arr.slice(-2000)));
          return jsonResp({ ok: true, added, total: arr.length });
        } catch (e) { return jsonResp({ ok: false, error: String(e) }, 500); }
      }

      if (path === "/api/admin/issued") {
        const arr = JSON.parse(await env?.STATS?.get("issued_licenses") || "[]");
        return jsonResp({ ok: true, data: arr });
      }

      // 删除已签发记录
      if (path === "/api/admin/issued/delete" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const lid = (body.lid || "").substring(0, 50);
        if (!lid) return jsonResp({ ok: false, error: "missing lid" }, 400);
        const kv = env?.STATS;
        if (kv) {
          const arr = JSON.parse(await kv.get("issued_licenses") || "[]");
          const ns = arr.filter(x => x.lid !== lid);
          await kv.put("issued_licenses", JSON.stringify(ns));
        }
        return jsonResp({ ok: true, msg: "deleted", lid });
      }

      // 吊销（管理会话）
      if (path === "/api/admin/revoke" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const lid = (body.license || body.lid || "").substring(0, 50);
        if (!lid) return jsonResp({ ok: false, error: "missing license id" }, 400);
        const kv = env?.STATS;
        if (kv) {
          const arr = JSON.parse(await kv.get("revoked_licenses") || "[]");
          if (!arr.includes(lid)) { arr.push(lid); await kv.put("revoked_licenses", JSON.stringify(arr)); }
          const set = JSON.parse(await kv.get("active_license_set") || "[]");
          const ns = set.filter(l => !l.startsWith(lid));
          await kv.put("active_license_set", JSON.stringify(ns));
          await kv.put("active_licenses", String(ns.length));
          const dev = JSON.parse(await kv.get("devices") || "{}");
          if (dev[lid]) { delete dev[lid]; await kv.put("devices", JSON.stringify(dev)); }
        }
        return jsonResp({ ok: true, msg: "revoked", lid });
      }

      // 解锁（撤销吊销：从吊销名单移除，恢复被误吊销的授权）
      if (path === "/api/admin/unrevoke" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const lid = (body.license || body.lid || "").substring(0, 50);
        if (!lid) return jsonResp({ ok: false, error: "missing license id" }, 400);
        const kv = env?.STATS;
        if (kv) {
          const arr = JSON.parse(await kv.get("revoked_licenses") || "[]");
          const ns = arr.filter(x => x !== lid);
          await kv.put("revoked_licenses", JSON.stringify(ns));
        }
        return jsonResp({ ok: true, msg: "unrevoked", lid });
      }

      // 强制更新开关（管理会话）
      if (path === "/api/admin/force_update" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const force = body.force ? "1" : "0";
        if (env?.STATS) await env.STATS.put("force_update", force);
        return jsonResp({ ok: true, force_update: force === "1" });
      }

      // 订单列表
      if (path === "/api/admin/orders") {
        const arr = JSON.parse(await env?.STATS?.get("orders") || "[]");
        return jsonResp({ ok: true, data: arr });
      }

      // 本地签发 → 线上登记（管理员）：接收【本地离线注册机】签发的授权码，
      // 服务端用内置公钥验签通过才登记进"已签发"台账 —— 激活私钥永远不必上云。
      if (path === "/api/admin/issue/register" && request.method === "POST") {
        try {
          const body = await request.json().catch(() => ({}));
          const license = (body.license || "").toString().trim();
          if (!license) return jsonResp({ ok: false, error: "缺少 license" }, 400);
          const seg = license.split(".");
          if (seg.length !== 2) return jsonResp({ ok: false, error: "授权码格式非法(应为 payload.sig)" }, 400);
          let payloadBytes, sigBytes, payload = null;
          try {
            payloadBytes = b64decode(seg[0]);
            sigBytes = b64decode(seg[1]);
            payload = JSON.parse(new TextDecoder().decode(payloadBytes));
          } catch (e) { return jsonResp({ ok: false, error: "授权码解码失败(格式非法)" }, 400); }
          const okSig = await rsaVerify(payloadBytes, sigBytes);
          if (!okSig) return jsonResp({ ok: false, error: "授权码验签失败（非本系统签发，拒绝登记）" }, 400);
          await recordIssued(env, license, {
            mh: payload.mh || "", tier: payload.tier || "", exp: payload.exp || 0,
            buyer: (body.buyer || "").toString().slice(0, 40),
            agent: (body.agent || "").toString().slice(0, 40),
            source: "local",
          });
          return jsonResp({ ok: true, registered: true, lid: payload.lid || "", mh: payload.mh || "", tier: payload.tier || "", exp: payload.exp || 0 });
        } catch (e) { return jsonResp({ ok: false, error: String((e && e.message) || e) }, 500); }
      }

      // [2026-09-14] 未登记授权清单：验签通过但从未推送登记的授权码 -> 用于识别非法/来源不明账户。
      if (path === "/api/admin/unregistered") {
        try {
          const map = JSON.parse(await env?.STATS?.get("unregistered_hits") || "{}");
          const list = Object.keys(map).map(k => map[k]).sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
          return jsonResp({ ok: true, data: list, total: list.length });
        } catch (e) { return jsonResp({ ok: false, error: String((e && e.message) || e) }, 500); }
      }

      // 处置未登记授权: action = register(登记为合法) | revoke(加入吊销) | ignore(忽略并移除)
      if (path === "/api/admin/unregistered/resolve" && request.method === "POST") {
        try {
          const body = await request.json().catch(() => ({}));
          const lid = (body.lid || "").toString().trim();
          const action = (body.action || "").toString().trim();
          if (!lid) return jsonResp({ ok: false, error: "缺少 lid" }, 400);
          if (["register", "revoke", "ignore"].indexOf(action) < 0)
            return jsonResp({ ok: false, error: "action 必须是 register|revoke|ignore" }, 400);
          const kv = env && env.STATS;
          if (!kv) return jsonResp({ ok: false, error: "KV 不可用" }, 500);
          const map = JSON.parse(await kv.get("unregistered_hits") || "{}");
          const hit = map[lid];
          if (!hit) return jsonResp({ ok: false, error: "清单中无此 lid" }, 404);
          if (action === "register") {
            const arr = JSON.parse(await kv.get("issued_licenses") || "[]");
            if (!arr.find(x => x && x.lid === lid)) {
              arr.push({ lid, tier: hit.tier || "", mh: hit.mh || "", issued_at: Date.now(), exp: hit.exp || 0, source: "manual_review" });
              await kv.put("issued_licenses", JSON.stringify(arr.slice(-2000)));
            }
          } else if (action === "revoke") {
            const rl = JSON.parse(await kv.get("revoked_licenses") || "[]");
            if (rl.indexOf(lid) < 0) { rl.push(lid); await kv.put("revoked_licenses", JSON.stringify(rl)); }
            try {
              const as = JSON.parse(await kv.get("active_license_set") || "[]");
              const ns = as.filter(l => !String(l).startsWith(lid));
              await kv.put("active_license_set", JSON.stringify(ns));
              await kv.put("active_licenses", String(ns.length));
            } catch (e) {}
          }
          delete map[lid];
          await kv.put("unregistered_hits", JSON.stringify(map));
          return jsonResp({ ok: true, action, lid });
        } catch (e) { return jsonResp({ ok: false, error: String((e && e.message) || e) }, 500); }
      }

      // [2026-09-14 安全整改] 服务端签发已永久停用。
      // 原因：激活私钥留在云端 = 服务器被黑即可伪造与合法码无法区分的授权码（断根级风险）。
      // 现行流程：本地离线批量签发(batch_issue.py) -> 本接口下方的 /api/admin/issue/register 推送登记。
      if (path === "/api/admin/issue" && request.method === "POST") {
        return jsonResp({ ok: false, error: "server_signing_disabled",
          msg: "服务端签发已停用（私钥已下线）。请用本地注册机离线签发，再用 /api/admin/issue/register 推送登记。" }, 410);
      }

      // [2026-09-14 安全整改] 订单签发一并停用：订单只作为销售流水，不再参与签发。
      if (path === "/api/admin/orders/issue" && request.method === "POST") {
        return jsonResp({ ok: false, error: "server_signing_disabled",
          msg: "服务端签发已停用（私钥已下线）。请走本地离线签发 + /api/admin/issue/register 登记。" }, 410);
      }

      // 删除订单（清理垃圾/测试/脚本刷的 pending 订单）
      if (path === "/api/admin/orders/delete" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const orderId = (body.order_id || "").toString().trim();
        if (!orderId) return jsonResp({ ok: false, error: "missing order_id" }, 400);
        const kv = env?.STATS;
        if (kv) {
          const orders = JSON.parse(await kv.get("orders") || "[]");
          const nx = orders.filter(x => x.order_id !== orderId);
          await kv.put("orders", JSON.stringify(nx));
        }
        return jsonResp({ ok: true, msg: "deleted", order_id: orderId });
      }

      // 代理列表（含归因统计）
      if (path === "/api/admin/agents") {
        let set = [];
        try { set = JSON.parse(await env?.STATS?.get("agent_set") || "[]"); } catch {}
        const list = [];
        for (const code of set) {
          const info = JSON.parse(await env?.STATS?.get("agent:" + code) || "{}");
          list.push({
            code,
            name: info.name || "",
            contact: info.contact || "",
            downloads: parseInt(await env?.STATS?.get("agent:" + code + ":downloads") || "0") || 0,
            visits: parseInt(await env?.STATS?.get("agent:" + code + ":visits") || "0") || 0,
            activations: parseInt(await env?.STATS?.get("agent:" + code + ":activations") || "0") || 0,
            orders: parseInt(await env?.STATS?.get("agent:" + code + ":orders") || "0") || 0,
            last_seen: info.last_seen || "",
          });
        }
        return jsonResp({ ok: true, data: list });
      }

      // 手动补记代理业绩（归因丢失时人工核对后补登）
      if (path === "/api/admin/agents/credit" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const code = (body.code || "").toString().trim();
        const field = (body.field || "").toString().trim();
        const amount = parseInt(body.amount || "0") || 0;
        const FIELDS = ["visits", "downloads", "activations", "orders"];
        if (!code) return jsonResp({ ok: false, error: "missing agent code" }, 400);
        if (!FIELDS.includes(field)) return jsonResp({ ok: false, error: "field must be one of " + FIELDS.join(",") }, 400);
        if (amount <= 0) return jsonResp({ ok: false, error: "amount must be > 0" }, 400);
        try {
          const cur = parseInt(await env?.STATS?.get("agent:" + code + ":" + field) || "0") || 0;
          await env?.STATS?.put("agent:" + code + ":" + field, String(cur + amount));
          // 同步全局汇总（若有）
          const gcur = parseInt(await env?.STATS?.get(field) || "0") || 0;
          await env?.STATS?.put(field, String(gcur + amount));
          return jsonResp({ ok: true, code, field, added: amount, total: cur + amount });
        } catch (e) { return jsonResp({ ok: false, error: e.message }, 500); }
      }

      return jsonResp({ ok: false, error: "unknown admin route" }, 404);
    }

    // ---------- 管理后台页 (挂到 /api/admin, 在 Worker 路由内, 一次 deploy 即可) ----------
    if (path === "/api/admin" || path === "/api/admin/") {
      return new Response(ADMIN_HTML, {
        headers: { ...CORS, "Content-Type": "text/html; charset=utf-8" }
      });
    }

    return new Response("Not Found", { status: 404, headers: CORS });
  }
};
