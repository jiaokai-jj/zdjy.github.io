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
const CURRENT_VERSION = "4.0.0";
const DOWNLOAD_URL = "https://www.jyt.cc.cd/";

// ========== 工具函数 ==========
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----[A-Z ]+/g, '').replace(/\s+/g, '');
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

// ========== 主处理 ==========
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

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

    // ---------- 访问/下载统计 ----------
    if (path === "/api/track" && request.method === "POST") {
      try {
        const body = await request.json();
        const type = body.type;
        if (type === "visit" || type === "download") {
          const cur = await env?.STATS?.get(type === "visit" ? "visits" : "downloads") || "0";
          const n = (parseInt(cur) || 0) + 1;
          await env?.STATS?.put(type === "visit" ? "visits" : "downloads", String(n));
          return jsonResp({ ok: true, count: n });
        }
        return jsonResp({ ok: false, error: "unknown type" }, 400);
      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 许可证验证（核心） ----------
    if (path === "/api/verify" && request.method === "POST") {
      try {
        const body = await request.json();
        const licenseKey = body.license || "";
        const machineCode = body.machine_code || "";

        if (!licenseKey || !machineCode) {
          return jsonResp({ ok: false, error: "missing parameters" }, 400);
        }

        // 1. 解析RSA签名格式: base64(JSON).RSA_signature
        const dotIdx = licenseKey.lastIndexOf(".");
        if (dotIdx < 0) {
          return jsonResp({ ok: false, error: "invalid format" }, 400);
        }

        const payloadB64 = licenseKey.substring(0, dotIdx);
        const sigB64 = licenseKey.substring(dotIdx + 1);

        let payloadStr, payload;
        try {
          payloadStr = atob(payloadB64);
          payload = JSON.parse(payloadStr);
        } catch {
          return jsonResp({ ok: false, error: "invalid payload" }, 400);
        }

        // 2. RSA签名验证
        const sigBytes = b64decode(sigB64);
        const payloadBytes = new TextEncoder().encode(payloadStr);
        const sigValid = await rsaVerify(payloadBytes, sigBytes);
        if (!sigValid) {
          return jsonResp({ ok: false, error: "signature invalid" }, 403);
        }

        // 3. 机器码绑定验证
        const licenseMh = payload.mh || payload.machine_id || "";
        if (licenseMh && licenseMh !== machineCode) {
          return jsonResp({ ok: false, error: "machine mismatch" }, 403);
        }

        // 4. 过期检查
        const exp = payload.exp || 0;
        const now = Math.floor(Date.now() / 1000);
        if (exp > 0 && now > exp) {
          return jsonResp({ ok: false, error: "license expired" }, 403);
        }

        // 5. 吊销检查（KV存储）
        const lid = payload.lid || payload.machine_id?.substring(0, 16) || "";
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
          return jsonResp({ ok: false, error: "license revoked" }, 403);
        }

        // 6. 生成短期令牌（7天有效）
        const tier = payload.tier || payload.version || "premium";
        const tokenPayload = {
          lid: lid,
          tier: tier,
          mh: machineCode,
          iat: now,
          exp: now + 7 * 86400,  // 7天有效
          perms: {
            can_trade: tier !== "trial",
            cond_order: tier === "premium",
            max_buys: tier === "premium" ? 999999 : (tier === "basic" ? 10 : 0),
            max_shares: tier === "premium" ? 999999 : (tier === "basic" ? 1000 : 0),
          }
        };

        const token = await generateToken(tokenPayload, adminKey);

        // 7. 更新活跃许可证计数
        try {
          if (env && env.STATS) {
            const active = await env.STATS.get("active_licenses") || "0";
            // 简单计数，实际生产环境应使用Set或列表
            const activeSet = JSON.parse(await env.STATS.get("active_license_set") || "[]");
            if (!activeSet.includes(lid)) {
              activeSet.push(lid);
              await env.STATS.put("active_license_set", JSON.stringify(activeSet));
              await env.STATS.put("active_licenses", String(activeSet.length));
            }
          }
        } catch {}

        return jsonResp({
          ok: true,
          data: {
            token: token,
            tier: tier,
            lid: lid,
            exp: tokenPayload.exp,
            perms: tokenPayload.perms,
          }
        });

      } catch (e) {
        return jsonResp({ ok: false, error: e.message }, 500);
      }
    }

    // ---------- 令牌验证（客户端定期调用） ----------
    if (path === "/api/verify_token" && request.method === "POST") {
      try {
        const body = await request.json();
        const token = body.token || "";
        const machineCode = body.machine_code || "";

        if (!token) {
          return jsonResp({ ok: false, error: "missing token" }, 400);
        }

        const payload = await verifyToken(token, adminKey);
        if (!payload) {
          return jsonResp({ ok: false, error: "invalid token" }, 403);
        }

        // 检查机器码
        if (payload.mh && payload.mh !== machineCode) {
          return jsonResp({ ok: false, error: "machine mismatch" }, 403);
        }

        // 检查过期
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && now > payload.exp) {
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
          return jsonResp({ ok: false, error: "license revoked" }, 403);
        }

        return jsonResp({
          ok: true,
          data: {
            tier: payload.tier,
            lid: payload.lid,
            exp: payload.exp,
            perms: payload.perms,
          }
        });

      } catch (e) {
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

    return new Response("Not Found", { status: 404, headers: CORS });
  }
};
