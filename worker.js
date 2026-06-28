// Cloudflare Worker - 智库授权 API
// 1. Cloudflare Dashboard -> Workers & Pages -> Create -> 粘贴此代码
// 2. 设置自定义域: jyt.cc.cd/api/*

// 吊销列表（要吊销哪个注册码，把前30位加进来）
const REVOKED = [
  // "eyJtYWNoaW5lX2lkIjoiY2M3YzBk",  // 示例：吊销时取消注释
];

// 管理员密钥
const ADMIN_KEY = "admin-change-me";  // 部署后改掉

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    // GET /api/version
    if (path === "/api/version") {
      return new Response(JSON.stringify({
        version: "2.0.2", url: "https://www.jyt.cc.cd/",
        force_update: false
      }), { headers: { ...cors, "Content-Type": "application/json" } });
    }

    // GET /api/health
    if (path === "/api/health") {
      return new Response(JSON.stringify({ status: "ok" }), { headers: { ...cors, "Content-Type": "application/json" } });
    }

    // POST /api/verify - 吊销检查
    if (path === "/api/verify" && request.method === "POST") {
      try {
        const body = await request.json();
        const license = body.license || "";
        const prefix = license.substring(0, 30);
        const revoked = REVOKED.some(r => license.startsWith(r));
        if (revoked) {
          return new Response(JSON.stringify({ ok: false, error: "revoked" }),
            { status: 403, headers: { ...cors, "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ ok: true, data: {} }),
          { headers: { ...cors, "Content-Type": "application/json" } });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }),
          { status: 500, headers: { ...cors, "Content-Type": "application/json" } });
      }
    }

    // POST /api/revoke - 吊销（需API Key）
    if (path === "/api/revoke" && request.method === "POST") {
      if ((request.headers.get("X-API-Key") || "") !== ADMIN_KEY) {
        return new Response(JSON.stringify({ ok: false, error: "unauthorized" }),
          { status: 401, headers: { ...cors, "Content-Type": "application/json" } });
      }
      const body = await request.json();
      if (body.license) {
        REVOKED.push(body.license.substring(0, 50));
        return new Response(JSON.stringify({ ok: true, msg: "revoked" }),
          { headers: { ...cors, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ ok: false, error: "missing license" }),
        { status: 400, headers: { ...cors, "Content-Type": "application/json" } });
    }

    return new Response("Not Found", { status: 404, headers: cors });
  }
};