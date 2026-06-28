// Cloudflare Worker - JYT License + Stats
const REVOKED = [];
const ADMIN_KEY = "admin-change-me";

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

    if (path === "/api/version") {
      return new Response(JSON.stringify({
        version: "2.0.2", url: "https://www.jyt.cc.cd/",
        force_update: false
      }), { headers: { ...cors, "Content-Type": "application/json" } });
    }

    if (path === "/api/health") {
      return new Response(JSON.stringify({ status: "ok" }), { headers: { ...cors, "Content-Type": "application/json" } });
    }

    if (path === "/api/stats") {
      const visits = (await env.STATS.get("visits")) || "0";
      const downloads = (await env.STATS.get("downloads")) || "0";
      return new Response(JSON.stringify({ visits: parseInt(visits), downloads: parseInt(downloads) }),
        { headers: { ...cors, "Content-Type": "application/json" } });
    }

    if (path === "/api/track" && request.method === "POST") {
      try {
        const body = await request.json();
        if (body.type === "visit") {
          const v = await env.STATS.get("visits");
          const n = (parseInt(v) || 0) + 1;
          await env.STATS.put("visits", String(n));
          return new Response(JSON.stringify({ ok: true, visits: n }),
            { headers: { ...cors, "Content-Type": "application/json" } });
        }
        if (body.type === "download") {
          const d = await env.STATS.get("downloads");
          const n = (parseInt(d) || 0) + 1;
          await env.STATS.put("downloads", String(n));
          return new Response(JSON.stringify({ ok: true, downloads: n }),
            { headers: { ...cors, "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ ok: false, error: "unknown type" }),
          { status: 400, headers: { ...cors, "Content-Type": "application/json" } });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }),
          { status: 500, headers: { ...cors, "Content-Type": "application/json" } });
      }
    }

    if (path === "/api/verify" && request.method === "POST") {
      try {
        const body = await request.json();
        const license = body.license || "";
        const prefix = license.substring(0, 30);
        const revoked = REVOKED.some(function(r) { return license.startsWith(r); });
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