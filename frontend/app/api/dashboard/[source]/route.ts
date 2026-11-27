const sources = {
  assets: "/api/v1/control-tower/assets",
  sites: "/api/v1/sites",
  collectors: "/api/v1/agents",
  active: "/api/v1/findings?status=active&limit=200",
  acknowledged: "/api/v1/findings?status=acknowledged&limit=200",
} as const;

const noCache = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

function apiOrigin() {
  const origin = new URL(process.env.OAW_API_ORIGIN ?? "http://127.0.0.1:8000");
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);
  if (origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash ||
      (origin.protocol !== "https:" && !(origin.protocol === "http:" && loopback))) {
    throw new Error("Invalid Control Tower API origin");
  }
  return origin;
}

export async function GET(request: Request, { params }: { params: Promise<{ source: string }> }) {
  const { source } = await params;
  if (!Object.hasOwn(sources, source)) {
    return Response.json({ error: "Unknown dashboard data source" }, { status: 404, headers: noCache });
  }

  try {
    const upstreamUrl = new URL(sources[source as keyof typeof sources], apiOrigin());
    const headers = new Headers({ Accept: "application/json" });
    if (source === "active" || source === "acknowledged") {
      const site = new URL(request.url).searchParams.get("site");
      if (site) upstreamUrl.searchParams.set("site_id", site);
    }
    const upstream = await fetch(upstreamUrl, {
      cache: "no-store",
      redirect: "error",
      headers,
      signal: AbortSignal.timeout(10_000),
    });
    if (!upstream.ok) {
      return Response.json({ error: "Control Tower API request failed" }, { status: upstream.status, headers: noCache });
    }
    return Response.json(await upstream.json(), { headers: noCache });
  } catch {
    return Response.json({ error: "Control Tower API unavailable" }, { status: 502, headers: noCache });
  }
}
