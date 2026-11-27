import assert from "node:assert/strict";
import test from "node:test";
import { GET } from "../app/api/dashboard/[source]/route.ts";

const adminHeader = "X-OpenAssetWatch-Admin-Token";

function read(source, query = "") {
  return GET(new Request(`http://localhost:3000/api/dashboard/${source}${query}`, {
    headers: { [adminHeader]: "synthetic", Authorization: "Bearer synthetic", Cookie: "synthetic=value" },
  }), { params: Promise.resolve({ source }) });
}

test("the dashboard route allowlists API reads and leaves browser credentials out of upstream requests", async (t) => {
  const upstream = t.mock.method(globalThis, "fetch", async () => Response.json({ items: [] }));
  assert.equal((await read("__proto__")).status, 404);
  assert.equal(upstream.mock.callCount(), 0);

  const assetResponse = await read("assets", "?url=https://example.invalid");
  const [assetUrl, assetOptions] = upstream.mock.calls[0].arguments;
  assert.equal(assetUrl.pathname, "/api/v1/control-tower/assets");
  assert.equal(assetUrl.search, "");
  assert.equal(assetOptions.headers.has(adminHeader), false);
  assert.equal(assetResponse.headers.get("Cache-Control"), "no-store");

  await read("acknowledged", "?site=north%26west&status=resolved");
  const [findingUrl, findingOptions] = upstream.mock.calls[1].arguments;
  assert.equal(findingUrl.searchParams.get("site_id"), "north&west");
  assert.equal(findingUrl.searchParams.get("status"), "acknowledged");
  assert.equal(findingOptions.headers.has(adminHeader), false);
  assert.equal(findingOptions.headers.has("Authorization"), false);
  assert.equal(findingOptions.headers.has("Cookie"), false);
  assert.equal(findingOptions.redirect, "error");
});

test("authentication failures remain visible without relaying upstream credentials or error content", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response("private upstream diagnostic", { status: 401 }));
  const response = await read("active");
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "Control Tower API request failed" });
});
