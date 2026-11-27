import assert from "node:assert/strict";
import test from "node:test";
import { readScope } from "../lib/dashboard.ts";
import { searchWorkspace } from "../lib/search.ts";

const scope = readScope(new URLSearchParams({ site: "north", range: "7d", asOf: "2026-11-25T16:00:00.000Z" }));
const north = { site_id: "north", asset_key: "north & #router", asset_id: "router", hostname: "EDGE-04", primary_ip: "192.0.2.4" };
const south = { ...north, site_id: "south", asset_key: "south/edge", primary_ip: "198.51.100.4" };

test("entity search groups results and preserves the selected site and date scope", () => {
  const groups = searchWorkspace({ scope, assets: [north, south], findings: [] }, "edge-04");
  assert.deepEqual(groups.map(({ label }) => label), ["Assets", "IP addresses", "Hostnames"]);
  for (const group of groups) {
    assert.equal(group.items.length, 1);
    const url = new URL(group.items[0].href, "http://localhost");
    assert.equal(url.origin, "http://localhost");
    assert.deepEqual(readScope(url.searchParams), { ...scope, view: "assets", asset: north.asset_key });
  }
  assert.deepEqual(searchWorkspace({ scope, assets: [north, south] }, "198.51.100.4"), []);
});

test("findings search opens a scoped detail page without resetting another view to Overview", () => {
  const finding = { site_id: scope.site, finding_id: "finding-7", title: "Firmware baseline", severity: "high" };
  const groups = searchWorkspace({ scope, findings: [finding] }, "finding-7");
  const detail = new URL(groups[0].items[0].href, "http://localhost");
  assert.deepEqual(readScope(detail.searchParams), { ...scope, view: "findings", finding: "finding-7" });
});

test("search limits each group and keeps untrusted labels as plain text with local destinations", () => {
  const assets = Array.from({ length: 8 }, (_, index) => ({
    ...north, asset_key: String(index), hostname: "<asset> node",
  }));
  const groups = searchWorkspace({ scope, assets }, "<asset> node");
  assert.deepEqual(groups.map(({ label }) => label), ["Assets", "IP addresses", "Hostnames"]);
  assert.equal(groups[0].items.length, 5);
  assert.equal(groups[0].items[0].title, "<asset> node");
  assert.match(groups[0].items[0].href, /^\/\?view=assets&/);
  assert.deepEqual(searchWorkspace({ scope }, "restricted finding"), []);
});
