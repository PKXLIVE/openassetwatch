import assert from "node:assert/strict";
import test from "node:test";
import {
  assetCountsBySite, assetsByCategory, collectorState, dashboardUrl, filterFindings,
  findingIntervals, hour, inSite, newAssetsInRange, ranges, readScope, recentEvidence,
} from "../lib/dashboard.ts";

const end = Date.parse("2026-11-25T16:00:00Z");
const iso = (time) => new Date(time).toISOString();

test("chart drilldowns keep the site, range, exact interval, and drawer state in the URL", () => {
  const scope = readScope(new URLSearchParams({ site: "north & west", range: "7d", asOf: iso(end) }));
  const url = dashboardUrl(scope, { view: "findings", bucket: 2, drawer: true });
  const linked = readScope(new URL(url, "http://localhost").searchParams);
  assert.deepEqual(linked, { ...scope, view: "findings", bucket: 2, drawer: true });
  const category = dashboardUrl(scope, { view: "assets", category: "network-device", drawer: true });
  assert.equal(readScope(new URL(category, "http://localhost").searchParams).category, "network-device");
  assert.equal(readScope(new URLSearchParams("view=assets&bucket=2&severity=high")).bucket, null);
  assert.equal(readScope(new URLSearchParams("view=findings&bucket=6&asOf=invalid")).asOf, null);
});

test("existing finding drilldowns retain stable site, time, interval, and severity filters", () => {
  const asOf = "2026-11-27T14:30:00.000Z";
  const scope = readScope(new URLSearchParams(`view=findings&site=site-stable-42&range=7d&asOf=${encodeURIComponent(asOf)}&severity=high&bucket=3`));
  const drilldown = readScope(new URL(dashboardUrl(scope, { drawer: true }), "http://localhost").searchParams);
  assert.deepEqual(drilldown, { ...scope, drawer: true });

  const assetScope = readScope(new URL(dashboardUrl(scope, { view: "assets", asset: "asset-stable-99", drawer: true }), "http://localhost").searchParams);
  assert.equal(assetScope.site, "site-stable-42");
  assert.equal(assetScope.range, "7d");
  assert.equal(assetScope.asOf, Date.parse(asOf));
  assert.equal(assetScope.asset, "asset-stable-99");
  assert.equal(assetScope.severity, null);
});

test("each finding drilldown matches the plotted half-open interval count", () => {
  const start = end - 24 * hour;
  const rows = [
    { severity: "critical", first_seen_at: iso(start) },
    { severity: "high", first_seen_at: iso(start + 4 * hour - 1) },
    { severity: "medium", first_seen_at: iso(start + 4 * hour) },
    { severity: "low", first_seen_at: iso(end) },
    { severity: "low", first_seen_at: "unknown" },
  ];
  const intervals = findingIntervals(rows, "24h", end);
  assert.deepEqual(intervals.map((interval) => filterFindings(rows, null, interval).length), [2, 1, 0, 0, 0, 0]);
  assert.equal(intervals[0].counts.critical, 1);
  assert.equal(intervals[1].counts.medium, 1);
  assert.equal(filterFindings(rows, "high", intervals[0]).length, 1);
});

test("shared URLs require the entire selected date range to be representable", () => {
  const earliest = Date.parse("-271821-04-20T00:00:00.000Z");
  const latest = Date.parse("+275760-09-13T00:00:00.000Z");
  for (const [range, [, hours]] of Object.entries(ranges)) {
    const minimumEnd = earliest + hours * hour;
    const scopeAt = (asOf) => readScope(new URLSearchParams({ range, asOf: iso(asOf) }));
    assert.equal(scopeAt(minimumEnd - 1).asOf, null, `${range} would start before the earliest date`);
    assert.equal(scopeAt(minimumEnd).asOf, minimumEnd);
    assert.equal(scopeAt(latest).asOf, latest);
    const intervals = findingIntervals([], range, scopeAt(minimumEnd).asOf);
    assert.equal(intervals[0].start, earliest);
    assert.doesNotThrow(() => new Intl.DateTimeFormat().format(intervals[0].start));
  }
});

test("inventory grouping and recency use distinct API fields with site isolation", () => {
  const rows = [
    { site_id: "north", asset_key: "a", classification: { category: "server" }, observed_at: iso(end - hour), first_seen_at: iso(end - 2 * hour) },
    { site_id: "north", asset_key: "b", observed_at: null, last_seen_at: iso(end - 2 * hour), first_seen_at: iso(end - 48 * hour) },
    { site_id: "south", asset_key: "c", classification: { category: "server" }, first_seen_at: iso(end - hour) },
  ];
  const north = inSite(rows, "north");
  assert.deepEqual(assetsByCategory(north), [{ id: "server", count: 1 }, { id: "unknown", count: 1 }]);
  assert.deepEqual(newAssetsInRange(north, "24h", end).map((row) => row.asset_key), ["a"]);
  assert.deepEqual(recentEvidence(north, "24h", end).map(({ asset }) => asset.asset_key), ["a", "b"]);
  assert.deepEqual(assetCountsBySite(rows, [{ site_id: "empty", name: "Empty site" }], "").map(({ count }) => count), [2, 1, 0]);
});

test("collector status distinguishes stale and missing check-ins", () => {
  assert.equal(collectorState({ last_seen_at: iso(end - 15 * 60_000) }, end), "reporting");
  assert.equal(collectorState({ last_seen_at: iso(end - 15 * 60_000 - 1) }, end), "stale");
  assert.equal(collectorState({ last_seen_at: null }, end), "unknown");
});
