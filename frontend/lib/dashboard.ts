import { severities, type Asset, type Collector, type Finding, type Severity, type Site } from "./contracts.ts";

export const hour = 3_600_000;
export const ranges = { "24h": ["Last 24 hours", 24], "7d": ["Last 7 days", 168], "30d": ["Last 30 days", 720] } as const;
export const views = ["overview", "assets", "findings", "collectors", "sites", "evidence"] as const;
export const collectorStates = ["reporting", "stale", "unknown"] as const;
export const intervalCount = 6;

type View = (typeof views)[number];
type Range = keyof typeof ranges;
export type CollectorState = (typeof collectorStates)[number];

export interface Scope {
  view: View;
  site: string;
  range: Range;
  asOf: number | null;
  severity: Severity | null;
  collector: CollectorState | null;
  bucket: number | null;
  asset: string | null;
  category: string | null;
  newAssets: boolean;
  finding: string | null;
  drawer: boolean;
}

export function timestamp(value?: string | null) {
  const time = value ? Date.parse(value) : NaN;
  return Number.isFinite(time) ? time : null;
}

export function readScope(params: Pick<URLSearchParams, "get">): Scope {
  const view = views.find((item) => item === params.get("view")) ?? "overview";
  const bucket = params.get("bucket");
  const rangeParam = params.get("range");
  const range = rangeParam === "7d" || rangeParam === "24h" ? rangeParam : "30d";
  const asOf = timestamp(params.get("asOf"));
  const validRange = asOf !== null && Number.isFinite(new Date(asOf - ranges[range][1] * hour).getTime());
  return {
    view,
    site: params.get("site") ?? "",
    range,
    asOf: validRange ? asOf : null,
    severity: view === "findings" ? severities.find((item) => item === params.get("severity")) ?? null : null,
    collector: view === "collectors" ? collectorStates.find((item) => item === params.get("collector")) ?? null : null,
    bucket: view === "findings" && bucket !== null && /^[0-5]$/.test(bucket) ? Number(bucket) : null,
    asset: view === "assets" || view === "evidence" ? params.get("asset") : null,
    category: view === "assets" ? params.get("category") : null,
    newAssets: view === "assets" && params.get("new") === "1",
    finding: view === "findings" ? params.get("finding") : null,
    drawer: view !== "overview" && params.get("details") === "1",
  };
}

export function dashboardUrl(scope: Scope, changes: Partial<Scope> = {}) {
  const next = { ...scope, ...changes };
  const params = new URLSearchParams();
  if (next.view !== "overview") params.set("view", next.view);
  if (next.site) params.set("site", next.site);
  if (next.range !== "30d") params.set("range", next.range);
  if (next.asOf !== null) params.set("asOf", new Date(next.asOf).toISOString());
  if (next.view === "findings" && next.severity) params.set("severity", next.severity);
  if (next.view === "findings" && next.bucket !== null) params.set("bucket", String(next.bucket));
  if (next.view === "collectors" && next.collector) params.set("collector", next.collector);
  if ((next.view === "assets" || next.view === "evidence") && next.asset) params.set("asset", next.asset);
  if (next.view === "assets" && next.category) params.set("category", next.category);
  if (next.view === "assets" && next.newAssets) params.set("new", "1");
  if (next.view === "findings" && next.finding) params.set("finding", next.finding);
  if (next.view !== "overview" && next.drawer) params.set("details", "1");
  return params.size ? `/?${params}` : "/";
}

export function inSite<T extends { site_id: string }>(rows: T[], site: string) {
  return site ? rows.filter((row) => row.site_id === site) : rows;
}

export function collectorState(collector: Collector, now: number): CollectorState {
  const seen = timestamp(collector.last_seen_at);
  if (seen === null) return "unknown";
  return now - seen > 15 * 60_000 ? "stale" : "reporting";
}

export function findingIntervals(findings: Finding[], range: Range, end: number) {
  const duration = ranges[range][1] * hour;
  const start = end - duration;
  const width = duration / intervalCount;
  const intervals = Array.from({ length: intervalCount }, (_, index) => ({
    start: start + index * width,
    end: start + (index + 1) * width,
    counts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
  }));
  for (const finding of findings) {
    const firstSeen = timestamp(finding.first_seen_at);
    if (firstSeen === null || firstSeen < start || firstSeen >= end) continue;
    intervals[Math.floor((firstSeen - start) / width)].counts[finding.severity] += 1;
  }
  return intervals;
}

export function filterFindings(findings: Finding[], severity: Severity | null, interval?: { start: number; end: number }) {
  return findings.filter((finding) => {
    if (severity && finding.severity !== severity) return false;
    if (!interval) return true;
    const observed = timestamp(finding.first_seen_at);
    return observed !== null && observed >= interval.start && observed < interval.end;
  });
}

export function assetTime(asset: Asset) {
  return timestamp(asset.observed_at) ?? timestamp(asset.last_seen_at);
}

export function assetCategory(asset: Asset) {
  return asset.classification?.category || "unknown";
}

export function assetsByCategory(assets: Asset[]) {
  const counts = new Map<string, number>();
  for (const asset of assets) {
    const category = assetCategory(asset);
    counts.set(category, (counts.get(category) ?? 0) + 1);
  }
  return [...counts].map(([id, count]) => ({ id, count }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
}

export function newAssetsInRange(assets: Asset[], range: Range, end: number) {
  const start = end - ranges[range][1] * hour;
  return assets.filter((asset) => {
    const firstSeen = timestamp(asset.first_seen_at);
    return firstSeen !== null && firstSeen >= start && firstSeen < end;
  });
}

export function recentEvidence(assets: Asset[], range: Range, end: number) {
  const start = end - ranges[range][1] * hour;
  return assets.flatMap((asset) => {
    const observed = assetTime(asset);
    return observed !== null && observed >= start && observed < end ? [{ asset, observed }] : [];
  }).sort((a, b) => b.observed - a.observed);
}

export function assetCountsBySite(assets: Asset[], sites: Site[], scope: string) {
  const counts = new Map<string, number>();
  for (const asset of assets) counts.set(asset.site_id, (counts.get(asset.site_id) ?? 0) + 1);
  const names = new Map(sites.map((site) => [site.site_id, site.name]));
  const siteIds = new Set([...sites.map((site) => site.site_id), ...counts.keys()]);
  return [...siteIds]
    .filter((siteId) => !scope || scope === siteId)
    .map((id) => ({ id, name: names.get(id) || id, count: counts.get(id) ?? 0 }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}
