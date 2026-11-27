"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { severities, type Asset, type Collector, type Finding, type FindingPage, type Site } from "../lib/contracts";
import {
  assetCategory, assetCountsBySite, collectorState, dashboardUrl, filterFindings, findingIntervals,
  inSite, newAssetsInRange, ranges, readScope, recentEvidence, timestamp, type Scope,
} from "../lib/dashboard";
import { AssetChart, categoryLabel, FindingChart, Panel } from "./charts";
import { useSource, type Result } from "./data";
import { AppShell, viewLabel } from "./app-shell";

const stateLabel = { reporting: "Reporting", stale: "Stale", unknown: "No check-in" };

function formatDate(value: number | null) {
  return value === null ? "Unknown" : new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function unavailable(result: Result<unknown> | undefined) {
  if (!result) return "Loading…";
  if (result.error === 401 || result.error === 403) return "Findings require an authorized session.";
  return `Data unavailable (HTTP ${result.error}). Refresh to retry.`;
}

function Table({ columns, rows }: { columns: string[]; rows: ReactNode[][] }) {
  return <div className="table-scroll" role="region" tabIndex={0} aria-label={`${columns[0]} results`}>
    <table><thead><tr>{columns.map((column) => <th scope="col" key={column}>{column}</th>)}</tr></thead>
      <tbody>{rows.map(([key, ...cells]) => <tr key={String(key)}>{cells.map((cell, index) => <td key={columns[index]}>{cell}</td>)}</tr>)}</tbody>
    </table>
  </div>;
}

function DetailDrawer({ title, subtitle, children, close }: { title: string; subtitle: string; children: ReactNode; close: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => dialog?.close();
  }, []);

  return <dialog ref={ref} className="drawer" aria-labelledby="drawer-title" onCancel={(event) => { event.preventDefault(); close(); }}
    onClick={(event) => { if (event.target === event.currentTarget) close(); }}>
    <div className="drawer-content">
      <div className="drawer-top"><span>Overview details</span><button type="button" className="quiet-button" aria-label="Close details" onClick={close} autoFocus>×</button></div>
      <h2 id="drawer-title">{title}</h2><p className="muted">{subtitle}</p>
      {children}
    </div>
  </dialog>;
}

function Kpi({ label, count, note, icon, url }: { label: string; count?: number; note: string; icon: string; url: string }) {
  return <Link className="panel kpi" href={url} prefetch={false}>
    <span className="kpi-head">{label}<span className="kpi-icon" aria-hidden="true">{icon}</span></span>
    <strong>{count?.toLocaleString() ?? "—"}</strong><span className="kpi-note">{note}</span>
  </Link>;
}

export function Dashboard() {
  const router = useRouter();
  const params = useSearchParams();
  const requested = readScope(params);
  const [now, setNow] = useState(0);
  useEffect(() => { setNow(Date.now()); }, []);

  const scope = { ...requested, asOf: requested.asOf ?? now };
  const overview: Scope = {
    ...scope, view: "overview", bucket: null, severity: null, collector: null,
    category: null, newAssets: false, finding: null, asset: null, drawer: false,
  };
  const siteQuery = scope.site ? `?${new URLSearchParams({ site: scope.site })}` : "";
  const sites = useSource<Site[]>("sites", now, "sites");
  const assets = useSource<Asset[]>("assets", now, "assets");
  const collectors = useSource<Collector[]>("collectors", now, "agents");
  const active = useSource<FindingPage>(`active${siteQuery}`, now);
  const acknowledged = useSource<FindingPage>(`acknowledged${siteQuery}`, now);
  const findingError = [active, acknowledged].find((result) => result?.error === 401 || result?.error === 403)
    ?? [active, acknowledged].find((result) => result?.error !== undefined);
  const findings = active?.data && acknowledged?.data ? [...active.data.items, ...acknowledged.data.items] : undefined;
  const truncated = Boolean(active?.data?.truncated || acknowledged?.data?.truncated);
  const findingTotal = active?.data && acknowledged?.data ? active.data.total + acknowledged.data.total : undefined;
  const findingOrder = (a: Finding, b: Finding) => severities.indexOf(a.severity) - severities.indexOf(b.severity) || b.first_seen_at.localeCompare(a.first_seen_at);
  const priority = findings ? [...findings].sort(findingOrder) : undefined;
  const siteList = sites?.data ?? [];
  const scopedAssets = assets?.data ? inSite(assets.data, scope.site) : undefined;
  const scopedCollectors = collectors?.data ? inSite(collectors.data, scope.site) : undefined;
  const reporting = scopedCollectors?.filter((row) => collectorState(row, now) === "reporting").length;
  const latestCheckIn = scopedCollectors?.reduce<number | null>((latest, collector) => {
    const seen = timestamp(collector.last_seen_at);
    return seen !== null && (latest === null || seen > latest) ? seen : latest;
  }, null) ?? null;
  const siteName = (id: string) => siteList.find((site) => site.site_id === id)?.name || id;
  const scopeName = scope.site ? siteName(scope.site) : "All sites";
  const intervals = findings ? findingIntervals(findings, scope.range, scope.asOf) : undefined;
  const newAssets = scopedAssets ? newAssetsInRange(scopedAssets, scope.range, scope.asOf) : undefined;
  const activity = scopedAssets ? recentEvidence(scopedAssets, scope.range, scope.asOf) : undefined;
  const assetNames = new Map(scopedAssets?.map((asset) => [JSON.stringify([asset.site_id, asset.asset_id]), asset.hostname || asset.asset_id]));
  const currentView = scope.drawer ? "overview" : scope.view;

  const link = (changes: Partial<Scope>) => dashboardUrl(overview, changes);
  const close = () => router.push(link({ view: "overview" }), { scroll: false });
  const changeScope = (changes: Partial<Scope>) => {
    const current = readScope(new URLSearchParams(window.location.search));
    window.history.pushState(null, "", dashboardUrl({ ...current, asOf: current.asOf ?? now }, changes));
  };
  const refresh = () => {
    setNow(Date.now());
    router.replace(dashboardUrl(scope, { asOf: null, bucket: null }), { scroll: false });
  };

  function assetDetails(asset: Asset) {
    return <dl className="details-list">
      <dt>Site</dt><dd>{siteName(asset.site_id)}</dd>
      <dt>Device category</dt><dd className="capitalize">{categoryLabel(assetCategory(asset))}</dd>
      <dt>Address</dt><dd>{asset.primary_ip || "Unknown"}</dd>
      <dt>Platform</dt><dd>{asset.os || asset.platform || "Unknown"}</dd>
      <dt>Latest observation</dt><dd>{formatDate(timestamp(asset.observed_at) ?? timestamp(asset.last_seen_at))}</dd>
      <dt>Observation source</dt><dd>{asset.observation_source || asset.source_agent_id || "Unknown"}</dd>
      <dt>Evidence records</dt><dd>{asset.evidence_count.toLocaleString()}</dd>
    </dl>;
  }

  function findingRows(rows: Finding[]) {
    return rows.map((finding) => [finding.finding_id,
      <><strong>{finding.asset_id ? assetNames.get(JSON.stringify([finding.site_id, finding.asset_id])) || finding.asset_id : siteName(finding.site_id)}</strong><small>{siteName(finding.site_id)}</small></>,
      <span className={`severity ${finding.severity}`}>{finding.severity}</span>,
      finding.title,
      <Link className="text-link" href={link({ view: "findings", finding: finding.finding_id, drawer: true })} prefetch={false}>Details <span aria-hidden="true">→</span></Link>,
    ]);
  }

  function activityList(limit: number) {
    if (!activity) return <p className="message">{unavailable(assets)}</p>;
    if (!activity.length) return <p className="message">No asset observations in this time range.</p>;
    return <div className="activity-list">{activity.slice(0, limit).map(({ asset, observed }) => <Link className="activity-item" key={asset.asset_key}
      href={link({ view: "evidence", asset: asset.asset_key, drawer: true })} prefetch={false}>
      <span className="activity-icon" aria-hidden="true">↻</span>
      <span><strong>{asset.hostname || asset.asset_id}</strong><small>{asset.observation_source || "Inventory observation"} · {siteName(asset.site_id)}</small></span>
      <time dateTime={new Date(observed).toISOString()}>{formatDate(observed)}</time>
    </Link>)}</div>;
  }

  function viewDetails() {
    if (scope.view === "findings") {
      if (!priority) return <p className="message">{unavailable(findingError)}</p>;
      if (scope.finding) {
        const finding = priority.find(({ finding_id }) => finding_id === scope.finding);
        if (!finding) return <p className="message">This finding is outside the available results.</p>;
        return <><h3>{finding.title}</h3><p>{finding.description}</p><dl className="details-list">
          <dt>Severity</dt><dd className="capitalize">{finding.severity}</dd><dt>Status</dt><dd className="capitalize">{finding.status}</dd>
          <dt>Site</dt><dd>{siteName(finding.site_id)}</dd><dt>First seen</dt><dd>{formatDate(timestamp(finding.first_seen_at))}</dd>
          <dt>Evidence freshness</dt><dd className="capitalize">{finding.evidence_freshness}</dd>
        </dl><div className="recommendation"><strong>Recommendation</strong><p>{finding.recommendation}</p></div></>;
      }
      const interval = scope.bucket === null ? undefined : intervals?.[scope.bucket];
      const rows = filterFindings(priority, scope.severity, interval);
      return <>
        {interval && <p className="filter-label">First seen {formatDate(interval.start)} to {formatDate(interval.end)}</p>}
        {scope.severity && <p className="filter-label capitalize">{scope.severity} severity</p>}
        {truncated && <p className="message">Showing up to 200 findings per status. These results are partial.</p>}
        {rows.length ? <Table columns={["Subject", "Severity", "Finding", "Details"]} rows={findingRows(rows)} /> : <p className="message">No open findings match this selection.</p>}
      </>;
    }
    if (scope.view === "assets" || scope.view === "evidence") {
      if (!scopedAssets) return <p className="message">{unavailable(assets)}</p>;
      if (scope.asset) {
        const asset = scopedAssets.find(({ asset_key }) => asset_key === scope.asset);
        return asset ? <><h3>{asset.hostname || asset.asset_id}</h3>{assetDetails(asset)}</> : <p className="message">This asset is outside the selected scope.</p>;
      }
      if (scope.view === "evidence") return activityList(Infinity);
      const rows = (scope.newAssets ? newAssets ?? [] : scopedAssets).filter((asset) => !scope.category || assetCategory(asset) === scope.category);
      return <>
        {(scope.category || scope.newAssets) && <p className="filter-label capitalize">{scope.category ? categoryLabel(scope.category) : ranges[scope.range][0]}</p>}
        <p className="muted">{rows.length.toLocaleString()} {rows.length === 1 ? "asset" : "assets"}</p>
        {rows.length > 0 && <Table columns={["Asset", "Category", "Site", "Last observed"]} rows={rows.map((asset) => [asset.asset_key,
          <Link className="text-link" href={link({ view: "assets", asset: asset.asset_key, drawer: true })} prefetch={false}>{asset.hostname || asset.asset_id}</Link>,
          <span className="capitalize">{categoryLabel(assetCategory(asset))}</span>, siteName(asset.site_id), formatDate(timestamp(asset.observed_at) ?? timestamp(asset.last_seen_at)),
        ])} />}
      </>;
    }
    if (scope.view === "collectors") {
      if (!scopedCollectors) return <p className="message">{unavailable(collectors)}</p>;
      const rows = scopedCollectors.filter((collector) => !scope.collector || collectorState(collector, now) === scope.collector);
      return <>
        <p className="muted">Reporting requires a check-in within 15 minutes.</p>
        {rows.length ? <Table columns={["Collector", "Site", "Check-in status", "Last seen"]} rows={rows.map((collector) => [collector.agent_id,
          <><strong>{collector.display_name || collector.hostname || collector.agent_id}</strong><small>{collector.agent_type}</small></>,
          siteName(collector.site_id), stateLabel[collectorState(collector, now)], formatDate(timestamp(collector.last_seen_at)),
        ])} /> : <p className="message">No enrolled collectors in this scope.</p>}
      </>;
    }
    if (!sites?.data || !scopedAssets) return <p className="message">{unavailable(!sites?.data ? sites : assets)}</p>;
    const rows = assetCountsBySite(scopedAssets, siteList, scope.site);
    return rows.length ? <Table columns={["Site", "Assets"]} rows={rows.map(({ id, name, count }) => [id,
      <Link className="text-link" href={link({ view: "assets", site: id })} prefetch={false}>{name}</Link>, count.toLocaleString(),
    ])} /> : <p className="message">No sites in this scope.</p>;
  }

  const showOverview = scope.view === "overview" || scope.drawer;
  const resultsTitle = scope.view === "findings" && scope.bucket !== null ? "Findings in interval"
    : scope.view === "findings" && scope.finding ? "Finding details"
    : scope.view === "assets" && scope.asset ? "Asset details"
    : scope.view === "assets" && scope.newAssets ? "Newly observed assets"
    : viewLabel(scope.view);

  return <AppShell view={currentView} site={scopeName}
    snapshot={now ? `Snapshot requested ${formatDate(now)}` : "Connecting to Control Tower…"}
    findingTotal={findingTotal} search={{ scope: overview, assets: scopedAssets, findings, pending: !assets || (!findings && !findingError), truncated }}>
      <header className="heading"><div><span className="eyebrow">Asset intelligence</span><h1>{viewLabel(currentView)}</h1>
        {showOverview && <p>See what’s connected, what changed, and where to focus next.</p>}</div>
        <div className="header-actions">
          <select aria-label="Site" value={scope.site} onChange={(event) => changeScope({ site: event.target.value, asset: null, finding: null })}>
            <option value="">All sites</option>
            {scope.site && !siteList.some(({ site_id }) => site_id === scope.site) && <option value={scope.site}>{scope.site}</option>}
            {[...siteList].sort((a, b) => a.name.localeCompare(b.name)).map((site) => <option key={site.site_id} value={site.site_id}>{site.name || site.site_id}</option>)}
          </select>
          <button type="button" className="primary-button" onClick={refresh}><span aria-hidden="true">↻</span> Refresh</button>
        </div>
      </header>

      {showOverview ? <>
        <div className={`notice ${reporting ? "reporting" : ""}`} role="status">
          <i aria-hidden="true" /><strong>{!scopedCollectors ? unavailable(collectors) : !scopedCollectors.length ? "No enrolled collectors" : `${reporting} of ${scopedCollectors.length} collectors reporting`}</strong>
          {latestCheckIn !== null && <span>Latest check-in {formatDate(latestCheckIn)}</span>}
          <Link className="text-link" href={link({ view: "collectors", drawer: true })} prefetch={false}>View collector health ↗</Link>
        </div>
        <section className="kpis" aria-label="Asset summary">
          <Kpi label="Assets observed" icon="◇" count={scopedAssets?.length} note="Current inventory" url={link({ view: "assets" })} />
          <Kpi label="Needs attention" icon="△" count={findingTotal} note="Active and acknowledged findings" url={link({ view: "findings" })} />
          <Kpi label="Reporting collectors" icon="✓" count={reporting} note={scopedCollectors ? `Of ${scopedCollectors.length.toLocaleString()} enrolled` : "Latest check-in status"} url={link({ view: "collectors", collector: "reporting" })} />
          <Kpi label="Newly observed" icon="✦" count={newAssets?.length} note={ranges[scope.range][0]} url={link({ view: "assets", newAssets: true, drawer: true })} />
        </section>
        <div className="dashboard-row">
          <Panel title="Exposure trend" subtitle="Currently open findings by first-seen time" className="trend-panel"
            action={<select className="range-select" aria-label="Date range" value={scope.range}
              onChange={(event) => changeScope({ range: event.target.value as Scope["range"], bucket: null })}>
              {Object.entries(ranges).map(([value, [label]]) => <option key={value} value={value}>{label}</option>)}
            </select>}>
            {intervals && now > 0 ? <FindingChart intervals={intervals} scope={overview} /> : <p className="message">{unavailable(findingError)}</p>}
            {truncated && <p className="muted" role="status">Partial data · up to 200 findings per status</p>}
          </Panel>
          {scopedAssets ? <AssetChart assets={scopedAssets} scope={overview} /> : <Panel title="Discovered assets" subtitle="By device category" className="discovery-panel"><p className="message">{unavailable(assets)}</p></Panel>}
        </div>
        <div className="dashboard-row lower-row">
          <Panel title="Priority findings" subtitle="Open findings ordered by severity" className="findings-panel"
            action={<Link className="panel-action" href={link({ view: "findings" })} prefetch={false}>View all ↗</Link>}>
            {!priority ? <p className="message">{unavailable(findingError)}</p> : priority.length ?
              <Table columns={["Subject", "Severity", "Finding", "Details"]} rows={findingRows(priority.slice(0, 4))} /> : <p className="message">No open findings in this scope.</p>}
          </Panel>
          <Panel title="Recent activity" subtitle="Latest inventory observation per asset" className="activity-panel"
            action={<Link className="panel-action" href={link({ view: "evidence" })} prefetch={false}>View evidence ↗</Link>}>
            {activityList(4)}
          </Panel>
        </div>
      </> : <Panel title={resultsTitle} subtitle={scopeName} className="detail-panel">{viewDetails()}</Panel>}

    {scope.drawer && <DetailDrawer title={resultsTitle} subtitle={scopeName} close={close}>{viewDetails()}</DetailDrawer>}
  </AppShell>;
}
