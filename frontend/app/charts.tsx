import Link from "next/link";
import { useState, type ReactNode } from "react";
import { severities, type Asset } from "../lib/contracts";
import { assetsByCategory, dashboardUrl, findingIntervals, type Scope } from "../lib/dashboard";

const categoryColors = ["var(--category-1)", "var(--category-2)", "var(--category-3)", "var(--category-4)", "var(--category-5)", "var(--category-6)", "var(--category-7)"];

export function Panel({ title, subtitle, action, className = "", children }: { title: string; subtitle?: string; action?: ReactNode; className?: string; children: ReactNode }) {
  return <section className={`panel panel-pad ${className}`} aria-label={title}>
    <header className="panel-head"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</header>
    {children}
  </section>;
}

export function categoryLabel(value: string) {
  return value.replaceAll(/[_-]/g, " ");
}

export function FindingChart({ intervals, scope }: { intervals: ReturnType<typeof findingIntervals>; scope: Scope }) {
  const chart = intervals.map(({ counts, start, end }) => ({ start, end, count: severities.reduce((sum, severity) => sum + counts[severity], 0) }));
  const ceiling = Math.max(3, Math.ceil(Math.max(...chart.map(({ count }) => count)) / 3) * 3);
  const points = chart.map(({ count }, index) => ({ x: 6 + index * 97.6, y: 150 - count / ceiling * 128 }));
  const line = points.map(({ x, y }) => `${x},${y}`).join(" ");
  const dateLabel = new Intl.DateTimeFormat(undefined, scope.range === "24h" ? { hour: "numeric" } : { month: "short", day: "numeric" });
  return <>
    <div className="trend">
      <div className="trend-axis" aria-hidden="true">{[ceiling, ceiling * 2 / 3, ceiling / 3, 0].map((tick) => <span key={tick}>{tick}</span>)}</div>
      <div className="trend-plot">
        <svg viewBox="0 0 500 160" preserveAspectRatio="none" aria-hidden="true">
          <defs>
            <linearGradient id="trend-line"><stop stopColor="var(--trend-start)" /><stop offset=".5" stopColor="var(--trend-middle)" /><stop offset="1" stopColor="var(--trend-end)" /></linearGradient>
            <linearGradient id="trend-area" x2="0" y2="1"><stop stopColor="var(--trend-fill)" stopOpacity=".26" /><stop offset="1" stopColor="var(--trend-end)" stopOpacity="0" /></linearGradient>
          </defs>
          {[22, 65, 107, 150].map((y) => <line key={y} x1="0" x2="500" y1={y} y2={y} className="grid-line" />)}
          <polygon points={`6,150 ${line} 494,150`} fill="url(#trend-area)" />
          <polyline points={line} fill="none" stroke="url(#trend-line)" strokeWidth="2.6" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        </svg>
        {points.map(({ x, y }, index) => <Link key={chart[index].start} className="trend-point" prefetch={false}
          href={dashboardUrl(scope, { view: "findings", bucket: index, drawer: true })}
          style={{ left: `${x / 5}%`, top: `${y / 1.6}%` }}
          title={`${new Date(chart[index].start).toLocaleString()} – ${new Date(chart[index].end).toLocaleString()} · ${chart[index].count} findings`}
          aria-label={`${chart[index].count} open findings first seen from ${new Date(chart[index].start).toLocaleString()} to ${new Date(chart[index].end).toLocaleString()}`} />)}
      </div>
      <div className="trend-dates" aria-hidden="true">{chart.map(({ start }) => <span key={start}>{dateLabel.format(start)}</span>)}</div>
    </div>
    <div className="chart-footer">
      <span><i className="swatch" style={{ background: "var(--trend-middle)" }} />Currently open findings</span>
      <details className="chart-data"><summary>View data</summary>
        <div className="table-scroll" tabIndex={0} aria-label="Finding counts by first-seen interval">
          <table><thead><tr><th>Interval start</th><th>Open findings</th></tr></thead>
            <tbody>{chart.map(({ start, count }, index) => <tr key={start}>
              <td><Link className="text-link" href={dashboardUrl(scope, { view: "findings", bucket: index, drawer: true })} prefetch={false}>{new Date(start).toLocaleString()}</Link></td><td>{count}</td>
            </tr>)}</tbody>
          </table>
        </div>
      </details>
    </div>
  </>;
}

export function AssetChart({ assets, scope }: { assets: Asset[]; scope: Scope }) {
  const [display, setDisplay] = useState<"donut" | "bars">("donut");
  const groups = assetsByCategory(assets);
  const biggest = groups[0]?.count ?? 1;
  let offset = 0;
  return <Panel title="Discovered assets" subtitle="By device category" className="discovery-panel"
    action={<div className="chart-switch" role="group" aria-label="Chart type">
      <button type="button" aria-pressed={display === "donut"} onClick={() => setDisplay("donut")}>Donut</button>
      <button type="button" aria-pressed={display === "bars"} onClick={() => setDisplay("bars")}>Bars</button>
    </div>}>
    {!groups.length ? <p className="message">No inventory assets in this scope.</p> : <div className={display === "donut" ? "discovery" : "asset-bars"}>
      {display === "donut" && <div className="donut">
        <svg viewBox="0 0 140 140" role="group" aria-label="Asset categories">
          {groups.map(({ id, count }, index) => {
            const share = count / assets.length * 100;
            const start = offset;
            offset += share;
            const gap = groups.length > 1 ? Math.min(0.8, share / 3) : 0;
            const quantity = `${count.toLocaleString()} ${count === 1 ? "asset" : "assets"}`;
            return <Link key={id} prefetch={false} href={dashboardUrl(scope, { view: "assets", category: id, drawer: true })} aria-label={`${categoryLabel(id)}: ${quantity}`}>
              <title>{`${categoryLabel(id)} · ${quantity} · ${share.toLocaleString(undefined, { maximumFractionDigits: 1 })}%`}</title>
              <circle cx="70" cy="70" r="54" pathLength="100" transform="rotate(-90 70 70)" fill="none"
                stroke={categoryColors[index % categoryColors.length]} strokeDasharray={`${share - gap} ${100 - share + gap}`} strokeDashoffset={-start} />
            </Link>;
          })}
        </svg>
        <div className="donut-center" aria-hidden="true"><strong>{assets.length.toLocaleString()}</strong><small>total assets</small></div>
      </div>}
      <div className={display === "donut" ? "asset-legend" : "asset-bar-list"} aria-label="Asset category counts">
        {groups.map(({ id, count }, index) => <Link key={id} className="category-row" prefetch={false}
          href={dashboardUrl(scope, { view: "assets", category: id, drawer: true })}>
          <span className="category-name">{display === "donut" && <i className="swatch" style={{ background: categoryColors[index % categoryColors.length] }} />}{categoryLabel(id)}</span>
          {display === "bars" && <span className="bar-track" aria-hidden="true"><span style={{ width: `${count / biggest * 100}%`, background: categoryColors[index % categoryColors.length] }} /></span>}
          <strong>{count.toLocaleString()}</strong>
        </Link>)}
      </div>
    </div>}
  </Panel>;
}
