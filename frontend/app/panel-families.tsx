import type { ReactNode } from "react";
import { Panel } from "./charts";
import { boundStatusMatrix, composeValues, formatCompositionValue, formatMetricValue, rankValues, segmentSeries, type OperationalStatus, type PanelState, type RankedValue, type SeriesPoint, type StatusMatrixRow } from "../lib/panel-families";

function StateMessage({ state, detail }: { state: PanelState; detail?: string }) {
  if (state === "ready" || state === "partial" || state === "stale") return null;
  const copy = { loading: "Loading data…", empty: "No matching records.", missing: "No measurement is available.", unavailable: "This source is unavailable.", error: "This panel could not be loaded.", ready: "", partial: "", stale: "" }[state];
  return <p className="message" role={state === "error" ? "alert" : "status"}>{detail || copy}</p>;
}

function QualityNote({ state, freshness, note }: { state: PanelState; freshness?: string; note?: string }) {
  if (state !== "stale" && state !== "partial" && !freshness && !note) return null;
  return <p className={`panel-quality ${state}`} role="status">{note || (state === "stale" ? "Showing a stale measurement." : state === "partial" ? "Partial results; coverage is incomplete." : `Freshness: ${freshness}`)}</p>;
}

export function MetricSummaryPanel({ title, value, state = "ready", unit, freshness, metricVersion, note }: {
  title: string; value: number | null; state?: PanelState; unit?: string; freshness?: string; metricVersion?: string; note?: string;
}) {
  const rendered = formatMetricValue(state, value);
  const hasValue = value !== null && Number.isFinite(value);
  return <Panel title={title}>
    <StateMessage state={state} />
    {(state === "ready" || state === "stale" || state === "partial") && (hasValue
      ? <div className="family-metric"><strong>{rendered}</strong>{unit && <span>{unit}</span>}</div>
      : <p className="message">No measurement is available.</p>)}
    <QualityNote state={state} freshness={freshness} note={note} />
    {metricVersion && <small className="family-meta">Metric version {metricVersion}</small>}
  </Panel>;
}

export function TimeSeriesPanel({ title, points, state = "ready", freshness, maxPoints = 60 }: {
  title: string; points: SeriesPoint[]; state?: PanelState; freshness?: string; maxPoints?: number;
}) {
  const segments = segmentSeries(points, maxPoints);
  const values = segments.flatMap((segment) => segment.map(({ value }) => value));
  const min = Math.min(0, ...values);
  const max = Math.max(1, ...values);
  const span = max - min || 1;
  const x = (index: number) => points.length < 2 ? 50 : index / (points.length - 1) * 100;
  const y = (value: number) => 100 - (value - min) / span * 92;
  return <Panel title={title}>
    <StateMessage state={state} />
    {state !== "missing" && state !== "unavailable" && state !== "error" && state !== "loading" && <>
      <div className="family-series" role="img" aria-label={`${values.length} displayed time points. Missing buckets split the chart into separate segments.`}>
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          {[10, 40, 70, 99].map((y) => <line key={y} x1="0" x2="100" y1={y} y2={y} className="grid-line" />)}
          {segments.map((segment, index) => segment.length > 1
            ? <polyline key={index} points={segment.map((point) => `${x(point.index)},${y(point.value)}`).join(" ")} fill="none" stroke="var(--trend-middle)" strokeWidth="2" vectorEffect="non-scaling-stroke" />
            : <circle key={index} cx={x(segment[0].index)} cy={y(segment[0].value)} r="1.4" fill="var(--trend-middle)" vectorEffect="non-scaling-stroke" />)}
        </svg>
      </div>
      <div className="family-axis"><span>{points[0]?.label}</span><span>{points.at(-1)?.label}</span></div>
      <details className="chart-data"><summary>View data</summary>
        <div className="table-scroll" tabIndex={0} aria-label={`${title} values`}>
          <table><thead><tr><th scope="col">Time</th><th scope="col">Value</th></tr></thead>
            <tbody>{points.map(({ label, value }, index) => <tr key={`${label}-${index}`}><td>{label}</td><td>{value === null ? "No measurement" : value.toLocaleString()}</td></tr>)}</tbody>
          </table>
        </div>
      </details>
    </>}
    <QualityNote state={state} freshness={freshness} />
  </Panel>;
}

export function RankedBarPanel({ title, values, state = "ready", limit = 10, freshness }: {
  title: string; values: RankedValue[]; state?: PanelState; limit?: number; freshness?: string;
}) {
  const { rows, truncated, total } = rankValues(values, limit);
  const max = Math.max(1, ...rows.map(({ value }) => value));
  return <Panel title={title}>
    <StateMessage state={state} />
    {(state === "ready" || state === "partial" || state === "stale") && rows.length > 0 && <ol className="family-bars" aria-label={`${rows.length} ranked categories`}>
      {rows.map(({ id, label, value }, index) => <li key={id}>
        <span className="family-bar-label">{label}</span><span className="bar-track" aria-hidden="true"><span style={{ width: `${value / max * 100}%`, background: `var(--category-${index % 7 + 1})` }} /></span><strong>{value.toLocaleString()}</strong>
      </li>)}
    </ol>}
    {truncated && <p className="family-meta" role="status">Showing {rows.length} of {total} categories (top {limit}).</p>}
    <QualityNote state={state} freshness={freshness} />
  </Panel>;
}

export function CompositionPanel({ title, values, denominator, state = "ready", limit = 7 }: {
  title: string; values: RankedValue[]; denominator: number; state?: PanelState; limit?: number;
}) {
  const { rows, truncated, shareAvailable } = composeValues(values, denominator, limit);
  return <Panel title={title} subtitle={shareAvailable ? `Share of ${denominator.toLocaleString()} total` : "Share unavailable"}>
    <StateMessage state={state} />
    {(state === "ready" || state === "partial" || state === "stale") && rows.length > 0 && <ul className="family-composition">
      {rows.map(({ id, label, value, share }, index) => <li key={id}>
        <span className="family-bar-label"><i className="swatch" style={{ background: `var(--category-${index % 7 + 1})` }} />{label}</span>
        <span>{formatCompositionValue(value, share)}</span>
      </li>)}
    </ul>}
    {truncated && <p className="family-meta" role="status">Remaining categories are grouped as Other.</p>}
    <QualityNote state={state} />
  </Panel>;
}

export function TablePanel({ title, headers, rows, state = "ready", maxRows = 25, note }: {
  title: string; headers: string[]; rows: ReactNode[][]; state?: PanelState; maxRows?: number; note?: string;
}) {
  if (!Number.isInteger(maxRows) || maxRows < 1) throw new RangeError("maxRows must be a positive integer");
  const shown = rows.slice(0, maxRows);
  return <Panel title={title}>
    <StateMessage state={state} />
    {(state === "ready" || state === "partial" || state === "stale") && rows.length > 0 && <div className="table-scroll" tabIndex={0} aria-label={`${title} data`}>
      <table><thead><tr>{headers.map((header) => <th key={header} scope="col">{header}</th>)}</tr></thead>
        <tbody>{shown.map((row, index) => <tr key={index}>{row.map((value, cellIndex) => <td key={cellIndex}>{value}</td>)}</tr>)}</tbody>
      </table>
    </div>}
    {rows.length > shown.length && <p className="family-meta" role="status">Showing {shown.length} of {rows.length} rows. Refine the filters to see more.</p>}
    <QualityNote state={state} note={note} />
  </Panel>;
}

const statusLabels: Record<OperationalStatus, string> = {
  unknown: "Unknown", late: "Late", disabled: "Disabled", degraded: "Degraded", healthy: "Healthy",
};

export function StatusMatrixPanel({ title, rows, state = "ready", maxRows = 25, maxColumns = 12 }: {
  title: string; rows: StatusMatrixRow[]; state?: PanelState; maxRows?: number; maxColumns?: number;
}) {
  const matrix = boundStatusMatrix(rows, maxRows, maxColumns);
  return <Panel title={title}>
    <StateMessage state={state} />
    {(state === "ready" || state === "partial" || state === "stale") && matrix.rows.length > 0 && <div className="table-scroll" tabIndex={0} aria-label={`${title} status table`}>
      <table className="family-matrix"><caption>Operational status by item and check</caption><thead><tr><th scope="col">Item</th>{matrix.columns.map(({ id, label }) => <th scope="col" key={id}>{label}</th>)}</tr></thead>
        <tbody>{matrix.rows.map(({ id, label, entries }) => <tr key={id}><th scope="row">{label}</th>{entries.map(({ id: entryId, status }) => <td key={entryId}><span className={`status-pill status-${status}`}><i aria-hidden="true" />{statusLabels[status]}</span></td>)}</tr>)}</tbody>
      </table>
    </div>}
    {matrix.truncated && <p className="family-meta" role="status">Status matrix limited to {maxRows} rows and {maxColumns} checks.</p>}
    <QualityNote state={state} />
  </Panel>;
}
