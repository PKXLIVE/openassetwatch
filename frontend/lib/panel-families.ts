export type PanelState = "loading" | "ready" | "empty" | "missing" | "stale" | "partial" | "unavailable" | "error";

export interface SeriesPoint {
  label: string;
  value: number | null;
}

export interface RankedValue {
  id: string;
  label: string;
  value: number;
}

export interface CompositionValue extends RankedValue {}

export type OperationalStatus = "unknown" | "late" | "disabled" | "degraded" | "healthy";

export interface StatusMatrixEntry {
  id: string;
  label: string;
  status: OperationalStatus;
}

export interface StatusMatrixRow {
  id: string;
  label: string;
  entries: StatusMatrixEntry[];
}

export function formatMetricValue(state: PanelState, value: number | null, format: (value: number) => string = (n) => n.toLocaleString()) {
  if (state === "loading") return "Loading";
  if (state === "missing") return "No measurement";
  if (state === "unavailable") return "Unavailable";
  if (state === "error") return "Could not load";
  if (value === null || !Number.isFinite(value)) return "No measurement";
  return format(value);
}

export interface IndexedSeriesPoint extends Omit<SeriesPoint, "value"> {
  value: number;
  index: number;
}

export function segmentSeries(points: SeriesPoint[], maxPoints = 60): IndexedSeriesPoint[][] {
  if (!Number.isInteger(maxPoints) || maxPoints < 1) throw new RangeError("maxPoints must be a positive integer");
  const runs: IndexedSeriesPoint[][] = [];
  points.forEach((point, index) => {
    const { label, value } = point;
    if (typeof value !== "number" || !Number.isFinite(value)) return;
    const indexed: IndexedSeriesPoint = { label, value, index };
    const last = runs.at(-1);
    if (last && last.at(-1)!.index === index - 1) last.push(indexed);
    else runs.push([indexed]);
  });
  if (!runs.length) return [];

  if (runs.length > maxPoints) {
    const stride = (runs.length - 1) / (maxPoints - 1 || 1);
    return Array.from({ length: maxPoints }, (_, index) => {
      const run = runs[Math.round(index * stride)];
      return [run[Math.floor((run.length - 1) / 2)]];
    });
  }

  const allocations = runs.map(() => 1);
  let remaining = maxPoints - runs.length;
  while (remaining > 0) {
    let candidate = -1;
    let priority = 0;
    for (let index = 0; index < runs.length; index++) {
      const score = runs[index].length / allocations[index];
      if (allocations[index] < runs[index].length && score > priority) {
        candidate = index;
        priority = score;
      }
    }
    if (candidate < 0) break;
    allocations[candidate]++;
    remaining--;
  }

  return runs.map((run, runIndex) => {
    const count = allocations[runIndex];
    if (count >= run.length) return run;
    return Array.from({ length: count }, (_, index) => run[Math.round(index * (run.length - 1) / (count - 1 || 1))]);
  });
}

export function rankValues(values: RankedValue[], limit = 10) {
  if (!Number.isInteger(limit) || limit < 1) throw new RangeError("limit must be a positive integer");
  const valid = values.filter(({ value }) => Number.isFinite(value) && value >= 0)
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  return { rows: valid.slice(0, limit), truncated: valid.length > limit, total: valid.length };
}

export function composeValues(values: CompositionValue[], denominator: number, limit = 7) {
  if (!Number.isFinite(denominator) || denominator < 0) throw new RangeError("denominator must be finite and non-negative");
  if (!Number.isInteger(limit) || limit < 1) throw new RangeError("limit must be a positive integer");
  const ranked = rankValues(values, Math.max(limit, values.length));
  const visible = ranked.rows.slice(0, limit);
  const hiddenCount = values.filter(({ value }) => Number.isFinite(value) && value >= 0).length - visible.length;
  if (hiddenCount > 0) {
    const visibleIds = new Set(visible.map(({ id }) => id));
    const other = values.filter(({ id, value }) => !visibleIds.has(id) && Number.isFinite(value) && value >= 0)
      .reduce((sum, { value }) => sum + value, 0);
    visible.push({ id: "other", label: "Other", value: other });
  }
  return {
    rows: visible.map((row) => ({ ...row, share: denominator === 0 ? null : row.value / denominator * 100 })),
    denominator,
    shareAvailable: denominator > 0,
    truncated: hiddenCount > 0,
  };
}

export function formatCompositionValue(value: number, share: number | null) {
  const renderedShare = share === null
    ? "Share unavailable"
    : `${share.toLocaleString(undefined, { maximumFractionDigits: 1 })}%`;
  return `${value.toLocaleString()} (${renderedShare})`;
}

export function boundStatusMatrix(rows: StatusMatrixRow[], maxRows = 25, maxColumns = 12) {
  if (!Number.isInteger(maxRows) || maxRows < 1 || !Number.isInteger(maxColumns) || maxColumns < 1) {
    throw new RangeError("matrix row and column limits must be positive integers");
  }
  const columns = [...new Map(rows.flatMap((row) => row.entries.map((entry) => [entry.id, { id: entry.id, label: entry.label }]))).values()]
    .slice(0, maxColumns);
  const columnIds = new Set(columns.map(({ id }) => id));
  const boundedRows = rows.slice(0, maxRows).map((row) => {
    const entries = new Map(row.entries.filter(({ id }) => columnIds.has(id)).map((entry) => [entry.id, entry]));
    return { ...row, entries: columns.map((column) => entries.get(column.id) ?? { ...column, status: "unknown" as const }) };
  });
  return { columns, rows: boundedRows, truncated: rows.length > maxRows || new Set(rows.flatMap((row) => row.entries.map(({ id }) => id))).size > maxColumns };
}
