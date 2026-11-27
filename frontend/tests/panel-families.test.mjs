import assert from "node:assert/strict";
import test from "node:test";
import { boundStatusMatrix, composeValues, formatCompositionValue, formatMetricValue, rankValues, segmentSeries } from "../lib/panel-families.ts";

test("metric summaries preserve measured zero and distinguish missing or unavailable values", () => {
  assert.equal(formatMetricValue("ready", 0), "0");
  assert.equal(formatMetricValue("missing", null), "No measurement");
  assert.equal(formatMetricValue("unavailable", null), "Unavailable");
});

test("time series downsampling preserves a missing bucket between two displayed points", () => {
  const series = [
    { label: "Monday", value: 1 },
    { label: "Tuesday", value: null },
    { label: "Wednesday", value: 2 },
  ];
  const segments = segmentSeries(series, 2);
  assert.deepEqual(segments.map((segment) => segment.map(({ label }) => label)), [["Monday"], ["Wednesday"]]);
});

test("time series downsamples a continuous run while staying within its point limit", () => {
  const points = Array.from({ length: 120 }, (_, index) => ({ label: String(index), value: index === 50 ? null : index }));
  const segments = segmentSeries(points, 12);
  assert.equal(segments.flat().length, 12);
  assert.equal(segments.length, 2);
});

test("ranked bars sort by value, apply top-N limits, and disclose truncation", () => {
  const result = rankValues([
    { id: "b", label: "Beta", value: 2 }, { id: "a", label: "Alpha", value: 4 }, { id: "c", label: "Gamma", value: 1 },
  ], 2);
  assert.deepEqual(result.rows.map(({ id }) => id), ["a", "b"]);
  assert.equal(result.truncated, true);
  assert.equal(result.total, 3);
});

test("composition names the denominator and groups lower ranked categories as Other", () => {
  const result = composeValues([
    { id: "a", label: "Alpha", value: 7 }, { id: "b", label: "Beta", value: 2 }, { id: "c", label: "Gamma", value: 1 },
  ], 12, 2);
  assert.equal(result.denominator, 12);
  assert.deepEqual(result.rows.map(({ label, value }) => [label, value]), [["Alpha", 7], ["Beta", 2], ["Other", 1]]);
  assert.equal(result.truncated, true);
});

test("composition with a zero denominator retains counts and marks shares unavailable", () => {
  const result = composeValues([{ id: "none", label: "No findings", value: 0 }], 0);
  assert.equal(result.rows[0].value, 0);
  assert.equal(result.rows[0].share, null);
  assert.equal(result.shareAvailable, false);
  assert.equal(formatCompositionValue(result.rows[0].value, result.rows[0].share), "0 (Share unavailable)");
});

test("composition with a positive denominator renders zero numerator as 0 percent", () => {
  const result = composeValues([{ id: "none", label: "No findings", value: 0 }], 5);
  assert.equal(result.rows[0].value, 0);
  assert.equal(result.rows[0].share, 0);
  assert.equal(result.shareAvailable, true);
  assert.equal(formatCompositionValue(result.rows[0].value, result.rows[0].share), "0 (0%)");
});

test("status matrix uses explicit governed states, fills missing checks as unknown, and bounds output", () => {
  const result = boundStatusMatrix([
    { id: "site-a", label: "Site A", entries: [{ id: "collector", label: "Collector", status: "healthy" }] },
    { id: "site-b", label: "Site B", entries: [{ id: "sensor", label: "Sensor", status: "late" }] },
  ], 1, 2);
  assert.deepEqual(result.columns.map(({ id }) => id), ["collector", "sensor"]);
  assert.deepEqual(result.rows[0].entries.map(({ status }) => status), ["healthy", "unknown"]);
  assert.equal(result.truncated, true);
});
