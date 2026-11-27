import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { darkThemeQuery, themeBootstrap, themeStorageKey } from "../lib/theme.ts";

function initialTheme(saved, systemDark, storageBlocked = false) {
  const dataset = {};
  runInNewContext(themeBootstrap, {
    document: { documentElement: { dataset } },
    localStorage: {
      getItem(key) {
        assert.equal(key, themeStorageKey);
        if (storageBlocked) throw new Error("Storage unavailable");
        return saved;
      },
    },
    matchMedia(query) {
      assert.equal(query, darkThemeQuery);
      return { matches: systemDark };
    },
  });
  return dataset.theme;
}

test("the first paint uses a saved theme or falls back to system preference", () => {
  assert.equal(initialTheme("light", true), "light");
  assert.equal(initialTheme("dark", false), "dark");
  assert.equal(initialTheme(null, true), "dark");
  assert.equal(initialTheme("invalid", false), "light");
  assert.equal(initialTheme(null, true, true), "dark");
});

function channels(hex) {
  return [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16) / 255);
}

function luminance(rgb) {
  return rgb.reduce((sum, channel, index) => {
    const linear = channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
    return sum + [0.2126, 0.7152, 0.0722][index] * linear;
  }, 0);
}

function contrast(foreground, background) {
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function readColors(css, selector) {
  const start = css.indexOf(`${selector} {`);
  assert.notEqual(start, -1, `Missing ${selector} palette`);
  const block = css.slice(start, css.indexOf("}", start));
  return Object.fromEntries(Array.from(block.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6});/gi), ([, name, value]) => [name, channels(value)]));
}

test("text, chart colors, and control indicators meet their contrast targets in both palettes", async () => {
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf-8");
  const light = readColors(css, ":root");
  const dark = { ...light, ...readColors(css, ':root[data-theme="dark"]') };
  const panels = ["surface", "surface-soft", "cool-panel", "lime-panel", "lavender-panel", "rose-panel", "info-surface"];
  const shell = ["canvas", "canvas-glow", "canvas-wash", "sidebar"];
  const chart = ["surface", "cool-panel", "lavender-panel", "rose-panel"];
  const trend = ["trend-start", "trend-middle", "trend-end"];
  const categories = Array.from({ length: 7 }, (_, index) => `category-${index + 1}`);

  for (const [theme, colors] of Object.entries({ light, dark })) {
    function check(foregrounds, backgrounds, minimum) {
      for (const foreground of foregrounds) {
        for (const background of backgrounds) {
          const ratio = contrast(colors[foreground], colors[background]);
          assert.ok(ratio >= minimum, `${theme} ${foreground} on ${background}: ${ratio.toFixed(2)} < ${minimum}`);
        }
      }
    }
    check(["ink", "muted", "accent"], [...panels, ...shell, "recess", "interactive-hover", "active-surface"], 4.5);
    check(["accent"], ["positive-surface"], 4.5);
    check(["primary-ink"], ["primary-start", "primary-end"], 4.5);
    for (const status of ["positive", "info", "warning", "danger"]) {
      check([`${status}-ink`], [`${status}-surface`], 4.5);
    }
    check(["focus", "control-border"], [...panels, ...shell, "recess", "interactive-hover"], 3);
    check(["positive-mark"], ["positive-surface"], 3);
    check(["toggle-edge"], [...shell, "toggle-track"], 3);
    if (theme === "light") check(["toggle-edge"], ["toggle-thumb"], 3);
    else check(["toggle-thumb"], ["toggle-track"], 3);
    check(["toggle-muted"], ["toggle-track"], 3);
    check(["toggle-active"], ["toggle-thumb"], 3);
    check([...categories, ...trend, "point-ring"], [...chart, "recess", "interactive-hover"], 3);

    for (const background of chart) {
      const fullAreaOpacity = colors[background].map((channel, index) => channel * 0.74 + colors["trend-fill"][index] * 0.26);
      for (const foreground of trend) {
        assert.ok(contrast(colors[foreground], fullAreaOpacity) >= 3, `${theme} ${foreground} over filled ${background}`);
      }
    }
  }
});
