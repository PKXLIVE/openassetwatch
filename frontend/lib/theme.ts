export type Theme = "light" | "dark";

export const themeStorageKey = "openassetwatch.theme";
export const darkThemeQuery = "(prefers-color-scheme: dark)";

// This runs in the document head before the dashboard paints or hydrates.
export const themeBootstrap = `(() => {
  let saved;
  try { saved = localStorage.getItem(${JSON.stringify(themeStorageKey)}); } catch {}
  document.documentElement.dataset.theme = saved === "light" || saved === "dark"
    ? saved : matchMedia(${JSON.stringify(darkThemeQuery)}).matches ? "dark" : "light";
})();`;
