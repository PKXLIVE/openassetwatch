"use client";

import { useSyncExternalStore } from "react";
import { darkThemeQuery, themeStorageKey, type Theme } from "../lib/theme";

let chosenTheme: Theme | undefined;

function subscribeToTheme(onChange: () => void) {
  const root = document.documentElement;
  const system = window.matchMedia(darkThemeQuery);
  const observer = new MutationObserver(onChange);
  observer.observe(root, { attributes: true, attributeFilter: ["data-theme"] });

  function followSystem() {
    if (chosenTheme) return;
    try {
      const saved = localStorage.getItem(themeStorageKey);
      if (saved === "light" || saved === "dark") return;
    } catch {
      // System preference still works when browsing storage is unavailable.
    }
    root.dataset.theme = system.matches ? "dark" : "light";
  }

  system.addEventListener("change", followSystem);
  return () => {
    observer.disconnect();
    system.removeEventListener("change", followSystem);
  };
}

function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function toggleTheme() {
  chosenTheme = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = chosenTheme;
  try {
    localStorage.setItem(themeStorageKey, chosenTheme);
  } catch {
    // The choice still applies to the open dashboard.
  }
}

function Sun() {
  return <svg className="theme-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2.5v3m0 13v3M2.5 12h3m13 0h3M5.3 5.3l2.1 2.1m9.2 9.2 2.1 2.1m0-13.4-2.1 2.1m-9.2 9.2-2.1 2.1" />
  </svg>;
}

function Moon() {
  return <svg className="theme-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12.6 3.2A8.7 8.7 0 1 0 20.8 16a8.1 8.1 0 0 1-8.2-12.8Z" />
    <path d="M18.4 4.5v4m-2-2h4" />
  </svg>;
}

export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribeToTheme, currentTheme, () => "light");
  return <button className="theme-toggle" type="button" aria-label="Dark theme" aria-pressed={theme === "dark"} onClick={toggleTheme}>
    <span className="theme-track" aria-hidden="true">
      <Sun /><Moon />
      <span className="theme-thumb"><Sun /><Moon /></span>
    </span>
  </button>;
}
