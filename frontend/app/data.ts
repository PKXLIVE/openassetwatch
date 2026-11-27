"use client";

import { useEffect, useState } from "react";

export type Result<T> = { data: T; error?: never } | { error: number; data?: never };

export function useSource<T>(path: string, refresh: number, key?: string) {
  const [loaded, setLoaded] = useState<{ path: string; refresh: number; result: Result<T> }>();

  useEffect(() => {
    if (!refresh) return;
    const controller = new AbortController();
    const resolve = (result: Result<T>) => {
      if (!controller.signal.aborted) setLoaded({ path, refresh, result });
    };

    async function load() {
      try {
        const response = await fetch(`/api/dashboard/${path}`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) return resolve({ error: response.status });
        const body = await response.json();
        const data = key ? body?.[key] : body;
        if (key ? !Array.isArray(data) : !Array.isArray(data?.items) || typeof data?.total !== "number") {
          return resolve({ error: 502 });
        }
        resolve({ data });
      } catch {
        resolve({ error: 502 });
      }
    }

    void load();
    return () => controller.abort();
  }, [path, refresh, key]);

  if (loaded?.path === path && loaded.refresh === refresh) return loaded.result;
}
