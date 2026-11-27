"use client";

import Image from "next/image";
import Link from "next/link";
import { useState, type ReactNode } from "react";
import { dashboardUrl, type Scope } from "../lib/dashboard";
import type { SearchSource } from "../lib/search";
import { HeaderControls } from "./header-controls";

const navigation = [
  { view: "overview", label: "Overview", icon: "▦", group: "Workspace" },
  { view: "findings", label: "Findings", icon: "⚑", group: "Workspace" },
  { view: "assets", label: "Assets", icon: "◇", group: "Inventory" },
  { view: "sites", label: "Sites", icon: "◎", group: "Inventory" },
  { view: "collectors", label: "Collectors", icon: "⌁", group: "Inventory" },
  { view: "evidence", label: "Evidence", icon: "▤", group: "Evidence" },
] as const;

export function viewLabel(view: Scope["view"]) {
  return navigation.find((item) => item.view === view)?.label ?? "Overview";
}

export function AppShell({ view, site, snapshot, findingTotal, search, children }: {
  view: Scope["view"];
  site: string;
  snapshot: string;
  findingTotal?: number;
  search: SearchSource;
  children: ReactNode;
}) {
  const [compact, setCompact] = useState(false);
  const overview = dashboardUrl(search.scope, { view: "overview" });
  return <div className={compact ? "app-shell shell-compact" : "app-shell"}>
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="sidebar" aria-label="Workspace sidebar">
      <Link href={overview} prefetch={false} aria-label="OpenAssetWatch overview">
        <div className="brand">
          <Image src="/brand/openassetwatch-icon.png" alt="" width={36} height={36} />
          <span>OpenAssetWatch<small>Asset intelligence</small></span>
        </div>
      </Link>
      <nav id="workspace-navigation" className="nav" aria-label="Workspace">
        {["Workspace", "Inventory", "Evidence"].map((group) => <div className="nav-group" key={group}>
          <div className="nav-label">{group}</div>
          {navigation.filter((item) => item.group === group).map(({ view: target, label, icon }) => <Link
            key={target} href={dashboardUrl(search.scope, { view: target })} prefetch={false} aria-current={view === target ? "page" : undefined} aria-label={label}>
            <span className="nav-icon" aria-hidden="true">{icon}</span><span className="nav-text">{label}</span>
            {target === "findings" && findingTotal !== undefined && <span className="nav-count">{findingTotal.toLocaleString()}</span>}
          </Link>)}
        </div>)}
      </nav>
      <div className="side-bottom"><span>Environment</span><strong>{site}</strong></div>
    </aside>
    <div className="shell-content">
      <header className="topbar" aria-label="Dashboard utilities">
        <div className="header-context">
          <button className="shell-control sidebar-size" type="button" aria-label="Compact sidebar" aria-pressed={compact}
            aria-controls="workspace-navigation" onClick={() => setCompact(!compact)}>☰</button>
          <div className="crumb">{site} <span aria-hidden="true">/</span> <strong>{viewLabel(view)}</strong><span className="snapshot">{snapshot}</span></div>
        </div>
        <HeaderControls source={search} overviewUrl={overview} />
      </header>
      <main id="main-content" tabIndex={-1}>{children}</main>
    </div>
  </div>;
}
