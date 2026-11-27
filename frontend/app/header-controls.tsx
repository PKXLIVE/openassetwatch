"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { searchWorkspace, type SearchSource } from "../lib/search";
import { ThemeToggle } from "./theme-toggle";

const noticeExamples = [
  { id: "inventory", category: "Discovery", title: "Inventory refresh example", message: "New observations appear in Assets." },
  { id: "findings", category: "Findings", title: "Finding review example", message: "Review evidence in the Findings workspace." },
] as const;

function Icon({ name }: { name: "search" | "bell" | "account" }) {
  const paths = {
    search: "M15 15l4.6 4.6M16.25 10.5a5.75 5.75 0 1 1-11.5 0 5.75 5.75 0 0 1 11.5 0Z",
    bell: "M18 8a6 6 0 0 0-12 0c0 6-2 7-2 8.5h16C20 15 18 14 18 8ZM10 20a2 2 0 0 0 4 0",
    account: "M5 19v-1a5 5 0 0 1 5-5h4a5 5 0 0 1 5 5v1M15 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z",
  };
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d={paths[name]} />
  </svg>;
}

export function HeaderControls({ source, overviewUrl }: { source: SearchSource; overviewUrl: string }) {
  const [panel, setPanel] = useState<"notifications" | "account" | null>(null);
  const [read, setRead] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const searchButton = useRef<HTMLButtonElement>(null);
  const bell = useRef<HTMLButtonElement>(null);
  const account = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const groups = open ? searchWorkspace(source, query) : [];
  const count = groups.reduce((total, group) => total + group.items.length, 0);
  const unread = noticeExamples.length - read.length;
  const unavailable = source.assets === undefined && source.findings === undefined;
  const emptySearch = source.pending ? "Loading search sources…" : unavailable ? "Inventory and findings are unavailable."
    : query.trim() ? "No matches in available sources." : "Search by asset, hostname, IP address, or finding.";

  const showSearch = useCallback(() => {
    const modal = dialog.current;
    if (modal && !modal.open) {
      searchButton.current?.focus();
      setPanel(null);
      setQuery("");
      setOpen(true);
      modal.showModal();
    }
    input.current?.focus();
  }, []);

  useEffect(() => {
    function keyboard(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === "k" && !event.defaultPrevented) {
        if (document.querySelector("dialog[open]:not(#workspace-search)")) return;
        event.preventDefault();
        showSearch();
      }
    }

    document.addEventListener("keydown", keyboard);
    return () => document.removeEventListener("keydown", keyboard);
  }, [showSearch]);

  useEffect(() => {
    if (!panel) return;
    const trigger = panel === "notifications" ? bell.current : account.current;
    const region = menu.current;
    region?.querySelector<HTMLElement>("button:not(:disabled):not([aria-disabled='true']), a")?.focus();

    function dismiss(event: Event) {
      if (event.target instanceof Node && !trigger?.contains(event.target) && !region?.contains(event.target)) setPanel(null);
    }
    function escape(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      event.preventDefault();
      setPanel(null);
      trigger?.focus();
    }

    document.addEventListener("pointerdown", dismiss);
    document.addEventListener("focusin", dismiss);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", dismiss);
      document.removeEventListener("focusin", dismiss);
      document.removeEventListener("keydown", escape);
    };
  }, [panel]);

  function markRead(id: string) {
    setRead((previous) => previous.includes(id) ? previous : [...previous, id]);
  }

  return <div className="header-utilities">
    <button className="shell-control header-search" ref={searchButton} type="button" aria-haspopup="dialog" aria-controls="workspace-search" aria-keyshortcuts="Control+K Meta+K" onClick={showSearch}>
      <Icon name="search" /><span>Search OpenAssetWatch...</span><kbd aria-hidden="true">Ctrl + K</kbd>
    </button>
    <button className="shell-control header-bell" ref={bell} type="button" aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
      aria-controls="header-notifications" aria-expanded={panel === "notifications"} onClick={() => setPanel(panel === "notifications" ? null : "notifications")}>
      <Icon name="bell" />{unread > 0 && <span className="header-badge" aria-hidden="true" title="Unread demonstration notifications">{unread}</span>}
    </button>
    <ThemeToggle />
    <button className="shell-control account-control" ref={account} type="button" aria-controls="header-account" aria-expanded={panel === "account"}
      onClick={() => setPanel(panel === "account" ? null : "account")}>
      <span className="account-avatar"><Icon name="account" /></span>Account <span className="account-chevron" aria-hidden="true">⌄</span>
    </button>

    {panel === "notifications" && <section ref={menu} className="header-popover" id="header-notifications" aria-labelledby="notification-heading">
      <div className="header-popover-top">
        <div><h2 id="notification-heading">Notifications</h2><p className="muted" role="status">Demonstration · {unread ? `${unread} unread` : "All read"}</p></div>
        <button className="quiet-button" type="button" aria-disabled={!unread} onClick={() => { if (unread) setRead(noticeExamples.map(({ id }) => id)); }}>Mark all read</button>
      </div>
      {noticeExamples.map(({ id, category, title, message }) => <div className="notification-category" key={id}>
        <h3>{category}</h3>
        <button className="header-list-item" type="button" onClick={() => markRead(id)}>
          <span><strong>{title}</strong><small>{message}</small></span><span className="notification-state">{read.includes(id) ? "Read" : "Mark read"}</span>
        </button>
      </div>)}
    </section>}

    {panel === "account" && <section ref={menu} className="header-popover account-popover" id="header-account" aria-labelledby="account-heading">
      <div className="header-popover-top"><div><h2 id="account-heading">Local workspace</h2><p className="muted">Profile details unavailable</p></div></div>
      <Link className="header-list-item" href={overviewUrl} prefetch={false} onClick={() => { setPanel(null); account.current?.focus(); }}>Overview</Link>
      <button className="header-list-item" type="button" onClick={showSearch}>Search workspace</button>
    </section>}

    <dialog className="workspace-search" id="workspace-search" ref={dialog} aria-labelledby="search-heading" onClose={() => setOpen(false)}
      onClick={(event) => { if (event.target === event.currentTarget) event.currentTarget.close(); }}
      onKeyDown={(event) => {
        if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); event.currentTarget.close(); return; }
        const rows = [...event.currentTarget.querySelectorAll<HTMLAnchorElement>(".search-match")];
        const focused = rows.indexOf(document.activeElement as HTMLAnchorElement);
        if (!rows.length || (event.target !== input.current && focused < 0)) return;
        if (event.key === "ArrowDown") { event.preventDefault(); rows[Math.min(focused + 1, rows.length - 1)].focus(); }
        if (event.key === "ArrowUp") { event.preventDefault(); if (focused === 0) input.current?.focus(); else rows[focused < 0 ? rows.length - 1 : focused - 1].focus(); }
        if (event.key === "Enter" && event.target === input.current) { event.preventDefault(); rows[0].click(); }
      }}>
      <div className="workspace-search-body">
        <div className="header-popover-top"><h2 id="search-heading">Search OpenAssetWatch</h2>
          <button className="quiet-button" type="button" aria-label="Close search" onClick={() => dialog.current?.close()}>×</button>
        </div>
        <input className="workspace-search-input" ref={input} type="search" aria-label="Search workspace data" placeholder="Search OpenAssetWatch..." maxLength={160}
          autoComplete="off" value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
        <p className="search-source-note muted">Searches the loaded inventory and findings in this scope. Vulnerability and knowledge lookup are unavailable.</p>
        {!source.pending && !unavailable && source.assets === undefined && <p className="search-source-note muted">Inventory is unavailable.</p>}
        {!source.pending && !unavailable && source.findings === undefined && <p className="search-source-note muted">Findings are unavailable.</p>}
        {source.findings && source.truncated && <p className="search-source-note muted">Finding results are partial.</p>}
        <p className="visually-hidden" role="status">{count} {count === 1 ? "result" : "results"}</p>
        <div className="workspace-search-results">
          {!groups.length && <p className="message">{emptySearch}</p>}
          {groups.map(({ label, items }) => <section className="search-group" key={label}>
            <h3>{label}</h3>
            {items.map(({ id, title, description, href }) => <Link className="header-list-item search-match" key={id} href={href} prefetch={false} onClick={() => dialog.current?.close()}>
              <span><strong>{title}</strong><small>{description}</small></span><span aria-hidden="true">↗</span>
            </Link>)}
          </section>)}
        </div>
        <p className="search-source-note muted" aria-hidden="true">↑ ↓ Move · Enter Open · Esc Close</p>
      </div>
    </dialog>
  </div>;
}
