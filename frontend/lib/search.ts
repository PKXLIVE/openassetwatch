import type { Asset, Finding } from "./contracts.ts";
import { dashboardUrl, inSite, type Scope } from "./dashboard.ts";

export interface SearchSource {
  scope: Scope;
  assets?: Asset[];
  findings?: Finding[];
  pending?: boolean;
  truncated?: boolean;
}

interface SearchItem {
  id: string;
  title: string;
  description: string;
  href: string;
}

interface SearchGroup {
  label: string;
  items: SearchItem[];
}

export function searchWorkspace({ scope, assets = [], findings = [] }: SearchSource, query: string): SearchGroup[] {
  const words = query.trim().slice(0, 160).toLowerCase().split(/\s+/).filter(Boolean);
  const groups: SearchGroup[] = [
    { label: "Assets", items: [] },
    { label: "Findings", items: [] },
    { label: "IP addresses", items: [] },
    { label: "Hostnames", items: [] },
  ];

  function add(group: SearchGroup, item: Omit<SearchItem, "href">, destination: Partial<Scope>, keywords: string[]) {
    if (group.items.length === 5) return;
    const text = [item.title, item.description, ...keywords].join(" ").toLowerCase();
    if (words.every((word) => text.includes(word))) {
      group.items.push({ ...item, href: dashboardUrl(scope, destination) });
    }
  }

  for (const asset of inSite(assets, scope.site)) {
    if (groups[0].items.length === 5 && groups[2].items.length === 5 && groups[3].items.length === 5) break;
    const { asset_key: id, hostname, primary_ip: address, asset_id: assetId } = asset;
    const description = [asset.site_id, asset.platform].filter(Boolean).join(" · ");
    const destination = { view: "assets", asset: id, drawer: false } as const;
    add(groups[0], { id, title: hostname || assetId, description }, destination, [assetId, address ?? ""]);
    if (address) add(groups[2], { id, title: address, description: hostname || assetId }, destination, [description]);
    if (hostname) add(groups[3], { id, title: hostname, description: address || description }, destination, [assetId]);
  }

  for (const finding of inSite(findings, scope.site)) {
    if (groups[1].items.length === 5) break;
    const id = finding.finding_id;
    const description = [finding.severity, finding.site_id, finding.asset_id].filter(Boolean).join(" · ");
    add(groups[1], { id, title: finding.title, description }, { view: "findings", finding: id, drawer: false }, [id]);
  }

  return groups.filter(({ items }) => items.length > 0);
}
