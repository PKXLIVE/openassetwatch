export const severities = ["critical", "high", "medium", "low", "informational"] as const;
export type Severity = (typeof severities)[number];

export interface Site {
  site_id: string;
  name: string;
  description?: string | null;
}

export interface Asset {
  asset_key: string;
  asset_id: string;
  site_id: string;
  hostname?: string | null;
  primary_ip?: string | null;
  platform?: string | null;
  os?: string | null;
  classification?: { category: string | null } | null;
  source_agent_id?: string | null;
  observation_source?: string | null;
  first_seen_at?: string | null;
  observed_at?: string | null;
  last_seen_at?: string | null;
  evidence_count: number;
}

export interface Collector {
  agent_id: string;
  site_id: string;
  agent_type: string;
  display_name?: string | null;
  hostname?: string | null;
  last_seen_at?: string | null;
}

export interface Finding {
  finding_id: string;
  site_id: string;
  asset_id?: string | null;
  title: string;
  severity: Severity;
  status: "active" | "acknowledged";
  first_seen_at: string;
  evidence_freshness: "fresh" | "aging" | "stale" | "unknown";
  description: string;
  recommendation: string;
}

export interface FindingPage {
  items: Finding[];
  total: number;
  truncated: boolean;
}
