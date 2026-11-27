import type { NextConfig } from "next";

const config: NextConfig = {
  devIndicators: false,
  agentRules: false,
  poweredByHeader: false,
  images: { unoptimized: true },
};

export default config;
