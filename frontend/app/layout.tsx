import type { Metadata } from "next";
import type { ReactNode } from "react";
import { themeBootstrap } from "../lib/theme";
import "./globals.css";

export const metadata: Metadata = {
  title: "Control Tower · OpenAssetWatch",
  description: "OpenAssetWatch asset inventory, collector health, and findings.",
  icons: { icon: { url: "/brand/openassetwatch-icon.png", type: "image/png", sizes: "128x128" } },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return <html lang="en" suppressHydrationWarning>
    <head><script dangerouslySetInnerHTML={{ __html: themeBootstrap }} /></head>
    <body>{children}</body>
  </html>;
}
