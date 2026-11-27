import { Suspense } from "react";
import { Dashboard } from "./dashboard";

export default function Home() {
  return <Suspense fallback={<main className="shell-loading">Loading Control Tower…</main>}><Dashboard /></Suspense>;
}
