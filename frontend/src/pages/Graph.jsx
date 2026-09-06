import AppLayout from "../components/layout/AppLayout";
import { Network } from "lucide-react";

export default function Graph() {
  return (
    <AppLayout>
      <div className="mt-8">
        <p className="text-blue-400 uppercase text-sm tracking-widest">
          Dashboard / Attack Graph
        </p>

        <h1 className="text-4xl font-bold mt-2">Attack Graph</h1>

        <p className="text-slate-400 mt-3">
          Visualize relationships between emails, domains, IP addresses, URLs,
          and attachments using Neo4j.
        </p>

        <div className="mt-8 rounded-2xl bg-[#111827] border border-slate-800 h-[600px] flex flex-col items-center justify-center">
          <Network size={80} className="text-blue-400 mb-4" />

          <h2 className="text-2xl font-semibold">
            Interactive Attack Graph
          </h2>

          <p className="text-slate-500 mt-2 text-center max-w-lg">
            Neo4j graph visualization will appear here after backend integration.
          </p>
        </div>
      </div>
    </AppLayout>
  );
}