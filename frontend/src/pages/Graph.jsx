import { useState } from "react";
import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";

export default function Graph() {
  const [sample] = useState([
    {
      hop: 1,
      server: "smtp.evilhost.xyz",
      ip: "185.221.44.88",
      timestamp: "06 Sep 2026 08:58 UTC",
    },
    {
      hop: 2,
      server: "relay01.mailprovider.net",
      ip: "172.217.12.20",
      timestamp: "06 Sep 2026 09:01 UTC",
    },
    {
      hop: 3,
      server: "outlook.office365.com",
      ip: "40.92.18.5",
      timestamp: "06 Sep 2026 09:03 UTC",
    },
  ]);

  return (
    <AppLayout>
      <section className="mb-12">
        <p className="text-[11px] uppercase tracking-[0.25em] text-zinc-500 mb-3">
          Investigation Graph
        </p>

        <h1 className="text-4xl font-semibold tracking-tight">
          Email Routing Timeline
        </h1>
      </section>

      <Panel title="SMTP Received Chain" subtitle="MAIL RELAY FORENSICS">
        <div className="relative ml-2 border-l border-zinc-800 pl-8">
          {sample.map((hop, index) => (
            <div key={hop.hop} className="mb-10 relative">
              <div className="absolute -left-[37px] top-1 h-4 w-4 rounded-full bg-blue-500 ring-4 ring-black" />

              <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                Hop {hop.hop}
              </p>

              <h3 className="mt-2 text-lg font-medium">{hop.server}</h3>

              <p className="text-sm text-zinc-400">{hop.ip}</p>

              <p className="mt-2 text-xs text-zinc-500">{hop.timestamp}</p>

              {index !== sample.length - 1 && (
                <div className="mt-5 h-8 border-l border-dashed border-zinc-700 ml-1" />
              )}
            </div>
          ))}
        </div>
      </Panel>
    </AppLayout>
  );
}