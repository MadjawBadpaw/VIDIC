import { useState } from "react";
import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";

export default function Graph() {
  const [sample] = useState([
    { hop: 1, server: "smtp.evilhost.xyz", ip: "185.221.44.88", timestamp: "06 Sep 2026 08:58 UTC" },
    { hop: 2, server: "relay01.mailprovider.net", ip: "172.217.12.20", timestamp: "06 Sep 2026 09:01 UTC" },
    { hop: 3, server: "outlook.office365.com", ip: "40.92.18.5", timestamp: "06 Sep 2026 09:03 UTC" },
  ]);

  return (
    <AppLayout>
      <section className="mb-10">
        <h1 className="text-[32px] font-semibold tracking-tight text-[var(--text)]">
          Email routing timeline
        </h1>
        <p className="mt-3 text-sm text-[var(--muted)]">
          SMTP relay path reconstructed from Received headers.
        </p>
      </section>

      <Panel title="SMTP received chain">
        <div className="relative ml-2 border-l border-[var(--border)] pl-8">
          {sample.map((hop, index) => (
            <div key={hop.hop} className="relative mb-9 last:mb-0">
              <div className="absolute -left-[37px] top-1 h-3.5 w-3.5 rounded-full bg-[var(--accent)] ring-4 ring-[var(--bg)]" />

              <p className="text-xs text-[var(--muted)]">Hop {hop.hop}</p>
              <h3 className="mt-1 text-base font-medium text-[var(--text)]">{hop.server}</h3>
              <p className="font-data text-sm text-[var(--muted)]">{hop.ip}</p>
              <p className="mt-1 text-xs text-[var(--muted-dim)]">{hop.timestamp}</p>

              {index !== sample.length - 1 && (
                <div className="mt-5 h-6 border-l border-dashed border-[var(--border-strong)]" />
              )}
            </div>
          ))}
        </div>
      </Panel>
    </AppLayout>
  );
}