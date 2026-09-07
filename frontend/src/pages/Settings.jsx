import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";
import Badge from "../components/ui/Badge";
import { Cpu, Database, Moon } from "lucide-react";

const settings = [
  {
    icon: Cpu,
    title: "AI summary model",
    value: "Not yet integrated",
    status: "planned",
  },
  {
    icon: Database,
    title: "Database",
    value: "In-memory only — nothing persists yet",
    status: "planned",
  },
  {
    icon: Moon,
    title: "Theme",
    value: "Dark (fixed)",
    status: "active",
  },
];

export default function Settings() {
  return (
    <AppLayout>
      <section className="mb-10">
        <h1 className="text-[32px] font-semibold tracking-tight text-[var(--text)]">
          Settings
        </h1>
        <p className="mt-3 text-sm text-[var(--muted)]">
          Current build status of each subsystem.
        </p>
      </section>

      <div className="grid gap-5 md:grid-cols-3">
        {settings.map((item) => (
          <Panel key={item.title}>
            <div className="mb-4 flex items-center justify-between">
              <div className="rounded-[var(--radius-sm)] bg-[var(--panel-hover)] p-2 text-[var(--muted)]">
                <item.icon size={18} />
              </div>

              <Badge variant={item.status === "active" ? "low" : "neutral"}>
                {item.status === "active" ? "Active" : "Planned"}
              </Badge>
            </div>

            <h2 className="text-sm font-semibold text-[var(--text)]">{item.title}</h2>
            <p className="mt-1 text-sm text-[var(--muted)]">{item.value}</p>
          </Panel>
        ))}
      </div>
    </AppLayout>
  );
}