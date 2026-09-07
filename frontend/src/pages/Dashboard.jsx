import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";
import Badge, { severityFromScore } from "../components/ui/Badge";
import ThreatChart from "../components/charts/ThreatChart";

const metrics = [
  ["Threats today", "42", "+6"],
  ["Investigations", "324", "+18"],
  ["Malicious URLs", "61", "+11"],
  ["Attachments flagged", "18", "+2"],
];

const investigations = [
  { sender: "paypal-security.com", verdict: "Phishing", score: 92, spf: "Pass", dkim: "Fail", time: "14:22" },
  { sender: "accounts.microsoft-login.net", verdict: "Spoofing", score: 87, spf: "Fail", dkim: "Fail", time: "13:18" },
  { sender: "github-alerts.co", verdict: "Suspicious", score: 68, spf: "Pass", dkim: "Pass", time: "11:47" },
  { sender: "amazon-support.io", verdict: "Malware", score: 95, spf: "Fail", dkim: "Fail", time: "10:03" },
  { sender: "office365-update.org", verdict: "Credential harvesting", score: 90, spf: "Pass", dkim: "Fail", time: "09:21" },
];

export default function Dashboard() {
  return (
    <AppLayout>
      <section className="mb-12 flex items-center justify-between">
        <div>
          <h1 className="text-[32px] font-semibold tracking-tight text-[var(--text)]">
            Threat investigation dashboard
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-[var(--muted)]">
            Monitor phishing investigations, inspect suspicious email traffic, and
            review indicators of compromise.
          </p>
        </div>

        <Badge variant="accent" dot>Live sample data</Badge>
      </section>

      <section className="mb-10 grid grid-cols-2 gap-5 xl:grid-cols-4">
        {metrics.map(([label, value, delta]) => (
          <Panel key={label} className="!py-0">
            <p className="text-xs text-[var(--muted)]">{label}</p>
            <div className="mt-4 flex items-end justify-between">
              <h2 className="text-3xl font-semibold text-[var(--text)]">{value}</h2>
              <span className="text-sm text-[var(--high)]">{delta}</span>
            </div>
          </Panel>
        ))}
      </section>

      <section className="mb-10">
        <Panel title="Threat activity" subtitle="Last 7 days">
          <ThreatChart />
        </Panel>
      </section>

      <section className="mb-10">
        <Panel title="Active investigations" subtitle="Most recent analyses, newest first">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-[var(--border)] text-xs text-[var(--muted)]">
                <tr>
                  <th className="py-3 text-left font-medium">Sender</th>
                  <th className="text-left font-medium">Verdict</th>
                  <th className="text-left font-medium">Risk</th>
                  <th className="text-left font-medium">SPF</th>
                  <th className="text-left font-medium">DKIM</th>
                  <th className="text-right font-medium">Time</th>
                </tr>
              </thead>

              <tbody>
                {investigations.map((row) => (
                  <tr
                    key={row.sender}
                    className="border-b border-[var(--border)] last:border-none hover:bg-[var(--panel-hover)]"
                  >
                    <td className="py-4 font-medium text-[var(--text)] font-data text-[13px]">
                      {row.sender}
                    </td>

                    <td>
                      <Badge variant={severityFromScore(row.score)}>{row.verdict}</Badge>
                    </td>

                    <td className="font-semibold" style={{ color: `var(--${severityFromScore(row.score)})` }}>
                      {row.score}
                    </td>

                    <td className={row.spf === "Pass" ? "text-[var(--low)]" : "text-[var(--critical)]"}>
                      {row.spf}
                    </td>

                    <td className={row.dkim === "Pass" ? "text-[var(--low)]" : "text-[var(--critical)]"}>
                      {row.dkim}
                    </td>

                    <td className="text-right text-[var(--muted)]">{row.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </section>

      <section className="grid gap-5 xl:grid-cols-3">
        <Panel title="Threat feed" subtitle="Recent IOC activity">
          <div className="space-y-4 text-sm leading-6 text-[var(--muted)]">
            <p>New phishing campaign targeting Microsoft 365 users.</p>
            <p>3 malicious IPs added to the IOC feed.</p>
            <p>Credential-harvesting domains up 18% week over week.</p>
            <p>ZIP attachment malware observed in the latest samples.</p>
          </div>
        </Panel>

        <Panel title="Summary" subtitle="Pattern across recent samples">
          <p className="text-sm leading-6 text-[var(--muted)]">
            Recent phishing samples share characteristics with Microsoft 365
            credential-harvesting campaigns: failed DKIM validation, spoofed
            sender domains, and malicious attachments.
          </p>
        </Panel>

        <Panel title="Local services">
          <Status name="FastAPI backend" state="unknown" />
          <Status name="PostgreSQL" state="not_connected" />
          <Status name="AI summary model" state="not_connected" />
        </Panel>
      </section>
    </AppLayout>
  );
}

function Status({ name, state }) {
  const config = {
    running: { label: "Running", color: "var(--low)" },
    not_connected: { label: "Not connected", color: "var(--muted-dim)" },
    unknown: { label: "Not monitored", color: "var(--muted-dim)" },
  }[state];

  return (
    <div className="flex items-center justify-between border-b border-[var(--border)] py-3.5 text-sm last:border-none">
      <span className="text-[var(--muted)]">{name}</span>
      <span className="flex items-center gap-2" style={{ color: config.color }}>
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: config.color }} />
        {config.label}
      </span>
    </div>
  );
}