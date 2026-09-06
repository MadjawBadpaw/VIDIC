import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";
import Badge from "../components/ui/Badge";
import ThreatChart from "../components/charts/ThreatChart";

const metrics = [
  ["Threats Today", "42", "+6"],
  ["Investigations", "324", "+18"],
  ["Malicious URLs", "61", "+11"],
  ["Attachments Flagged", "18", "+2"],
];

const investigations = [
  ["paypal-security.com", "Phishing", "92", "Pass", "Fail", "14:22"],
  ["accounts.microsoft-login.net", "Spoofing", "87", "Fail", "Fail", "13:18"],
  ["github-alerts.co", "Suspicious", "68", "Pass", "Pass", "11:47"],
  ["amazon-support.io", "Malware", "95", "Fail", "Fail", "10:03"],
  ["office365-update.org", "Credential Harvesting", "90", "Pass", "Fail", "09:21"],
];

export default function Dashboard() {
  return (
    <AppLayout>
      {/* HEADER */}
      <section className="mb-14">
        <p className="mb-4 text-[11px] uppercase tracking-[0.3em] text-zinc-500">
          Security Operations Console
        </p>

        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-[40px] font-semibold tracking-tight">
              Threat Investigation Dashboard
            </h1>

            <p className="mt-4 max-w-3xl text-sm leading-7 text-zinc-400">
              Monitor phishing investigations, inspect suspicious email traffic,
              analyze indicators of compromise, and generate AI-powered reports
              completely offline.
            </p>
          </div>

          <Badge variant="green">ONLINE</Badge>
        </div>
      </section>

      {/* METRICS */}
      <section className="mb-14 grid grid-cols-2 gap-6 xl:grid-cols-4">
        {metrics.map(([label, value, delta]) => (
          <Panel key={label}>
            <p className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">
              {label}
            </p>

            <div className="mt-5 flex items-end justify-between">
              <h2 className="text-4xl font-semibold">{value}</h2>

              <span className="text-sm text-red-400">{delta}</span>
            </div>
          </Panel>
        ))}
      </section>

      {/* CHART */}
      <section className="mb-14">
        <Panel title="Threat Activity" subtitle="LAST 7 DAYS">
          <ThreatChart />
        </Panel>
      </section>

      {/* TABLE */}
      <section className="mb-14">
        <Panel title="Active Investigations" subtitle="LATEST ANALYSIS">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-[#27272A] text-[11px] uppercase tracking-[0.18em] text-zinc-500">
                <tr>
                  <th className="py-4 text-left font-medium">Sender</th>
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
                    key={row[0]}
                    className="border-b border-[#1A1A1D] hover:bg-[#141416]"
                  >
                    <td className="py-5 font-medium">{row[0]}</td>

                    <td>
                      <Badge variant="red">{row[1]}</Badge>
                    </td>

                    <td className="text-red-400">{row[2]}</td>

                    <td className={row[3] === "Pass" ? "text-green-400" : "text-red-400"}>
                      {row[3]}
                    </td>

                    <td className={row[4] === "Pass" ? "text-green-400" : "text-red-400"}>
                      {row[4]}
                    </td>

                    <td className="text-right text-zinc-500">{row[5]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </section>

      {/* LOWER GRID */}
      <section className="grid gap-6 xl:grid-cols-3">
        <Panel title="Threat Feed" subtitle="LIVE IOC SUMMARY">
          <div className="space-y-5 text-sm leading-6 text-zinc-300">
            <p>New phishing campaign targeting Microsoft 365 users.</p>
            <p>3 malicious IPs added to IOC feed.</p>
            <p>Credential harvesting domains increased by 18%.</p>
            <p>ZIP attachment malware observed in latest samples.</p>
          </div>
        </Panel>

        <Panel title="AI Summary" subtitle="LATEST INFERENCE">
          <p className="text-sm leading-7 text-zinc-400">
            Recent phishing samples share characteristics with Microsoft 365
            credential harvesting campaigns, including failed DKIM validation,
            spoofed sender domains, shortened URLs and malicious ZIP attachments.
          </p>

          <div className="mt-6 flex items-center justify-between border-t border-[#27272A] pt-4 text-sm">
            <span className="text-zinc-500">Confidence</span>
            <span className="font-medium">91%</span>
          </div>
        </Panel>

        <Panel title="Infrastructure" subtitle="SERVICE STATUS">
          <Status name="FastAPI Backend" />
          <Status name="PostgreSQL" />
          <Status name="Neo4j Graph" />
          <Status name="Ollama Runtime" />
        </Panel>
      </section>
    </AppLayout>
  );
}

function Status({ name }) {
  return (
    <div className="flex items-center justify-between border-b border-[#1A1A1D] py-4 text-sm">
      <span className="text-zinc-400">{name}</span>

      <div className="flex items-center gap-2">
        <div className="h-2 w-2 rounded-full bg-green-500" />
        Running
      </div>
    </div>
  );
}