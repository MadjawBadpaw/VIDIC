import AppLayout from "../components/layout/AppLayout";
import Panel from "../components/ui/Panel";
import Badge from "../components/ui/Badge";
import ThreatChart from "../components/charts/ThreatChart";

const metrics = [
  { label: "Threats Today", value: "42", delta: "+6" },
  { label: "Investigations", value: "324", delta: "+18" },
  { label: "Malicious URLs", value: "61", delta: "+11" },
  { label: "Attachments Flagged", value: "18", delta: "+2" },
];

const investigations = [
  {
    sender: "paypal-security.com",
    verdict: "Phishing",
    risk: 92,
    spf: "Pass",
    dkim: "Fail",
    time: "14:22",
  },
  {
    sender: "accounts.microsoft-login.net",
    verdict: "Spoofing",
    risk: 87,
    spf: "Fail",
    dkim: "Fail",
    time: "13:18",
  },
  {
    sender: "github-alerts.co",
    verdict: "Suspicious",
    risk: 68,
    spf: "Pass",
    dkim: "Pass",
    time: "11:47",
  },
  {
    sender: "amazon-support.io",
    verdict: "Malware",
    risk: 95,
    spf: "Fail",
    dkim: "Fail",
    time: "10:03",
  },
  {
    sender: "office365-update.org",
    verdict: "Credential Harvesting",
    risk: 90,
    spf: "Pass",
    dkim: "Fail",
    time: "09:21",
  },
];

const feeds = [
  "New phishing campaign targeting Microsoft 365 users.",
  "3 malicious IPs added to IOC feed.",
  "Credential harvesting domains increased by 18%.",
  "ZIP attachment malware observed in latest samples.",
];

export default function Dashboard() {
  return (
    <AppLayout>
      {/* Header */}

      <section className="mb-10">
        <p className="uppercase tracking-[0.25em] text-[11px] text-zinc-500">
          Security Operations Console
        </p>

        <div className="mt-3 flex items-end justify-between">
          <div>
            <h1 className="text-4xl font-semibold tracking-tight">
              Threat Investigation Dashboard
            </h1>

            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-400">
              Monitor phishing investigations, inspect suspicious email traffic,
              analyze indicators of compromise, and generate AI-powered reports
              completely offline.
            </p>
          </div>

          <Badge variant="green">Online</Badge>
        </div>
      </section>

      {/* Metrics */}

      <section className="grid grid-cols-2 xl:grid-cols-4 gap-6 mb-10">
        {metrics.map((item) => (
          <Panel key={item.label}>
            <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">
              {item.label}
            </p>

            <div className="mt-3 flex items-end justify-between">
              <h2 className="text-4xl font-semibold">{item.value}</h2>

              <span className="text-sm text-red-400">{item.delta}</span>
            </div>
          </Panel>
        ))}
      </section>

      {/* Chart */}

      <section className="mb-10">
        <Panel
          title="Threat Activity"
          subtitle="LAST 7 DAYS"
        >
          <ThreatChart />
        </Panel>
      </section>

      {/* Investigation Table */}

      <section className="mb-10">
        <Panel
          title="Active Investigations"
          subtitle="LATEST EMAIL ANALYSIS"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-zinc-500 uppercase text-xs border-b border-[#27272A]">
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
                    key={row.sender}
                    className="border-b border-[#1A1A1D] hover:bg-[#141416]"
                  >
                    <td className="py-5 font-medium">{row.sender}</td>

                    <td>
                      <Badge
                        variant={
                          row.risk > 90
                            ? "red"
                            : row.risk > 75
                            ? "blue"
                            : "neutral"
                        }
                      >
                        {row.verdict}
                      </Badge>
                    </td>

                    <td className="text-red-400">{row.risk}</td>

                    <td
                      className={
                        row.spf === "Pass"
                          ? "text-green-400"
                          : "text-red-400"
                      }
                    >
                      {row.spf}
                    </td>

                    <td
                      className={
                        row.dkim === "Pass"
                          ? "text-green-400"
                          : "text-red-400"
                      }
                    >
                      {row.dkim}
                    </td>

                    <td className="text-right text-zinc-500">{row.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </section>

      {/* Bottom Panels */}

      <section className="grid xl:grid-cols-3 gap-6">

        {/* Threat Feed */}

        <Panel
          title="Threat Feed"
          subtitle="LIVE IOC SUMMARY"
        >
          <div className="space-y-4">
            {feeds.map((feed) => (
              <div
                key={feed}
                className="border-l border-blue-500 pl-4 text-sm text-zinc-300"
              >
                {feed}
              </div>
            ))}
          </div>
        </Panel>

        {/* AI Summary */}

        <Panel
          title="AI Investigation Summary"
          subtitle="QWEN INFERENCE"
        >
          <p className="text-sm leading-7 text-zinc-400">
            Most recent phishing samples share visual similarity with Microsoft
            365 credential harvesting campaigns. Common indicators include failed
            DKIM validation, mismatched sender domains, shortened URLs, and ZIP
            attachments requesting authentication.
          </p>

          <div className="mt-6 space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-zinc-500">Confidence</span>

              <span>91%</span>
            </div>

            <div className="flex justify-between">
              <span className="text-zinc-500">Model</span>

              <span>Local LLM</span>
            </div>

            <div className="flex justify-between">
              <span className="text-zinc-500">Status</span>

              <Badge variant="green">Ready</Badge>
            </div>
          </div>
        </Panel>

        {/* Infrastructure */}

        <Panel
          title="Infrastructure Status"
          subtitle="SERVICES"
        >
          <Service name="FastAPI Backend" status="Running" />
          <Service name="PostgreSQL" status="Connected" />
          <Service name="Neo4j Graph" status="Idle" />
          <Service name="Ollama Runtime" status="Running" />
        </Panel>
      </section>
    </AppLayout>
  );
}

function Service({ name, status }) {
  return (
    <div className="flex items-center justify-between border-b border-[#1A1A1D] py-4">
      <span className="text-sm text-zinc-400">{name}</span>

      <div className="flex items-center gap-2">
        <div className="h-2 w-2 rounded-full bg-green-500" />

        <span className="text-sm">{status}</span>
      </div>
    </div>
  );
}