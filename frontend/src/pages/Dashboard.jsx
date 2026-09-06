import Sidebar from "../components/layout/Sidebar";
import Topbar from "../components/layout/Topbar";
import StatCard from "../components/cards/StatCard";
import ThreatChart from "../components/charts/ThreatChart";

import {
  dashboardStats,
  recentInvestigations,
} from "../services/mockData";

import {
  Upload,
  FileText,
  ShieldCheck,
  Database,
  Network,
  Bot,
} from "lucide-react";

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-[#080A10] text-white flex">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Content */}
      <main className="flex-1 p-8 overflow-y-auto">

        {/* Top Navigation */}
        <Topbar />

        {/* Page Heading */}
        <section className="mb-8">
          <p className="text-sm uppercase tracking-widest text-blue-400">
            Security Operations Center
          </p>

          <h1 className="mt-2 text-4xl font-bold">
            Threat Investigation Dashboard
          </h1>

          <p className="mt-2 text-slate-400 max-w-3xl">
            Analyze suspicious emails, investigate phishing campaigns, extract
            indicators of compromise (IOCs), and generate offline AI-powered
            investigation reports using Ollama.
          </p>
        </section>

        {/* Quick Actions */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">

          <button className="bg-blue-600 hover:bg-blue-700 transition rounded-2xl p-5 flex items-center gap-3 shadow-lg">
            <Upload />
            <div className="text-left">
              <p className="font-semibold">Upload Email</p>
              <p className="text-xs text-blue-100">.eml / .msg</p>
            </div>
          </button>

          <button className="bg-[#111827] border border-slate-700 hover:border-blue-500 transition rounded-2xl p-5 flex items-center gap-3">
            <FileText />
            <div className="text-left">
              <p className="font-semibold">Generate Report</p>
              <p className="text-xs text-slate-400">PDF Investigation</p>
            </div>
          </button>

          <button className="bg-[#111827] border border-slate-700 hover:border-blue-500 transition rounded-2xl p-5 flex items-center gap-3">
            <ShieldCheck />
            <div className="text-left">
              <p className="font-semibold">IOC Scan</p>
              <p className="text-xs text-slate-400">URLs · Domains · IPs</p>
            </div>
          </button>

          <button className="bg-[#111827] border border-slate-700 hover:border-blue-500 transition rounded-2xl p-5 flex items-center gap-3">
            <Bot />
            <div className="text-left">
              <p className="font-semibold">AI Investigation</p>
              <p className="text-xs text-slate-400">Run Local LLM</p>
            </div>
          </button>

        </section>

        {/* Statistics */}
        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5 mb-8">
          {dashboardStats.map((card) => (
            <StatCard key={card.title} {...card} />
          ))}
        </section>

        {/* Middle Grid */}
        <section className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-8">

          {/* Threat Timeline */}
          <div className="xl:col-span-2 bg-[#111827] rounded-2xl border border-slate-800 p-6">

            <div className="flex items-center justify-between mb-5">
              <div>
                <h2 className="text-xl font-semibold">
                  Weekly Threat Timeline
                </h2>

                <p className="text-sm text-slate-400">
                  Suspicious emails detected this week.
                </p>
              </div>

              <span className="text-xs bg-blue-500/10 text-blue-400 px-3 py-1 rounded-full">
                Live Analytics
              </span>
            </div>

            <ThreatChart />

          </div>

          {/* Recent Investigations */}
          <div className="bg-[#111827] rounded-2xl border border-slate-800 p-6">

            <h2 className="text-xl font-semibold mb-5">
              Recent Investigations
            </h2>

            <div className="space-y-4">
              {recentInvestigations.map((item) => (
                <div
                  key={item.id}
                  className="rounded-xl bg-[#1F2937] border border-slate-700 p-4 hover:border-blue-500 transition"
                >

                  <p className="text-xs text-slate-500">{item.id}</p>

                  <h3 className="mt-2 font-medium break-all">
                    {item.sender}
                  </h3>

                  <div className="mt-4 flex items-center justify-between">

                    <span
                      className={`text-xs px-3 py-1 rounded-full font-medium ${
                        item.severity === "Critical"
                          ? "bg-red-500/20 text-red-400"
                          : item.severity === "High"
                          ? "bg-orange-500/20 text-orange-400"
                          : "bg-yellow-500/20 text-yellow-400"
                      }`}
                    >
                      {item.severity}
                    </span>

                    <span className="text-xs text-slate-400">
                      {item.status}
                    </span>

                  </div>

                </div>
              ))}
            </div>

          </div>

        </section>

        {/* Bottom Status Grid */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* AI Engine */}
          <div className="bg-[#111827] rounded-2xl border border-slate-800 p-6">

            <div className="flex items-center gap-3 mb-4">
              <Bot className="text-green-400" />
              <h3 className="text-lg font-semibold">AI Engine Status</h3>
            </div>

            <p className="text-green-400 font-semibold">
              Ollama Running
            </p>

            <p className="text-slate-400 text-sm mt-2">
              Model: Qwen2.5 7B Instruct (Offline)
            </p>

            <p className="text-slate-400 text-sm">
              Context Window: 4096 Tokens
            </p>

          </div>

          {/* Databases */}
          <div className="bg-[#111827] rounded-2xl border border-slate-800 p-6">

            <div className="flex items-center gap-3 mb-4">
              <Database className="text-blue-400" />
              <h3 className="text-lg font-semibold">Database Health</h3>
            </div>

            <div className="space-y-3 text-sm">

              <div className="flex justify-between">
                <span>PostgreSQL</span>
                <span className="text-green-400">Connected</span>
              </div>

              <div className="flex justify-between">
                <span>Neo4j Graph</span>
                <span className="text-yellow-400">Waiting</span>
              </div>

              <div className="flex justify-between">
                <span>Redis Cache</span>
                <span className="text-slate-400">Offline</span>
              </div>

            </div>

          </div>

          {/* Threat Feed */}
          <div className="bg-[#111827] rounded-2xl border border-slate-800 p-6">

            <div className="flex items-center gap-3 mb-4">
              <Network className="text-red-400" />
              <h3 className="text-lg font-semibold">Threat Feed</h3>
            </div>

            <div className="space-y-3 text-sm">

              <div className="flex justify-between">
                <span>Malicious URLs</span>
                <span className="text-red-400">148</span>
              </div>

              <div className="flex justify-between">
                <span>Suspicious Domains</span>
                <span className="text-orange-400">23</span>
              </div>

              <div className="flex justify-between">
                <span>Known IP Indicators</span>
                <span className="text-blue-400">61</span>
              </div>

            </div>

          </div>

        </section>

      </main>
    </div>
  );
}