import AppLayout from "../components/layout/AppLayout";
import { Cpu, Database, Moon } from "lucide-react";

export default function Settings() {
  return (
    <AppLayout>
      <div className="mt-8">
        <p className="text-blue-400 uppercase text-sm tracking-widest">
          Dashboard / Settings
        </p>

        <h1 className="text-4xl font-bold mt-2">Settings</h1>

        <div className="grid md:grid-cols-2 gap-6 mt-8">
          <SettingCard
            icon={<Cpu className="text-green-400" />}
            title="AI Model"
            value="Qwen2.5 7B (Ollama)"
          />

          <SettingCard
            icon={<Database className="text-blue-400" />}
            title="Database"
            value="PostgreSQL Connected"
          />

          <SettingCard
            icon={<Moon className="text-purple-400" />}
            title="Theme"
            value="Dark Mode"
          />
        </div>
      </div>
    </AppLayout>
  );
}

function SettingCard({ icon, title, value }) {
  return (
    <div className="rounded-2xl bg-[#111827] border border-slate-800 p-6">
      <div className="flex items-center gap-3 mb-3">
        {icon}
        <h2 className="font-semibold text-lg">{title}</h2>
      </div>

      <p className="text-slate-400">{value}</p>
    </div>
  );
}