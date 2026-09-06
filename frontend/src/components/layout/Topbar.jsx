import { Search, Bell, Cpu, UserCircle } from "lucide-react";

export default function Topbar() {
  return (
    <header className="flex flex-wrap items-center justify-between gap-4 mb-8">
      {/* Search Bar */}
      <div className="relative w-full max-w-md">
        <Search
          size={18}
          className="absolute left-4 top-3.5 text-slate-500"
        />

        <input
          type="text"
          placeholder="Search investigations, emails, domains..."
          className="w-full rounded-xl bg-[#111827] border border-slate-700 py-3 pl-11 pr-4 text-sm text-white placeholder:text-slate-500 outline-none focus:border-blue-500 transition"
        />
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* AI Model Badge */}
        <div className="flex items-center gap-2 rounded-xl border border-green-500/30 bg-green-500/10 px-4 py-2">
          <Cpu size={18} className="text-green-400" />

          <div className="leading-tight">
            <p className="text-xs text-slate-400">AI Engine</p>

            <p className="text-sm font-medium text-green-400">
              Ollama • Qwen 7B
            </p>
          </div>
        </div>

        {/* Notifications */}
        <button className="rounded-xl border border-slate-700 bg-[#111827] p-3 hover:border-blue-500 transition">
          <Bell size={18} className="text-slate-300" />
        </button>

        {/* User */}
        <button className="rounded-xl border border-slate-700 bg-[#111827] p-2 hover:border-blue-500 transition">
          <UserCircle size={28} className="text-slate-300" />
        </button>
      </div>
    </header>
  );
}