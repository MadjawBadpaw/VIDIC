import { useState } from "react";
import { Search, Bell, UserCircle } from "lucide-react";

export default function Topbar() {
  const [query, setQuery] = useState("");

  return (
    <header className="sticky top-0 z-30 border-b border-[#27272A] bg-[#09090B]/90 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-[1400px] items-center justify-between px-8">
        {/* Search */}
        <div className="relative w-full max-w-xl">
          <Search
            size={16}
            className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500"
          />

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search emails, domains, IPs or hashes..."
            className="w-full rounded-lg border border-[#27272A] bg-[#111113] py-2.5 pl-11 pr-16 text-sm outline-none placeholder:text-zinc-500 focus:border-blue-600"
          />

          <span className="absolute right-3 top-1/2 -translate-y-1/2 rounded border border-[#27272A] px-2 py-0.5 text-[10px] text-zinc-500">
            Ctrl K
          </span>
        </div>

        {/* Actions */}
        <div className="ml-6 flex items-center gap-2">
          <button className="rounded-lg border border-[#27272A] bg-[#111113] p-2 hover:bg-[#17171A] transition">
            <Bell size={17} />
          </button>

          <button className="rounded-lg border border-[#27272A] bg-[#111113] p-2 hover:bg-[#17171A] transition">
            <UserCircle size={20} />
          </button>
        </div>
      </div>
    </header>
  );
}