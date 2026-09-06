import { Search, Bell, UserCircle } from "lucide-react";
import { useState } from "react";

export default function Topbar() {
  const [search, setSearch] = useState("");

  return (
    <header className="sticky top-0 z-20 border-b border-[#27272A] bg-[#09090B]/90 backdrop-blur px-8 py-5">
      <div className="flex items-center justify-between gap-6">
        {/* Search */}
        <div className="relative w-full max-w-lg">
          <Search
            size={16}
            className="absolute left-4 top-3.5 text-zinc-500"
          />

          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search emails, domains, hashes..."
            className="w-full rounded-xl border border-[#27272A] bg-[#111113] py-3 pl-11 pr-16 text-sm outline-none placeholder:text-zinc-500 focus:border-blue-600"
          />

          <span className="absolute right-3 top-2.5 rounded-md border border-[#27272A] px-2 py-1 text-[10px] text-zinc-500">
            Ctrl K
          </span>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <button className="rounded-lg border border-[#27272A] bg-[#111113] p-2.5 hover:bg-[#17171A]">
            <Bell size={18} />
          </button>

          <button className="rounded-lg border border-[#27272A] bg-[#111113] p-2.5 hover:bg-[#17171A]">
            <UserCircle size={20} />
          </button>
        </div>
      </div>
    </header>
  );
}