import { useState } from "react";
import { Search, Bell, UserCircle } from "lucide-react";

export default function Topbar() {
  const [query, setQuery] = useState("");
  const [openMenu, setOpenMenu] = useState(null); // null | "notifications" | "profile"

  const toggle = (menu) => setOpenMenu((current) => (current === menu ? null : menu));

  return (
    <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[var(--bg)]/90 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-[1400px] items-center justify-between px-8">
        {/* Search */}
        <div className="relative w-full max-w-xl">
          <Search
            size={16}
            className="pointer-events-none absolute left-4 top-1/2 z-10 -translate-y-1/2 text-[var(--muted-dim)]"
          />

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search emails, domains, IPs, hashes"
            className="w-full rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel)] py-2.5 pl-11 pr-4 text-sm text-[var(--text)] outline-none placeholder:text-[var(--muted-dim)] focus:border-[var(--accent)]"
          />
        </div>

        {/* Actions */}
        <div className="ml-6 flex items-center gap-2">
          <div className="relative">
            <button
              onClick={() => toggle("notifications")}
              aria-expanded={openMenu === "notifications"}
              className={`rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel)] p-2 transition hover:bg-[var(--panel-hover)] ${
                openMenu === "notifications" ? "border-[var(--accent)]" : ""
              }`}
            >
              <Bell size={17} className="text-[var(--muted)]" />
            </button>

            {openMenu === "notifications" && (
              <div className="absolute right-0 mt-2 w-64 rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel)] p-4 shadow-lg">
                <p className="text-sm font-medium text-[var(--text)]">Notifications</p>
                <p className="mt-2 text-sm text-[var(--muted)]">
                  No new notifications yet.
                </p>
              </div>
            )}
          </div>

          <div className="relative">
            <button
              onClick={() => toggle("profile")}
              aria-expanded={openMenu === "profile"}
              className={`rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel)] p-2 transition hover:bg-[var(--panel-hover)] ${
                openMenu === "profile" ? "border-[var(--accent)]" : ""
              }`}
            >
              <UserCircle size={20} className="text-[var(--muted)]" />
            </button>

            {openMenu === "profile" && (
              <div className="absolute right-0 mt-2 w-56 rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--panel)] p-4 shadow-lg">
                <p className="text-sm font-medium text-[var(--text)]">Local session</p>
                <p className="mt-1 text-sm text-[var(--muted)]">
                  No account system yet — running as a local analyst.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}