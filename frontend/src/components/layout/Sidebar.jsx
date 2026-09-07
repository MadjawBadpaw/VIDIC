import { NavLink } from "react-router-dom";
import {
  LayoutGrid,
  Mail,
  Network,
  FileText,
  Settings,
} from "lucide-react";

// "Investigations" was previously a separate nav item pointing at the same
// /reports route as "Reports" — a leftover duplicate rather than a real
// page. Removed until there's an actual investigations-list view to link.
const items = [
  { label: "Dashboard", path: "/", icon: LayoutGrid },
  { label: "Email Upload", path: "/upload", icon: Mail },
  { label: "Attack Graph", path: "/graph", icon: Network },
  { label: "Reports", path: "/reports", icon: FileText },
  { label: "Settings", path: "/settings", icon: Settings },
];

export default function Sidebar() {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--bg)] px-5 py-8">
      <div className="mb-12">
        <h1 className="text-2xl font-semibold tracking-tight text-[var(--text)]">
          VIDIC
        </h1>
        <p className="mt-2 text-[11px] leading-relaxed tracking-wide text-[var(--muted-dim)]">
          Vigilant Intelligent Detection &amp; Investigation Console
        </p>
      </div>

      <nav className="space-y-1">
        {items.map((item) => {
          const Icon = item.icon;

          return (
            <NavLink
              key={item.label}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-[var(--radius-sm)] px-3 py-2.5 text-sm transition ${
                  isActive
                    ? "bg-[var(--panel-hover)] text-[var(--text)]"
                    : "text-[var(--muted)] hover:bg-[var(--panel-hover)] hover:text-[var(--text)]"
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <div
                    className={`h-4 w-[2px] rounded-full ${
                      isActive ? "bg-[var(--accent)]" : "bg-transparent"
                    }`}
                  />
                  <Icon size={17} strokeWidth={1.8} />
                  <span>{item.label}</span>
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      <div className="mt-auto pt-10">
        <p className="text-xs text-[var(--muted-dim)]">VIDIC v1.0.0 — local dev build</p>
      </div>
    </aside>
  );
}