import { NavLink } from "react-router-dom";
import {
  LayoutGrid,
  Mail,
  Search,
  Network,
  FileText,
  Settings,
} from "lucide-react";

const items = [
  { label: "Dashboard", path: "/", icon: LayoutGrid },
  { label: "Email Upload", path: "/upload", icon: Mail },
  { label: "Investigations", path: "/reports", icon: Search },
  { label: "Attack Graph", path: "/graph", icon: Network },
  { label: "Reports", path: "/reports", icon: FileText },
  { label: "Settings", path: "/settings", icon: Settings },
];

export default function Sidebar() {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-[#27272A] bg-[#09090B] px-5 py-8">
      {/* Brand */}
      <div className="mb-12">
        <p className="text-[10px] uppercase tracking-[0.3em] text-zinc-600">
          Vigilant Intelligent Detection
        </p>

        <h1 className="mt-3 text-2xl font-semibold tracking-tight">VIDIC</h1>
      </div>

      {/* Navigation */}
      <nav className="space-y-1">
        {items.map((item) => {
          const Icon = item.icon;

          return (
            <NavLink
              key={item.label}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
                  isActive
                    ? "bg-[#17171A] text-white"
                    : "text-zinc-400 hover:bg-[#17171A] hover:text-white"
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <div
                    className={`h-4 w-[2px] rounded-full ${
                      isActive ? "bg-blue-500" : "bg-transparent"
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
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <div className="h-2 w-2 rounded-full bg-green-500" />
          Local inference ready
        </div>
      </div>
    </aside>
  );
}