import { NavLink } from "react-router-dom";
import {
  LayoutGrid,
  Mail,
  Search,
  Network,
  FileText,
  Settings,
} from "lucide-react";

const navigation = [
  { label: "Dashboard", to: "/", icon: LayoutGrid },
  { label: "Email Upload", to: "/upload", icon: Mail },
  { label: "Investigations", to: "/reports", icon: Search },
  { label: "Attack Graph", to: "/graph", icon: Network },
  { label: "Reports", to: "/reports", icon: FileText },
  { label: "Settings", to: "/settings", icon: Settings },
];

export default function Sidebar() {
  return (
    <aside className="w-56 shrink-0 border-r border-[#27272A] bg-[#09090B] px-4 py-6">
      {/* Logo */}
      <div className="mb-10 px-2">
        <p className="text-[11px] uppercase tracking-[0.25em] text-zinc-500">
          Vigilant Intelligent Detection
        </p>

        <h1 className="mt-2 text-2xl font-semibold tracking-tight">VIDIC</h1>
      </div>

      {/* Navigation */}
      <nav className="space-y-1">
        {navigation.map((item) => {
          const Icon = item.icon;

          return (
            <NavLink
              key={item.label}
              to={item.to}
              className={({ isActive }) =>
                `group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${
                  isActive
                    ? "bg-[#17171A] text-white"
                    : "text-zinc-400 hover:bg-[#17171A] hover:text-white"
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <div
                    className={`h-4 w-1 rounded-full ${
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

      {/* Bottom status */}
      <div className="mt-auto pt-10 px-2">
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <div className="h-2 w-2 rounded-full bg-green-500" />
          Local inference available
        </div>
      </div>
    </aside>
  );
}