import {
  Shield,
  Mail,
  Activity,
  Network,
  FileWarning,
  Settings,
} from "lucide-react";

const items = [
  ["Dashboard", Shield],
  ["Email Upload", Mail],
  ["Investigations", Activity],
  ["Attack Graph", Network],
  ["Reports", FileWarning],
  ["Settings", Settings],
];

export default function Sidebar() {
  return (
    <aside className="w-64 bg-[#111827] border-r border-slate-800 p-5">
      <h1 className="text-2xl font-bold text-blue-500 tracking-wider">VIDIC</h1>
      <p className="text-xs text-slate-400 mt-1">SOC Investigation Console</p>

      <nav className="mt-8 space-y-2">
        {items.map(([label, Icon], index) => (
          <button
            key={label}
            className={`flex w-full items-center gap-3 rounded-xl px-4 py-3 transition ${
              index === 0
                ? "bg-blue-600 text-white"
                : "text-slate-400 hover:bg-slate-800 hover:text-white"
            }`}
          >
            <Icon size={18} />
            {label}
          </button>
        ))}
      </nav>
    </aside>
  );
}