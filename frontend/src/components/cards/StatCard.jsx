import {
  Mail,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

const colors = {
  blue: {
    icon: Mail,
    text: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
  },
  red: {
    icon: ShieldAlert,
    text: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/20",
  },
  green: {
    icon: ShieldCheck,
    text: "text-green-400",
    bg: "bg-green-500/10",
    border: "border-green-500/20",
  },
  amber: {
    icon: TriangleAlert,
    text: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/20",
  },
};

export default function StatCard({ title, value, change, color }) {
  const theme = colors[color];
  const Icon = theme.icon;

  return (
    <div
      className={`rounded-2xl border ${theme.border} bg-[#111827] p-5 shadow-lg`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-400">{title}</p>

          <h2 className="mt-3 text-3xl font-bold">{value}</h2>

          <p className={`mt-2 text-sm ${theme.text}`}>{change}</p>
        </div>

        <div className={`${theme.bg} rounded-xl p-3`}>
          <Icon className={`h-7 w-7 ${theme.text}`} />
        </div>
      </div>
    </div>
  );
}