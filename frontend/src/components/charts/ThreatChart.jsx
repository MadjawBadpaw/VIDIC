import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { threatTimeline } from "../../services/mockData";

export default function ThreatChart() {
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={threatTimeline}>
          <CartesianGrid stroke="#1F2937" strokeDasharray="3 3" />

          <XAxis
            dataKey="day"
            stroke="#64748B"
            tick={{ fill: "#94A3B8", fontSize: 12 }}
          />

          <YAxis
            stroke="#64748B"
            tick={{ fill: "#94A3B8", fontSize: 12 }}
          />

          <Tooltip
            contentStyle={{
              background: "#111827",
              border: "1px solid #334155",
              borderRadius: "10px",
            }}
          />

          <Line
            type="monotone"
            dataKey="threats"
            stroke="#2563EB"
            strokeWidth={3}
            dot={{ r: 5, fill: "#2563EB" }}
            activeDot={{ r: 7 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}