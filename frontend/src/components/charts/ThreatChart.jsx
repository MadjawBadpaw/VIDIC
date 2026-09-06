import {
  ResponsiveContainer,
  LineChart,
  Line,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

const data = [
  { day: "Mon", threats: 5 },
  { day: "Tue", threats: 11 },
  { day: "Wed", threats: 8 },
  { day: "Thu", threats: 16 },
  { day: "Fri", threats: 10 },
  { day: "Sat", threats: 18 },
  { day: "Sun", threats: 13 },
];

export default function ThreatChart() {
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer>
        <LineChart data={data}>
          <CartesianGrid
            stroke="#1A1A1D"
            vertical={false}
          />

          <XAxis
            dataKey="day"
            stroke="#71717A"
            tickLine={false}
            axisLine={false}
          />

          <YAxis
            stroke="#71717A"
            tickLine={false}
            axisLine={false}
          />

          <Tooltip
            cursor={{ stroke: "#27272A" }}
            contentStyle={{
              background: "#111113",
              border: "1px solid #27272A",
              borderRadius: "10px",
              color: "#FAFAFA",
            }}
          />

          <Line
            dataKey="threats"
            stroke="#2563EB"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}