import {
  ResponsiveContainer,
  AreaChart,
  Area,
  ReferenceLine,
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

const ELEVATED_THRESHOLD = 15;

export default function ThreatChart() {
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
          <defs>
            <linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#2DD4BF" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#2DD4BF" stopOpacity={0} />
            </linearGradient>
          </defs>

          <CartesianGrid stroke="#1E2530" vertical={false} />

          <XAxis
            dataKey="day"
            stroke="#5C6675"
            tickLine={false}
            axisLine={false}
            fontSize={12}
          />

          <YAxis stroke="#5C6675" tickLine={false} axisLine={false} fontSize={12} width={28} />

          <ReferenceLine
            y={ELEVATED_THRESHOLD}
            stroke="#FB923C"
            strokeDasharray="4 4"
            label={{
              value: "Elevated",
              position: "insideTopRight",
              fill: "#FB923C",
              fontSize: 11,
            }}
          />

          <Tooltip
            cursor={{ stroke: "#2A3340" }}
            contentStyle={{
              background: "#11151C",
              border: "1px solid #1E2530",
              borderRadius: "10px",
              color: "#E7EAEE",
              fontSize: "13px",
            }}
          />

          <Area
            dataKey="threats"
            stroke="#2DD4BF"
            strokeWidth={2}
            fill="url(#threatFill)"
            activeDot={{ r: 4 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}