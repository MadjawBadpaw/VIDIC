// src/components/ui/Badge.jsx

const styles = {
  neutral: "bg-white/5 text-[var(--muted)]",

  success: "bg-[var(--low-soft)] text-[var(--low)]",
  warning: "bg-[var(--medium-soft)] text-[var(--medium)]",

  critical: "bg-[var(--critical-soft)] text-[var(--critical)]",
  high: "bg-[var(--high-soft)] text-[var(--high)]",
  medium: "bg-[var(--medium-soft)] text-[var(--medium)]",
  low: "bg-[var(--low-soft)] text-[var(--low)]",
};

/**
 * Must mirror backend/app/detectors/risk_engine.py exactly.
 */
export function severityFromScore(score = 0) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export default function Badge({
  children,
  variant = "neutral",
  dot = false,
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
        styles[variant] ?? styles.neutral
      }`}
    >
      {dot && (
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: "currentColor" }}
        />
      )}

      {children}
    </span>
  );
}