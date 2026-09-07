const styles = {
  neutral: "bg-white/5 text-[var(--muted)]",
  accent: "bg-[var(--accent-soft)] text-[var(--accent)]",
  critical: "bg-[var(--critical-soft)] text-[var(--critical)]",
  high: "bg-[var(--high-soft)] text-[var(--high)]",
  medium: "bg-[var(--medium-soft)] text-[var(--medium)]",
  low: "bg-[var(--low-soft)] text-[var(--low)]",
};

// Mirrors backend/app/detectors/risk_engine.py's verdict thresholds exactly,
// so a badge in the UI can never disagree with the score it's labeling.
export function severityFromScore(score = 0) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export default function Badge({ children, variant = "neutral", dot = false }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${styles[variant]}`}
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