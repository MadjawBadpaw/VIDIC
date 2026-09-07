export default function Button({
  children,
  variant = "primary",
  className = "",
  ...props
}) {
  const variants = {
    primary:
      "bg-[var(--accent)] hover:bg-[var(--accent-strong)] text-[#04120F] border-transparent font-semibold",

    secondary:
      "bg-[var(--panel-hover)] hover:bg-[var(--border)] text-[var(--text)] border-[var(--border)]",

    ghost:
      "bg-transparent hover:bg-[var(--panel-hover)] text-[var(--muted)] border-transparent",
  };

  return (
    <button
      {...props}
      className={`border rounded-[var(--radius-sm)] px-4 py-2.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`}
    >
      {children}
    </button>
  );
}