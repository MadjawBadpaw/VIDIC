export default function Panel({ title, subtitle, children, className = "" }) {
  return (
    <section
      className={`rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--panel)] ${className}`}
    >
      {(title || subtitle) && (
        <header className="border-b border-[var(--border)] px-6 pt-5 pb-4">
          {title && (
            <h2 className="text-base font-semibold tracking-tight text-[var(--text)]">
              {title}
            </h2>
          )}

          {subtitle && (
            <p className="mt-1 text-sm text-[var(--muted)]">{subtitle}</p>
          )}
        </header>
      )}

      <div className="px-6 py-5">{children}</div>
    </section>
  );
}