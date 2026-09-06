export default function Panel({
  title,
  subtitle,
  children,
  className = "",
}) {
  return (
    <section
      className={`rounded-xl border border-[#27272A] bg-[#111113] ${className}`}
    >
      {(title || subtitle) && (
        <header className="border-b border-[#27272A] px-6 pt-6 pb-4">
          {subtitle && (
            <p className="mb-2 text-[11px] uppercase tracking-[0.25em] text-zinc-500">
              {subtitle}
            </p>
          )}

          {title && (
            <h2 className="text-lg font-semibold tracking-tight">
              {title}
            </h2>
          )}
        </header>
      )}

      <div className="px-6 py-5">{children}</div>
    </section>
  );
}