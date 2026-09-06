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
        <div className="border-b border-[#27272A] px-6 py-5">
          {subtitle && (
            <p className="text-[11px] uppercase tracking-[0.2em] text-zinc-500 mb-2">
              {subtitle}
            </p>
          )}

          {title && (
            <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
          )}
        </div>
      )}

      <div className="p-6">{children}</div>
    </section>
  );
}