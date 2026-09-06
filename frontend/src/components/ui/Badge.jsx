const styles = {
  neutral: "bg-zinc-800 text-zinc-300",
  blue: "bg-blue-500/10 text-blue-400",
  red: "bg-red-500/10 text-red-400",
  green: "bg-green-500/10 text-green-400",
};

export default function Badge({
  children,
  variant = "neutral",
}) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${styles[variant]}`}
    >
      {children}
    </span>
  );
}