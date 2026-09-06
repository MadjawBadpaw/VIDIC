export default function Button({
  children,
  variant = "primary",
  className = "",
  ...props
}) {
  const variants = {
    primary:
      "bg-blue-600 hover:bg-blue-500 text-white border-transparent",

    secondary:
      "bg-[#17171A] hover:bg-[#1F1F22] text-zinc-200 border-[#27272A]",

    ghost:
      "bg-transparent hover:bg-[#17171A] text-zinc-300 border-transparent",
  };

  return (
    <button
      {...props}
      className={`border rounded-xl px-4 py-2.5 text-sm font-medium transition-colors ${variants[variant]} ${className}`}
    >
      {children}
    </button>
  );
}