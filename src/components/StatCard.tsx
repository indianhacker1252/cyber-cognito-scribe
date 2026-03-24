import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  variant?: "green" | "cyan" | "red" | "amber" | "purple";
}

const variantStyles = {
  green: "border-cyber-green/30 glow-green",
  cyan: "border-cyber-cyan/30 glow-cyan",
  red: "border-cyber-red/30 glow-red",
  amber: "border-cyber-amber/30",
  purple: "border-cyber-purple/30",
};

const iconStyles = {
  green: "text-cyber-green",
  cyan: "text-cyber-cyan",
  red: "text-cyber-red",
  amber: "text-cyber-amber",
  purple: "text-cyber-purple",
};

export function StatCard({ title, value, icon: Icon, variant = "green" }: StatCardProps) {
  return (
    <div className={cn("rounded-lg border bg-card p-4 transition-all hover:scale-[1.02]", variantStyles[variant])}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{title}</p>
          <p className={cn("text-2xl font-bold font-mono mt-1", iconStyles[variant])}>{value}</p>
        </div>
        <Icon className={cn("h-8 w-8 opacity-40", iconStyles[variant])} />
      </div>
    </div>
  );
}
