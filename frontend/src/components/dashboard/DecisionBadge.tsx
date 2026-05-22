import { Badge } from "@/components/ui/badge";

type Decision = "ALLOW" | "DENY" | "CIRCUIT_BREAK" | string;

const decisionClass: Record<string, string> = {
  ALLOW: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  DENY: "bg-red-500/20 text-red-300 border-red-500/40",
  CIRCUIT_BREAK: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  PENDING: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
};

export function DecisionBadge({ value }: { value: Decision }) {
  return (
    <Badge
      variant="outline"
      className={decisionClass[value] ?? "bg-slate-500/20 text-slate-300 border-slate-500/40"}
    >
      {value}
    </Badge>
  );
}
