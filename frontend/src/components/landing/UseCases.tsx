import { motion } from "framer-motion";
import { Wallet, Building2, Vote } from "lucide-react";

export function UseCases() {
  const cases = [
    {
      title: "Financial Operations",
      desc: "Prevent AI agents from executing unauthorized transactions or exceeding risk limits. Enforce hard caps on amounts, velocity, and counterparty exposure in real time.",
      icon: <Wallet className="w-8 h-8 text-primary" />,
      gradient: "from-blue-900/20 to-background"
    },
    {
      title: "Enterprise Automation",
      desc: "Stop internal agents from executing destructive API calls against production databases. Add human-in-the-loop approvals for high-risk operations automatically.",
      icon: <Building2 className="w-8 h-8 text-primary" />,
      gradient: "from-purple-900/20 to-background"
    },
    {
      title: "Governance & Compliance",
      desc: "Allow AI agents to participate in approval workflows while ensuring they cannot violate organizational policies or regulatory constraints.",
      icon: <Vote className="w-8 h-8 text-primary" />,
      gradient: "from-emerald-900/20 to-background"
    }
  ];

  return (
    <section id="use-cases" className="py-32 relative border-t border-border/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-20">
          <h2 className="text-3xl md:text-5xl font-display font-bold text-foreground">
            Built for High-Stakes <span className="text-primary">Use Cases</span>
          </h2>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {cases.map((item, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.15 }}
              className={`p-8 rounded-3xl border border-border/50 bg-gradient-to-b ${item.gradient} hover:border-primary/50 transition-colors duration-300`}
            >
              <div className="mb-6 p-4 rounded-2xl bg-card inline-block border border-border shadow-lg">
                {item.icon}
              </div>
              <h3 className="text-2xl font-bold text-foreground mb-4">{item.title}</h3>
              <p className="text-muted-foreground leading-relaxed text-lg">
                {item.desc}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
