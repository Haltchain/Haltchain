import { motion } from "framer-motion";
import { Zap, ShieldCheck, TrendingUp, Layers, Sliders, SplitSquareHorizontal } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

export function Features() {
  const features = [
    {
      title: "Policy Enforcement API",
      description: "Gate every high-stakes action through a central decision engine before it reaches downstream systems.",
      icon: <Zap className="w-6 h-6 text-primary" />
    },
    {
      title: "Behavioral Anomaly Detection",
      description: "Velocity guards and anomaly models flag behavior shifts that pure policy checks miss.",
      icon: <TrendingUp className="w-6 h-6 text-primary" />
    },
    {
      title: "Decision Review Queue",
      description: "Escalate sensitive actions to humans with review workflows instead of letting risky automation run unchecked.",
      icon: <TrendingUp className="w-6 h-6 text-primary" />
    },
    {
      title: "Audit-grade trails",
      description: "Tamper-evident logging, optional decision signing, Postgres hash-chained decisions, and SIEM-friendly exports — built for evidence, not vanity metrics.",
      icon: <ShieldCheck className="w-6 h-6 text-primary" />
    },
    {
      title: "Threshold Operations",
      description: "Adjust guardrails per tenant or agent without redeploying the calling application.",
      icon: <Layers className="w-6 h-6 text-primary" />
    },
    {
      title: "Canary Variants",
      description: "Roll out threshold variants gradually and compare operational behavior before making changes global.",
      icon: <SplitSquareHorizontal className="w-6 h-6 text-primary" />
    },
    {
      title: "Risk Advisories",
      description: "Publish cross-agent advisories when a risky pattern appears so operators see cascading issues early.",
      icon: <Sliders className="w-6 h-6 text-primary" />
    }
  ];

  return (
    <section id="features" className="py-32 bg-card/30 relative">
      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-border to-transparent" />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-20">
          <h2 className="text-3xl md:text-5xl font-display font-bold text-foreground">
            Enterprise-Grade <span className="text-primary">Features</span>
          </h2>
          <p className="mt-4 text-muted-foreground text-lg max-w-2xl mx-auto">
            Controls that map to approval workflows, operator review, and audit evidence instead of generic AI safety marketing.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.1 }}
            >
              <Card className="h-full bg-background/50 border-border/50 hover:border-primary/40 hover:bg-background transition-all duration-300 shadow-sm hover:shadow-[0_8px_30px_rgba(0,255,102,0.05)] overflow-hidden group">
                <CardHeader className="p-8">
                  <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300">
                    {feature.icon}
                  </div>
                  <CardTitle className="text-xl mb-3">{feature.title}</CardTitle>
                  <CardDescription className="text-base text-muted-foreground leading-relaxed">
                    {feature.description}
                  </CardDescription>
                </CardHeader>
              </Card>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
