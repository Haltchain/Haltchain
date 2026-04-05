import { motion } from "framer-motion";
import { Zap, ShieldCheck, TrendingUp, Layers, Sliders, SplitSquareHorizontal } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

export function Features() {
  const features = [
    {
      title: "Decision Engine",
      description: "Robust rules engine capable of parsing complex state conditions before any action executes.",
      icon: <Zap className="w-6 h-6 text-primary" />
    },
    {
      title: "EWMA Velocity Guard",
      description: "Exponentially Weighted Moving Average guards prevent sudden spikes in agent activity.",
      icon: <TrendingUp className="w-6 h-6 text-primary" />
    },
    {
      title: "Anomaly Detection",
      description: "Statistical modeling catches out-of-distribution commands that bypass traditional rules.",
      icon: <ShieldCheck className="w-6 h-6 text-primary" />
    },
    {
      title: "Cryptographic Audit Trail",
      description: "Every decision is cryptographically signed and logged, providing an immutable record for compliance.",
      icon: <Layers className="w-6 h-6 text-primary" />
    },
    {
      title: "Threshold Tuning",
      description: "Dynamically adjust safety parameters via API without redeploying your agent code.",
      icon: <Sliders className="w-6 h-6 text-primary" />
    },
    {
      title: "A/B Policy Variants",
      description: "Test new governance policies on shadow traffic before enforcing them in production.",
      icon: <SplitSquareHorizontal className="w-6 h-6 text-primary" />
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
            Everything you need to confidently deploy autonomous systems into production.
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
