import { motion } from "framer-motion";
import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";

export function Pricing() {
  const tiers = [
    {
      name: "Open Source Core",
      price: "Self-hosted",
      desc: "For internal evaluation and local integration work",
      features: ["Validator and policy engine", "Local dashboard access", "Community-driven adoption"],
      button: "View GitHub",
      highlight: false,
      action: () => window.open('https://github.com/Haltchain/Haltchain', '_blank')
    },
    {
      name: "Private Pilot",
      price: "Custom",
      desc: "Scoped deployment for regulated or high-stakes teams",
      features: ["Sidecar rollout plan", "Review queue and threshold operations", "Implementation support", "Defined success criteria"],
      button: "Book a Pilot",
      highlight: true,
      action: () => document.getElementById('demo')?.scrollIntoView({ behavior: 'smooth' })
    },
    {
      name: "Enterprise",
      price: "$100K+",
      period: "/yr",
      desc: "Compliance infrastructure for production environments",
      features: ["Private deployment options", "Signed audit evidence and operator workflows", "Enterprise support model", "Custom SLA and architecture review"],
      button: "Contact Sales",
      highlight: false,
      action: () => document.getElementById('sales')?.scrollIntoView({ behavior: 'smooth' })
    }
  ];

  return (
    <section id="pricing" className="py-32 bg-card/30 relative border-t border-border/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-20">
          <h2 className="text-3xl md:text-5xl font-display font-bold text-foreground">
            Deployment <span className="text-primary">Paths</span>
          </h2>
          <p className="mt-4 text-muted-foreground text-lg max-w-2xl mx-auto">
            The commercial path is enterprise-first. Start locally, run a scoped pilot, or deploy a full compliance control plane.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto items-center">
          {tiers.map((tier, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.1 }}
              className={`h-full ${tier.highlight ? 'md:-mt-8 md:-mb-8' : ''}`}
            >
              <Card className={`h-full flex flex-col ${
                tier.highlight 
                  ? 'border-2 border-primary bg-background shadow-[0_0_40px_rgba(0,255,102,0.15)] relative z-10' 
                  : 'bg-background/50 border-border/50'
              }`}>
                {tier.highlight && (
                  <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2">
                    <span className="bg-primary text-primary-foreground text-xs font-bold uppercase tracking-wider py-1 px-3 rounded-full">
                      Recommended
                    </span>
                  </div>
                )}
                
                <CardHeader className="text-center pb-8 pt-10">
                  <CardTitle className="text-xl text-muted-foreground font-medium mb-4">{tier.name}</CardTitle>
                  <div className="flex items-baseline justify-center text-5xl font-display font-bold text-foreground">
                    {tier.price}
                    {tier.period && <span className="text-xl text-muted-foreground font-medium ml-1">{tier.period}</span>}
                  </div>
                  <p className="text-sm text-muted-foreground mt-4">{tier.desc}</p>
                </CardHeader>
                
                <CardContent className="flex-1">
                  <ul className="space-y-4">
                    {tier.features.map((feature, idx) => (
                      <li key={idx} className="flex items-center text-muted-foreground">
                        <Check className="w-5 h-5 text-primary mr-3 shrink-0" />
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
                
                <CardFooter className="pb-10 pt-6">
                  <Button 
                    onClick={tier.action}
                    variant={tier.highlight ? 'default' : 'outline'}
                    className={`w-full h-12 text-lg font-semibold rounded-xl ${
                      tier.highlight 
                        ? 'bg-primary text-primary-foreground hover:bg-primary/90 shadow-[0_0_20px_rgba(0,255,102,0.2)]' 
                        : 'border-border hover:bg-white/5'
                    }`}
                  >
                    {tier.button}
                  </Button>
                </CardFooter>
              </Card>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
