import { motion } from "framer-motion";
import { Bot, ShieldAlert, Activity, Link as LinkIcon } from "lucide-react";

export function HowItWorks() {
  const steps = [
    {
      num: "01",
      title: "Agent submits action",
      desc: "The autonomous agent requests permission to execute a high-stakes action via the API.",
      icon: <Bot className="w-6 h-6 text-primary" />
    },
    {
      num: "02",
      title: "Policy engine validates",
      desc: "Haltchain evaluates the request against your custom cryptographic rule sets.",
      icon: <ShieldAlert className="w-6 h-6 text-primary" />
    },
    {
      num: "03",
      title: "EWMA/anomaly check",
      desc: "Velocity guards and statistical models analyze the request for abnormal behavior.",
      icon: <Activity className="w-6 h-6 text-primary" />
    },
    {
      num: "04",
      title: "Decision logged",
      desc: "The approved action is cryptographically signed and logged to an immutable audit trail.",
      icon: <LinkIcon className="w-6 h-6 text-primary" />
    }
  ];

  return (
    <section id="how-it-works" className="py-32 bg-background relative border-t border-border/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center mb-20">
          <h2 className="text-3xl md:text-5xl font-display font-bold text-foreground">
            How It <span className="text-primary">Works</span>
          </h2>
          <p className="mt-4 text-muted-foreground text-lg max-w-2xl mx-auto">
            A seamless intercept layer between your AI's intentions and its execution context.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 relative">
          {/* Connector line for desktop */}
          <div className="hidden lg:block absolute top-12 left-[12%] right-[12%] h-[2px] bg-gradient-to-r from-transparent via-primary/30 to-transparent -z-10" />

          {steps.map((step, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              className="flex flex-col items-center text-center relative"
            >
              <div className="w-24 h-24 rounded-full bg-card border-2 border-border flex items-center justify-center mb-6 shadow-xl relative group hover:border-primary transition-colors duration-300">
                <div className="absolute inset-0 rounded-full bg-primary/5 group-hover:bg-primary/20 transition-colors" />
                <div className="relative z-10 flex flex-col items-center">
                  {step.icon}
                </div>
                {/* Number Badge */}
                <div className="absolute -top-2 -right-2 w-8 h-8 rounded-full bg-primary text-primary-foreground font-bold flex items-center justify-center text-sm shadow-[0_0_15px_rgba(0,255,102,0.5)]">
                  {step.num}
                </div>
              </div>
              <h3 className="text-xl font-bold text-foreground mb-3">{step.title}</h3>
              <p className="text-muted-foreground leading-relaxed">{step.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
