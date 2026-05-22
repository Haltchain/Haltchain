import { motion } from "framer-motion";
import { ArrowRight, ArrowDown, ChevronRight, FileCode2 } from "lucide-react";
import { Button } from "@/components/ui/button";

export function Hero() {
  return (
    <section className="relative min-h-screen flex items-center justify-center pt-20 overflow-hidden">
      {/* Dynamic Background Image */}
      <div className="absolute inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-b from-background/40 via-background/80 to-background z-10" />
        <img
          src={`${import.meta.env.BASE_URL}images/hero-bg.png`}
          alt="Abstract dark background with neon glowing lines"
          className="w-full h-full object-cover opacity-60 mix-blend-screen"
        />
      </div>

      {/* Decorative Glow Elements */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-accent/20 rounded-full blur-[100px] pointer-events-none" />

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full text-center">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="max-w-4xl mx-auto space-y-8"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-primary/30 bg-primary/5 text-primary text-sm font-medium mb-4 shadow-[0_0_20px_rgba(0,255,102,0.1)]">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
            </span>
            Compliance control plane for agentic systems
          </div>

          <h1 className="text-5xl sm:text-6xl lg:text-7xl font-display font-extrabold tracking-tight text-foreground leading-[1.1]">
            Compliance Infrastructure <br className="hidden sm:block" />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary to-emerald-300 drop-shadow-[0_0_30px_rgba(0,255,102,0.4)]">
              for Autonomous Systems
            </span>
          </h1>
          
          <p className="text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
            Deploy Haltchain beside LangGraph, CrewAI, or OpenClaw to intercept actions, enforce policy, route high-risk decisions to review, and preserve signed audit evidence before execution.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
            <Button
              size="lg"
              className="w-full sm:w-auto h-14 px-8 text-lg font-semibold bg-primary text-primary-foreground hover:bg-primary/90 shadow-[0_0_20px_rgba(0,255,102,0.3)] hover:shadow-[0_0_40px_rgba(0,255,102,0.5)] transition-all duration-300 hover:-translate-y-1 rounded-xl"
              onClick={() => document.getElementById('demo')?.scrollIntoView({ behavior: 'smooth' })}
            >
              Get a Demo
              <ChevronRight className="ml-2 w-5 h-5" />
            </Button>
            <Button
              size="lg"
              variant="outline"
              className="w-full sm:w-auto h-14 px-8 text-lg font-semibold border-border hover:bg-white/5 hover:text-foreground transition-all duration-300 rounded-xl"
              onClick={() => window.location.assign(`${import.meta.env.BASE_URL}dashboard`)}
            >
              <FileCode2 className="mr-2 w-5 h-5 text-muted-foreground" />
              Open Dashboard
            </Button>
          </div>
        </motion.div>

        {/* The Pill Chain Visualization */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 1, delay: 0.4, ease: "easeOut" }}
          className="mt-24 flex flex-col md:flex-row items-center justify-center gap-4 md:gap-6"
        >
          <div className="flex items-center px-6 py-4 rounded-2xl border border-border bg-card/60 backdrop-blur-md shadow-lg w-full md:w-auto justify-center group hover:border-primary/30 transition-colors">
            <div className="w-3 h-3 rounded-full bg-blue-500 mr-3" />
            <span className="font-semibold text-muted-foreground group-hover:text-foreground transition-colors">Agent Runtime</span>
          </div>

          <div className="text-muted-foreground hidden md:flex animate-pulse">
            <ArrowRight className="w-6 h-6" />
          </div>
          <div className="text-muted-foreground md:hidden flex my-2 animate-pulse">
            <ArrowDown className="w-6 h-6" />
          </div>

          <div className="relative flex items-center px-8 py-5 rounded-2xl border-2 border-primary bg-primary/10 backdrop-blur-md shadow-[0_0_40px_rgba(0,255,102,0.2)] w-full md:w-auto justify-center overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-r from-primary/0 via-primary/20 to-primary/0 translate-x-[-100%] animate-[shimmer_3s_infinite]" />
            <span className="font-display font-bold text-xl text-primary drop-shadow-[0_0_10px_rgba(0,255,102,0.8)] z-10">
              Haltchain Sidecar
            </span>
          </div>

          <div className="text-muted-foreground hidden md:flex animate-pulse">
            <ArrowRight className="w-6 h-6" />
          </div>
          <div className="text-muted-foreground md:hidden flex my-2 animate-pulse">
            <ArrowDown className="w-6 h-6" />
          </div>

          <div className="flex items-center px-6 py-4 rounded-2xl border border-border bg-card/60 backdrop-blur-md shadow-lg w-full md:w-auto justify-center group hover:border-primary/30 transition-colors">
            <div className="w-3 h-3 rounded-full bg-purple-500 mr-3" />
            <span className="font-semibold text-muted-foreground group-hover:text-foreground transition-colors">Compliance Record</span>
          </div>
        </motion.div>
      </div>

      <style>{`
        @keyframes shimmer {
          100% { transform: translateX(100%); }
        }
      `}</style>
    </section>
  );
}
