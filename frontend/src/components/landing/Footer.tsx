import { Hexagon, Github, Twitter, Disc } from "lucide-react";

export function Footer() {
  const currentYear = new Date().getFullYear();
  
  return (
    <footer className="bg-background border-t border-border pt-16 pb-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-12 mb-12">
          
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center gap-2 mb-6">
              <Hexagon className="w-6 h-6 text-primary" />
              <span className="font-display font-bold text-xl tracking-wide text-foreground">
                Halt<span className="text-primary">chain</span>
              </span>
            </div>
            <p className="text-muted-foreground max-w-sm">
              Compliance infrastructure for autonomous systems, with signed decisions, operator review, and audit evidence before actions execute.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-foreground mb-4">Product</h4>
            <ul className="space-y-3 text-muted-foreground">
              <li><a href="#features" className="hover:text-primary transition-colors">Features</a></li>
              <li><a href="#how-it-works" className="hover:text-primary transition-colors">How it works</a></li>
              <li><a href="#use-cases" className="hover:text-primary transition-colors">Use Cases</a></li>
              <li><a href="#pricing" className="hover:text-primary transition-colors">Pricing</a></li>
            </ul>
          </div>

          <div>
            <h4 className="font-semibold text-foreground mb-4">Resources</h4>
            <ul className="space-y-3 text-muted-foreground">
              <li><a href="/dashboard" className="hover:text-primary transition-colors">Dashboard</a></li>
              <li><a href="/dashboard/review-queue" className="hover:text-primary transition-colors">Review Queue</a></li>
              <li><a href="/dashboard/thresholds" className="hover:text-primary transition-colors">Threshold Ops</a></li>
              <li><a href="#sales" className="hover:text-primary transition-colors">Contact Sales</a></li>
            </ul>
          </div>

        </div>

        <div className="flex flex-col md:flex-row items-center justify-between pt-8 border-t border-border/50">
          <p className="text-muted-foreground text-sm">
            © {currentYear} Haltchain Inc. All rights reserved.
          </p>
          <div className="flex space-x-6 mt-4 md:mt-0 text-muted-foreground">
            <a href="#sales" className="hover:text-foreground transition-colors">
              <Twitter className="w-5 h-5" />
              <span className="sr-only">Twitter</span>
            </a>
            <a href="https://github.com/Haltchain/Haltchain" className="hover:text-foreground transition-colors">
              <Github className="w-5 h-5" />
              <span className="sr-only">GitHub</span>
            </a>
            <a href="#demo" className="hover:text-foreground transition-colors">
              <Disc className="w-5 h-5" />
              <span className="sr-only">Discord</span>
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
