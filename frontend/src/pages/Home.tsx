import { Navbar } from "@/components/landing/Navbar";
import { Hero } from "@/components/landing/Hero";
import { HowItWorks } from "@/components/landing/HowItWorks";
import { Features } from "@/components/landing/Features";
import { UseCases } from "@/components/landing/UseCases";
import { Pricing } from "@/components/landing/Pricing";
import { ContactSection } from "@/components/landing/ContactSection";
import { Footer } from "@/components/landing/Footer";

export default function Home() {
  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col selection:bg-primary/20">
      <Navbar />
      
      <main className="flex-1">
        <Hero />
        <HowItWorks />
        <Features />
        <UseCases />
        <Pricing />
        
        {/* Contact Demo Section */}
        <ContactSection 
          id="demo"
          type="demo"
          alignment="left"
          title={
            <>Ready to operationalize <span className="text-primary">AI Compliance?</span></>
          }
          description="Get a walkthrough of the Haltchain control plane, including review queue flows, threshold variants, risk advisories, and signed audit evidence for agent-driven actions."
        />

        {/* Contact Sales Section */}
        <ContactSection 
          id="sales"
          type="sales"
          alignment="right"
          title={
            <>Compliance Programs for <span className="text-primary">Regulated Systems</span></>
          }
          description="Running trading, healthcare, or critical operational workflows? Talk to sales engineering about sidecar deployment, private networking, audit evidence requirements, and enterprise support."
        />
      </main>

      <Footer />
    </div>
  );
}
