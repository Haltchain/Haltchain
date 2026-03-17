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
            <>Ready to secure your <span className="text-primary">Agents?</span></>
          }
          description="Get a personalized walkthrough of the Haltchain engine. See how we can integrate cryptographic guardrails directly into your existing AI workflows in under 30 minutes."
        />

        {/* Contact Sales Section */}
        <ContactSection 
          id="sales"
          type="sales"
          alignment="right"
          title={
            <>Mission-Critical <span className="text-primary">Deployments</span></>
          }
          description="Managing billions in TVL or sensitive enterprise data? Talk to our sales engineering team to discuss custom anomaly models, SLA requirements, and on-premise solutions."
        />
      </main>

      <Footer />
    </div>
  );
}
