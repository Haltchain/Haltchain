import { useState, useEffect } from "react";
import { Menu, X, Hexagon } from "lucide-react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";

export function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [, navigate] = useLocation();

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const handleDashboardClick = () => {
    navigate("/dashboard");
  };

  const navLinks = [
    { name: "Features", href: "#features" },
    { name: "How It Works", href: "#how-it-works" },
    { name: "Use Cases", href: "#use-cases" },
    { name: "Pricing", href: "#pricing" },
  ];

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled
          ? "bg-background/80 backdrop-blur-md border-b border-border/50 py-3 shadow-lg"
          : "bg-transparent py-5"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <div className="relative flex items-center justify-center w-8 h-8 rounded-md bg-primary/10 border border-primary/30">
              <Hexagon className="w-5 h-5 text-primary absolute" />
              <div className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
            </div>
            <span className="font-display font-bold text-xl tracking-wide text-foreground">
              Halt<span className="text-primary">chain</span>
            </span>
          </div>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center space-x-8">
            {navLinks.map((link) => (
              <a
                key={link.name}
                href={link.href}
                className="text-sm font-medium text-muted-foreground hover:text-primary transition-colors duration-200"
              >
                {link.name}
              </a>
            ))}
            <Button
              onClick={handleDashboardClick}
              variant="outline"
              className="border-primary/50 text-primary hover:bg-primary/10 hover:text-primary transition-all duration-300 shadow-[0_0_15px_rgba(0,255,102,0.1)] hover:shadow-[0_0_25px_rgba(0,255,102,0.2)]"
            >
              Open Control Plane
            </Button>
          </div>

          {/* Mobile Menu Toggle */}
          <div className="md:hidden flex items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="text-muted-foreground hover:text-foreground focus:outline-none p-2"
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Nav */}
      {mobileMenuOpen && (
        <div className="md:hidden absolute top-full left-0 right-0 bg-background/95 backdrop-blur-xl border-b border-border p-4 shadow-2xl">
          <div className="flex flex-col space-y-4">
            {navLinks.map((link) => (
              <a
                key={link.name}
                href={link.href}
                onClick={() => setMobileMenuOpen(false)}
                className="text-base font-medium text-muted-foreground hover:text-primary block px-2 py-1"
              >
                {link.name}
              </a>
            ))}
            <Button
              onClick={() => {
                handleDashboardClick();
                setMobileMenuOpen(false);
              }}
              className="w-full bg-primary/10 text-primary border border-primary hover:bg-primary/20"
            >
              Open Control Plane
            </Button>
          </div>
        </div>
      )}
    </nav>
  );
}
