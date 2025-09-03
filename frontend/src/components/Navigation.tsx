import { useState } from "react";
import { Button } from "@/components/ui/button";

const navItems = [
  { name: "Home", href: "#home" },
  { name: "Product", href: "#product" },
  { name: "Services", href: "#services" },
  { name: "About us", href: "#about" },
];

export function Navigation() {
  const [activeSection, setActiveSection] = useState("home");

  return (
    <nav className="fixed top-0 left-0 right-0 z-50">
      <div className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <div className="text-2xl font-bold cyber-text-glow">
            Adaptive Threat Modeler
          </div>

          {/* Navigation Links */}
          <div className="hidden md:flex items-center space-x-8">
            {navItems.map((item) => (
              <a
                key={item.name}
                href={item.href}
                className={`relative transition-colors duration-300 hover:text-primary ${
                  activeSection === item.name.toLowerCase().replace(" ", "")
                    ? "text-primary"
                    : "text-foreground/80"
                }`}
                onClick={() =>
                  setActiveSection(item.name.toLowerCase().replace(" ", ""))
                }
              >
                {item.name}
                {activeSection === item.name.toLowerCase().replace(" ", "") && (
                  <div className="absolute -bottom-1 left-0 w-full h-0.5 bg-primary cyber-glow" />
                )}
              </a>
            ))}
          </div>

          {/* CTA Button */}
          <Button
            variant="default"
            className="cyber-glow hover:shadow-[0_0_30px_hsl(var(--cyber-green)/0.8)] transition-all duration-300"
          >
            Contact us
          </Button>
        </div>
      </div>
    </nav>
  );
}
