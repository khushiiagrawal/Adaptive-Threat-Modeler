import { motion } from "framer-motion";
import { useInView } from "framer-motion";
import { useRef } from "react";

const services = [
  {
    title: "Continuous Threat Modeling",
    description:
      "Automatic threat maps update on every code push or config change—no manual upkeep.",
    category: "CORE",
  },
  {
    title: "AI Findings & Prioritization",
    description:
      "Maps risks to CVE and MITRE ATT&CK and ranks by impact with fixes.",
    category: "AI",
  },
  {
    title: "Code & Cloud Analysis",
    description:
      "Parses endpoints, dependencies, IaC and cloud configs to reveal exploit paths.",
    category: "ANALYSIS",
  },
  {
    title: "Interactive Attack Surface Map",
    description:
      "Visualize APIs, databases, services, and how threats can enter or move laterally.",
    category: "VISUALIZATION",
  },
];

export function ServicesSection() {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true, amount: 0.3 });

  return (
    <section id="services" className="min-h-screen py-20 relative">
      {/* Animated particle background */}
      <div className="absolute inset-0 overflow-hidden">
        {[...Array(20)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-1 h-1 bg-primary rounded-full opacity-30"
            animate={{
              x: ["-100vw", "100vw"],
              y: [Math.random() * 100 + "%", Math.random() * 100 + "%"],
            }}
            transition={{
              duration: 20 + Math.random() * 10,
              repeat: Infinity,
              delay: Math.random() * 10,
              ease: "linear",
            }}
            style={{
              top: Math.random() * 100 + "%",
            }}
          />
        ))}
      </div>

      <div ref={ref} className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="text-center mb-16"
        >
          <h2 className="text-5xl lg:text-7xl font-bold mb-8 cyber-text-glow">
            Our Services
          </h2>
          <p className="text-xl text-foreground/80 max-w-3xl mx-auto">
            Continuous, developer-first security that stays in lockstep with
            your code and cloud
          </p>
        </motion.div>

        {/* Services Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {services.map((service, index) => (
            <motion.div
              key={service.title}
              initial={{ opacity: 0, y: 50 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, delay: index * 0.2 }}
              className="glassmorphism p-6 rounded-lg border border-primary/30 hover:border-primary/60 transition-all duration-300 hover:cyber-glow group"
            >
              {/* Category badge */}
              <div className="text-primary font-mono text-xs mb-4 opacity-70">
                {service.category}
              </div>

              {/* Title */}
              <h3 className="text-xl font-bold mb-4 group-hover:cyber-text-glow transition-all duration-300">
                {service.title}
              </h3>

              {/* Description */}
              <p className="text-foreground/70 text-sm leading-relaxed">
                {service.description}
              </p>

              {/* Animated border effect */}
              <motion.div
                className="absolute inset-0 border border-primary/50 rounded-lg opacity-0 group-hover:opacity-100"
                animate={
                  isInView
                    ? {
                        borderImage: [
                          "linear-gradient(0deg, #39ff14, transparent, transparent, transparent) 1",
                          "linear-gradient(90deg, transparent, #39ff14, transparent, transparent) 1",
                          "linear-gradient(180deg, transparent, transparent, #39ff14, transparent) 1",
                          "linear-gradient(270deg, transparent, transparent, transparent, #39ff14) 1",
                          "linear-gradient(360deg, #39ff14, transparent, transparent, transparent) 1",
                        ],
                      }
                    : {}
                }
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
              />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
