import { motion } from "framer-motion";
import { useInView } from "framer-motion";
import { useRef } from "react";

export function ProductSection() {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true, amount: 0.3 });

  return (
    <section
      id="product"
      className="min-h-screen flex items-center justify-center relative py-20"
    >
      {/* Dark smoky background */}
      <div className="absolute inset-0 bg-gradient-to-b from-background via-cyber-darker to-background" />

      <div ref={ref} className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="text-center mb-16"
        >
          {/* Volumetric light beam effect */}
          <div className="relative">
            <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-2 h-64 bg-gradient-to-t from-primary/50 to-transparent blur-sm" />
            <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-1 h-64 bg-gradient-to-t from-primary to-transparent" />
          </div>

          <h2 className="text-5xl lg:text-7xl font-bold mb-16 cyber-text-glow">
            Continuous threat modeling
          </h2>
        </motion.div>

        {/* Threat Detection Interface */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={isInView ? { opacity: 1, scale: 1 } : {}}
          transition={{ duration: 1, delay: 0.5 }}
          className="flex justify-center"
        >
          <div className="relative glassmorphism p-8 rounded-lg border border-primary/50 cyber-glow">
            {/* Threat scanner frame */}
            <div className="relative w-96 h-96 border-2 border-primary rounded-lg overflow-hidden">
              {/* Scanning lines animation */}
              <motion.div
                animate={{ y: [0, 384, 0] }}
                transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-80 z-20"
              />

              {/* Threat visualization */}
              <div className="absolute inset-0 flex items-center justify-center">
                <svg
                  viewBox="0 0 200 240"
                  className="w-72 h-80 text-primary stroke-current opacity-70"
                  fill="none"
                >
                  {/* Danger/Warning Triangle */}
                  <path 
                    d="M100 30 L170 190 L30 190 Z" 
                    strokeWidth="4" 
                    className="text-green-500"
                    fill="none"
                  />
                  
                  {/* Exclamation mark */}
                  <circle cx="100" cy="150" r="12" fill="currentColor" className="text-green-500" />
                  <rect x="94" y="120" width="12" height="30" fill="currentColor" className="text-green-500" />
                  
                  {/* Warning stripes inside triangle */}
                  <path 
                    d="M100 50 L150 170 L50 170 Z" 
                    strokeWidth="1.5" 
                    className="text-green-300"
                    fill="none"
                    strokeDasharray="8,4"
                  />
                </svg>
              </div>

              {/* Corner brackets */}
              <div className="absolute top-2 left-2 w-6 h-6 border-l-2 border-t-2 border-primary" />
              <div className="absolute top-2 right-2 w-6 h-6 border-r-2 border-t-2 border-primary" />
              <div className="absolute bottom-2 left-2 w-6 h-6 border-l-2 border-b-2 border-primary" />
              <div className="absolute bottom-2 right-2 w-6 h-6 border-r-2 border-b-2 border-primary" />
            </div>

            {/* Info display */}
            <div className="mt-4 text-center">
              <div className="text-primary font-mono text-sm mb-2">
                THREAT DETECTION ACTIVE
              </div>
              <div className="text-foreground/70 font-mono text-xs">
                {new Date().toLocaleDateString()} - VULNERABILITIES SCANNED
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
