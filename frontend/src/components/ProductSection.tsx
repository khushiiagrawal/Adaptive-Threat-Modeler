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

        {/* Holographic Face Scanner */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={isInView ? { opacity: 1, scale: 1 } : {}}
          transition={{ duration: 1, delay: 0.5 }}
          className="flex justify-center"
        >
          <div className="relative glassmorphism p-8 rounded-lg border border-primary/50 cyber-glow">
            {/* Scanner frame */}
            <div className="relative w-80 h-80 border-2 border-primary rounded-lg overflow-hidden">
              {/* Scanning lines animation */}
              <motion.div
                animate={{ y: [0, 320, 0] }}
                transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-80 z-20"
              />

              {/* Face wireframe */}
              <div className="absolute inset-0 flex items-center justify-center">
                <svg
                  viewBox="0 0 200 240"
                  className="w-48 h-56 text-primary stroke-current opacity-70"
                  fill="none"
                >
                  {/* Face outline */}
                  <ellipse cx="100" cy="120" rx="60" ry="80" strokeWidth="1" />
                  {/* Eyes */}
                  <ellipse cx="85" cy="100" rx="8" ry="6" strokeWidth="1" />
                  <ellipse cx="115" cy="100" rx="8" ry="6" strokeWidth="1" />
                  {/* Nose */}
                  <path
                    d="M100 110 L100 125 M95 125 L105 125"
                    strokeWidth="1"
                  />
                  {/* Mouth */}
                  <path d="M90 140 Q100 150 110 140" strokeWidth="1" />
                  {/* Grid lines */}
                  <line
                    x1="50"
                    y1="80"
                    x2="150"
                    y2="80"
                    strokeWidth="0.5"
                    opacity="0.5"
                  />
                  <line
                    x1="50"
                    y1="120"
                    x2="150"
                    y2="120"
                    strokeWidth="0.5"
                    opacity="0.5"
                  />
                  <line
                    x1="50"
                    y1="160"
                    x2="150"
                    y2="160"
                    strokeWidth="0.5"
                    opacity="0.5"
                  />
                  <line
                    x1="80"
                    y1="50"
                    x2="80"
                    y2="190"
                    strokeWidth="0.5"
                    opacity="0.5"
                  />
                  <line
                    x1="100"
                    y1="50"
                    x2="100"
                    y2="190"
                    strokeWidth="0.5"
                    opacity="0.5"
                  />
                  <line
                    x1="120"
                    y1="50"
                    x2="120"
                    y2="190"
                    strokeWidth="0.5"
                    opacity="0.5"
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
                THREAT RECOGNITION
              </div>
              <div className="text-foreground/70 font-mono text-xs">
                {new Date().toLocaleDateString()} - SYSTEM ACTIVE
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
