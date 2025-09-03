import { motion } from 'framer-motion';
import { useInView } from 'framer-motion';
import { useRef } from 'react';
import { Eye, Lock, Shield, Zap } from 'lucide-react';

const aboutItems = [
  {
    title: "Provide Solutions",
    description: "We deliver cutting-edge cybersecurity solutions tailored to modern threats.",
    icon: Shield,
    animation: "geometric"
  },
  {
    title: "Staying Ahead",
    description: "Our team continuously evolves to stay ahead of emerging cyber threats.",
    icon: Zap,
    animation: "device"
  },
  {
    title: "Experience",
    description: "Years of expertise in protecting digital assets and infrastructure.",
    icon: Eye,
    animation: "data-flow"
  },
  {
    title: "How We Help",
    description: "Comprehensive security assessments and continuous monitoring services.",
    icon: Lock,
    animation: "security"
  }
];

export function AboutSection() {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true, amount: 0.3 });

  return (
    <section id="about" className="min-h-screen py-20 relative">
      <div className="absolute inset-0 bg-gradient-to-br from-background via-cyber-darker to-background" />
      
      <div ref={ref} className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="text-center mb-16"
        >
          <h2 className="text-5xl lg:text-7xl font-bold mb-8">
            We are a <span className="cyber-text-glow">boutique</span>
          </h2>
          <h2 className="text-5xl lg:text-7xl font-bold mb-8 cyber-text-glow">
            cyber security company
          </h2>
        </motion.div>

        {/* Dynamic grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {aboutItems.map((item, index) => {
            const IconComponent = item.icon;
            
            return (
              <motion.div
                key={item.title}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={isInView ? { opacity: 1, scale: 1 } : {}}
                transition={{ duration: 0.6, delay: index * 0.2 }}
                className="relative glassmorphism p-8 rounded-lg border border-primary/30 hover:border-primary/60 transition-all duration-300 group overflow-hidden"
              >
                {/* Background animation */}
                <div className="absolute inset-0 opacity-20">
                  {item.animation === "geometric" && (
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
                      className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2"
                    >
                      <div className="w-32 h-32 border border-primary/30">
                        <div className="absolute inset-4 border border-primary/20 rotate-45" />
                        <div className="absolute inset-8 border border-primary/10 rotate-90" />
                      </div>
                    </motion.div>
                  )}
                  
                  {item.animation === "device" && (
                    <motion.div
                      animate={{ scale: [1, 1.1, 1] }}
                      transition={{ duration: 3, repeat: Infinity }}
                      className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2"
                    >
                      <div className="w-24 h-16 bg-primary/10 rounded border border-primary/30" />
                      <div className="absolute inset-2 bg-primary/5 rounded" />
                      <motion.div
                        animate={{ opacity: [0.3, 1, 0.3] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="absolute top-1 right-1 w-2 h-2 bg-primary rounded-full"
                      />
                    </motion.div>
                  )}
                  
                  {item.animation === "data-flow" && (
                    <div className="absolute inset-0">
                      {[...Array(6)].map((_, i) => (
                        <motion.div
                          key={i}
                          animate={{
                            x: [0, 100, 0],
                            opacity: [0, 1, 0]
                          }}
                          transition={{
                            duration: 2,
                            repeat: Infinity,
                            delay: i * 0.3
                          }}
                          className="absolute w-2 h-2 bg-primary/40 rounded-full"
                          style={{
                            top: 20 + i * 15 + '%',
                            left: '10%'
                          }}
                        />
                      ))}
                    </div>
                  )}
                  
                  {item.animation === "security" && (
                    <motion.div
                      animate={{ rotateY: [0, 180, 360] }}
                      transition={{ duration: 4, repeat: Infinity }}
                      className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2"
                    >
                      <Eye className="w-12 h-12 text-primary/30" />
                      <motion.div
                        animate={{ scale: [1, 1.2, 1] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="absolute -top-2 -right-2"
                      >
                        <Lock className="w-6 h-6 text-primary/40" />
                      </motion.div>
                    </motion.div>
                  )}
                </div>

                {/* Content */}
                <div className="relative z-10">
                  <IconComponent className="w-8 h-8 text-primary mb-4 group-hover:text-primary group-hover:animate-pulse-glow" />
                  <h3 className="text-xl font-bold mb-4 group-hover:cyber-text-glow transition-all duration-300">
                    {item.title}
                  </h3>
                  <p className="text-foreground/70 text-sm leading-relaxed">
                    {item.description}
                  </p>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}