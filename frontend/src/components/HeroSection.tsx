import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { Scene3D } from "./Scene3D";

function UploadZipBlock() {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div
      className="flex items-center justify-center text-center px-6 py-10 rounded bg-transparent cursor-pointer"
      onClick={handleClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") handleClick();
      }}
    >
      <input
        ref={fileInputRef}
        type="file"
        accept=".zip,application/zip,application/x-zip-compressed"
        className="hidden"
        onChange={() => {}}
      />
      <div>
        <div className="text-foreground/80 mb-2">
          Drag & drop your .zip here
        </div>
        <div className="text-xs text-foreground/60">
          or click to choose a file
        </div>
      </div>
    </div>
  );
}

export function HeroSection() {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = -(e.clientY / window.innerHeight) * 2 + 1;
      setMousePosition({ x, y });
    };

    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, []);

  return (
    <section
      id="home"
      className="relative min-h-screen flex items-center justify-center overflow-hidden"
    >
      {/* Background particle effects */}
      <div className="absolute inset-0 particle-bg opacity-50" />

      {/* 3D Brain Animation */}
      <div className="absolute inset-0">
        <Scene3D mousePosition={mousePosition} className="w-full h-full" />
      </div>

      {/* Hero Text */}
      <div className="relative z-10 container mx-auto px-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 1, delay: 0.2 }}
            className="text-left"
          >
            <h1 className="text-6xl lg:text-8xl font-bold">
              <span className="block cyber-text-glow">Adaptive</span>
              <span className="block text-foreground/90">Threat Modeling</span>
            </h1>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 1, delay: 0.8 }}
            className="text-right"
          >
            <h1 className="text-6xl lg:text-8xl font-bold">
              <span className="block text-foreground/90">for your</span>
              <span className="block cyber-text-glow">Code & Cloud</span>
            </h1>
          </motion.div>
        </div>

        {/* Input actions */}
        <div className="mt-12 grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* GitHub repo input */}
          <motion.div
            initial={{ opacity: 0, x: -60 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="glassmorphism border border-primary/30 rounded-lg p-4"
          >
            <label className="block text-sm text-foreground/70 mb-2">
              GitHub repository URL
            </label>
            <div className="flex items-center space-x-3">
              <input
                type="url"
                placeholder="https://github.com/owner/repo"
                className="w-full bg-transparent border border-primary/40 rounded px-3 py-2 focus:outline-none focus:border-primary/70"
              />
              <button className="px-4 py-2 border border-primary/40 rounded hover:cyber-glow transition-colors">
                Analyze
              </button>
            </div>
            <p className="mt-2 text-xs text-foreground/60">
              Paste a public repo link to generate an attack surface map.
            </p>
          </motion.div>

          {/* Drag and drop upload */}
          <motion.div
            initial={{ opacity: 0, x: 60 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.5 }}
            className="glassmorphism border border-dashed border-primary/40 rounded-lg p-4"
          >
            <label className="block text-sm text-foreground/70 mb-2">
              Upload a project zip
            </label>
            <UploadZipBlock />
          </motion.div>
        </div>
      </div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2 }}
        className="absolute bottom-8 left-1/2 transform -translate-x-1/2"
      >
        <div className="w-6 h-10 border-2 border-primary rounded-full flex justify-center">
          <motion.div
            animate={{ y: [0, 12, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="w-1 h-3 bg-primary rounded-full mt-2"
          />
        </div>
      </motion.div>
    </section>
  );
}
