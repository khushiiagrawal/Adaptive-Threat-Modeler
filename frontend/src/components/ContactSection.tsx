import { motion } from "framer-motion";
import { useInView } from "framer-motion";
import { useRef } from "react";
import { Button } from "@/components/ui/button";
import { Canvas } from "@react-three/fiber";
import { Points, PointMaterial } from "@react-three/drei";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

function OrganicShapes() {
  const leftRef = useRef<THREE.Points>(null);
  const rightRef = useRef<THREE.Points>(null);

  const particleCount = 800;

  const createOrganicShape = (offset: number) => {
    const positions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      const phi = Math.random() * Math.PI * 2;
      const theta = Math.random() * Math.PI;

      // Create organic blob shape
      let radius =
        1 +
        Math.sin(phi * 3 + offset) * 0.3 +
        Math.sin(theta * 4 + offset) * 0.2;
      radius += Math.sin(phi + theta + offset) * 0.2 + Math.random() * 0.1;

      const x = radius * Math.sin(theta) * Math.cos(phi);
      const y = radius * Math.sin(theta) * Math.sin(phi);
      const z = radius * Math.cos(theta);

      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;
    }

    return positions;
  };

  const leftPositions = createOrganicShape(0);
  const rightPositions = createOrganicShape(Math.PI);

  useFrame((state) => {
    const time = state.clock.getElapsedTime();

    if (leftRef.current && rightRef.current) {
      // Organic movement - cells merging and separating
      const separation = 3 + Math.sin(time * 0.5) * 1.5;

      leftRef.current.position.x = -separation / 2;
      rightRef.current.position.x = separation / 2;

      // Rotation and morphing
      leftRef.current.rotation.y = time * 0.2;
      rightRef.current.rotation.y = -time * 0.2;

      leftRef.current.rotation.x = Math.sin(time * 0.3) * 0.3;
      rightRef.current.rotation.x = Math.sin(time * 0.3 + Math.PI) * 0.3;

      // Particle flow between shapes
      const leftPositionsArray = leftRef.current.geometry.attributes.position
        .array as Float32Array;
      const rightPositionsArray = rightRef.current.geometry.attributes.position
        .array as Float32Array;

      for (let i = 0; i < particleCount; i++) {
        const i3 = i * 3;

        // Add flowing motion
        leftPositionsArray[i3] =
          leftPositions[i3] + Math.sin(time + i * 0.01) * 0.1;
        leftPositionsArray[i3 + 1] =
          leftPositions[i3 + 1] + Math.cos(time + i * 0.02) * 0.1;

        rightPositionsArray[i3] =
          rightPositions[i3] + Math.sin(time + i * 0.01 + Math.PI) * 0.1;
        rightPositionsArray[i3 + 1] =
          rightPositions[i3 + 1] + Math.cos(time + i * 0.02 + Math.PI) * 0.1;
      }

      leftRef.current.geometry.attributes.position.needsUpdate = true;
      rightRef.current.geometry.attributes.position.needsUpdate = true;
    }
  });

  return (
    <>
      <Points ref={leftRef} positions={leftPositions}>
        <PointMaterial
          transparent
          color="#39ff14"
          size={0.02}
          sizeAttenuation={true}
          blending={THREE.AdditiveBlending}
        />
      </Points>
      <Points ref={rightRef} positions={rightPositions}>
        <PointMaterial
          transparent
          color="#39ff14"
          size={0.02}
          sizeAttenuation={true}
          blending={THREE.AdditiveBlending}
        />
      </Points>
    </>
  );
}

export function ContactSection() {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true, amount: 0.3 });

  return (
    <section
      id="contact"
      className="min-h-screen flex items-center justify-center relative py-20"
    >
      {/* Background 3D shapes */}
      <div className="absolute inset-0">
        <Canvas camera={{ position: [0, 0, 8], fov: 75 }}>
          <ambientLight intensity={0.1} />
          <pointLight position={[10, 10, 10]} intensity={0.3} color="#39ff14" />
          <OrganicShapes />
        </Canvas>
      </div>

      <div ref={ref} className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="text-center"
        >
          <h2 className="text-6xl lg:text-8xl font-bold mb-8 cyber-text-glow">
            Try it on your repo
          </h2>

          <motion.p
            initial={{ opacity: 0 }}
            animate={isInView ? { opacity: 1 } : {}}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="text-xl text-foreground/80 mb-12 max-w-2xl mx-auto"
          >
            Paste a GitHub URL or upload a zip in the hero section to generate
            your interactive threat map.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={isInView ? { opacity: 1, scale: 1 } : {}}
            transition={{ duration: 0.6, delay: 0.6 }}
          >
            <Button
              size="lg"
              className="text-lg px-12 py-6 cyber-glow hover:shadow-[0_0_40px_hsl(var(--cyber-green)/0.8)] transition-all duration-300 transform hover:scale-105"
            >
              Get started
            </Button>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}
