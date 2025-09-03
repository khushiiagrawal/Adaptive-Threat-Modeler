import { Canvas } from "@react-three/fiber";
import { Suspense } from "react";
import { ParticleBrain } from "./ParticleBrain";

interface Scene3DProps {
  mousePosition: { x: number; y: number };
  className?: string;
}

export function Scene3D({ mousePosition, className = "" }: Scene3DProps) {
  return (
    <Canvas
      className={className}
      camera={{ position: [0, 0, 5], fov: 75 }}
      style={{ background: "transparent" }}
    >
      <Suspense fallback={null}>
        <ambientLight intensity={0.1} />
        <pointLight position={[10, 10, 10]} intensity={0.5} color="#39ff14" />
        <ParticleBrain mousePosition={mousePosition} />
      </Suspense>
    </Canvas>
  );
}
