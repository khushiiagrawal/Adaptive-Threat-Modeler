import { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Points, PointMaterial } from '@react-three/drei';
import * as THREE from 'three';

interface ParticleBrainProps {
  mousePosition: { x: number; y: number };
}

export function ParticleBrain({ mousePosition }: ParticleBrainProps) {
  const ref = useRef<THREE.Points>(null);
  const particleCount = 3000;

  const particles = useMemo(() => {
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      // Create brain-like organic shape using multiple noise functions
      const phi = Math.random() * Math.PI * 2;
      const theta = Math.random() * Math.PI;
      
      // Base sphere with organic deformation
      let radius = 1.5 + Math.sin(phi * 3) * 0.3 + Math.sin(theta * 5) * 0.2;
      
      // Add brain-like lobes
      radius += Math.sin(phi * 2) * Math.sin(theta * 3) * 0.4;
      
      const x = radius * Math.sin(theta) * Math.cos(phi);
      const y = radius * Math.sin(theta) * Math.sin(phi);
      const z = radius * Math.cos(theta);

      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      // Green particles with some variation
      colors[i * 3] = 0.2 + Math.random() * 0.3; // Red
      colors[i * 3 + 1] = 1.0; // Green
      colors[i * 3 + 2] = 0.2 + Math.random() * 0.3; // Blue
    }

    return { positions, colors };
  }, []);

  useFrame((state) => {
    if (ref.current) {
      const time = state.clock.getElapsedTime();
      
      // Continuous organic rotation and morphing
      ref.current.rotation.y = time * 0.1;
      ref.current.rotation.x = Math.sin(time * 0.05) * 0.1;
      
      // React to mouse position
      const targetRotationY = mousePosition.x * 0.3;
      const targetRotationX = -mousePosition.y * 0.3;
      
      ref.current.rotation.y += (targetRotationY - ref.current.rotation.y) * 0.05;
      ref.current.rotation.x += (targetRotationX - ref.current.rotation.x) * 0.05;

      // Animate particle positions for organic movement
      const positions = ref.current.geometry.attributes.position.array as Float32Array;
      
      for (let i = 0; i < particleCount; i++) {
        const i3 = i * 3;
        const originalX = particles.positions[i3];
        const originalY = particles.positions[i3 + 1];
        const originalZ = particles.positions[i3 + 2];
        
        // Add subtle wave motion
        positions[i3] = originalX + Math.sin(time + originalY * 2) * 0.02;
        positions[i3 + 1] = originalY + Math.cos(time + originalX * 2) * 0.02;
        positions[i3 + 2] = originalZ + Math.sin(time + originalX + originalY) * 0.01;
      }
      
      ref.current.geometry.attributes.position.needsUpdate = true;
    }
  });

  return (
    <Points ref={ref} positions={particles.positions} colors={particles.colors}>
      <PointMaterial
        transparent
        color="#39ff14"
        size={0.03}
        sizeAttenuation={true}
        vertexColors
        blending={THREE.AdditiveBlending}
      />
    </Points>
  );
}