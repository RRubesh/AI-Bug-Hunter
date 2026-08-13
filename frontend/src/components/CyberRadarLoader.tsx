import React, { useEffect, useState } from "react";

interface CyberRadarLoaderProps {
  size?: "sm" | "md" | "lg" | "xl" | "full";
  text?: string;
  showText?: boolean;
  className?: string;
}

/**
 * Universal Security Scanner Animation Component for AI BUG HUNTER.
 * Represents all platform loading states (detecting, scanning, analyzing, processing, connecting, loading).
 */
export const CyberRadarLoader: React.FC<CyberRadarLoaderProps> = ({
  size = "md",
  text = "ANALYZING SECURITY",
  showText = true,
  className = "",
}) => {
  const [dotCount, setDotCount] = useState(1);

  useEffect(() => {
    if (!showText) return;
    const interval = setInterval(() => {
      setDotCount((prev) => (prev % 3) + 1);
    }, 450);
    return () => clearInterval(interval);
  }, [showText]);

  const dots = ".".repeat(dotCount);

  // Size mappings (1:1 square ratio)
  const containerSize =
    size === "sm" ? "w-28 h-28" :
    size === "md" ? "w-56 h-56" :
    size === "lg" ? "w-72 h-72" :
    size === "xl" ? "w-96 h-96" :
    "w-full h-full max-w-sm aspect-square";

  return (
    <div className={`flex flex-col items-center justify-center p-4 text-slate-100 font-mono select-none ${className}`}>
      
      {/* 1:1 Square Universal AI Security Scanner Container */}
      <div className={`relative ${containerSize} flex items-center justify-center animate-core-breathe`}>
        
        {/* SVG Universal Scanner Vector Graphic & Motion Layer */}
        <svg
          className="absolute inset-0 w-full h-full text-cyan-400 overflow-visible"
          viewBox="0 0 200 200"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            {/* Holographic Radar Gradient Sweep */}
            <linearGradient id="radarSweepGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.4" />
              <stop offset="50%" stopColor="#3b82f6" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0" />
            </linearGradient>

            {/* Core Shield Neon Gradient */}
            <linearGradient id="shieldGlowGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.9" />
              <stop offset="50%" stopColor="#3b82f6" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.9" />
            </linearGradient>

            {/* Subtle Core Background Radial Glow */}
            <radialGradient id="coreRadialGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.25" />
              <stop offset="60%" stopColor="#8b5cf6" stopOpacity="0.08" />
              <stop offset="100%" stopColor="#030712" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Central Radial Background Ambient Glow */}
          <circle cx="100" cy="100" r="90" fill="url(#coreRadialGlow)" />

          {/* 1. Outer Continuous Rotating HUD Ring (Clockwise) */}
          <g className="animate-spin-slow origin-center">
            {/* Outer Boundary Ring */}
            <circle cx="100" cy="100" r="92" stroke="#06b6d4" strokeOpacity="0.3" strokeWidth="1" strokeDasharray="6 4" />
            
            {/* Tick Marks (Degree Identifiers) */}
            <line x1="100" y1="5" x2="100" y2="12" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round" />
            <line x1="100" y1="188" x2="100" y2="195" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round" />
            <line x1="5" y1="100" x2="12" y2="100" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round" />
            <line x1="188" y1="100" x2="195" y2="100" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round" />

            {/* Diagonal Corner Accents */}
            <circle cx="33" cy="33" r="1.5" fill="#38bdf8" />
            <circle cx="167" cy="33" r="1.5" fill="#38bdf8" />
            <circle cx="33" cy="167" r="1.5" fill="#38bdf8" />
            <circle cx="167" cy="167" r="1.5" fill="#38bdf8" />
          </g>

          {/* 2. Inner Counter-Rotating Ring (Counter-Clockwise) */}
          <g className="animate-spin-reverse origin-center">
            <circle cx="100" cy="100" r="78" stroke="#8b5cf6" strokeOpacity="0.35" strokeWidth="1.2" strokeDasharray="3 9" />
            <circle cx="100" cy="100" r="64" stroke="#06b6d4" strokeOpacity="0.2" strokeWidth="1" strokeDasharray="40 10 15 10" />
          </g>

          {/* 3. Static Concentric Grid & Target Crosshairs */}
          <circle cx="100" cy="100" r="50" stroke="#38bdf8" strokeOpacity="0.15" strokeWidth="1" />
          <circle cx="100" cy="100" r="32" stroke="#06b6d4" strokeOpacity="0.25" strokeWidth="1" strokeDasharray="4 4" />

          <line x1="20" y1="100" x2="180" y2="100" stroke="#06b6d4" strokeOpacity="0.12" strokeWidth="1" />
          <line x1="100" y1="20" x2="100" y2="180" stroke="#06b6d4" strokeOpacity="0.12" strokeWidth="1" />

          {/* 4. Clockwise Sweeping Holographic Radar Beam Sector */}
          <g className="animate-spin-slow origin-center">
            <path
              d="M100 100 L100 8 A92 92 0 0 1 192 100 Z"
              fill="url(#radarSweepGradient)"
              opacity="0.85"
            />
            {/* Leading Neon Edge Line */}
            <line x1="100" y1="100" x2="192" y2="100" stroke="#22d3ee" strokeWidth="1.5" strokeOpacity="0.8" />
          </g>

          {/* 5. Sequentially Illuminating Digital Circuit Nodes */}
          <g>
            {/* Circuit Traces */}
            <path d="M100 50 L100 36 M100 150 L100 164 M50 100 L36 100 M150 100 L164 100" stroke="#06b6d4" strokeOpacity="0.3" strokeWidth="1.2" />
            <path d="M65 65 L52 52 M135 65 L148 52 M65 135 L52 148 M135 135 L148 148" stroke="#8b5cf6" strokeOpacity="0.3" strokeWidth="1.2" />

            {/* Illuminated Nodes */}
            <circle cx="100" cy="36" r="3" fill="#22d3ee" className="animate-circuit-1" />
            <circle cx="164" cy="100" r="3" fill="#60a5fa" className="animate-circuit-2" />
            <circle cx="100" cy="164" r="3" fill="#a78bfa" className="animate-circuit-3" />
            <circle cx="36" cy="100" r="3" fill="#22d3ee" className="animate-circuit-1" />
            <circle cx="52" cy="52" r="2.5" fill="#a78bfa" className="animate-circuit-3" />
            <circle cx="148" cy="52" r="2.5" fill="#60a5fa" className="animate-circuit-2" />
            <circle cx="148" cy="148" r="2.5" fill="#22d3ee" className="animate-circuit-1" />
            <circle cx="52" cy="148" r="2.5" fill="#60a5fa" className="animate-circuit-2" />
          </g>

          {/* 6. Small Orbiting Data Particles */}
          <g className="origin-center">
            {/* Particle 1: Cyan Orbit */}
            <circle cx="100" cy="45" r="2.5" fill="#22d3ee">
              <animateTransform attributeName="transform" type="rotate" from="0 100 100" to="360 100 100" dur="4s" repeatCount="indefinite" />
            </circle>

            {/* Particle 2: Electric Blue Orbit */}
            <circle cx="100" cy="25" r="2" fill="#60a5fa">
              <animateTransform attributeName="transform" type="rotate" from="360 100 100" to="0 100 100" dur="7s" repeatCount="indefinite" />
            </circle>

            {/* Particle 3: Violet Orbit */}
            <circle cx="100" cy="170" r="2" fill="#a78bfa">
              <animateTransform attributeName="transform" type="rotate" from="180 100 100" to="540 100 100" dur="5.5s" repeatCount="indefinite" />
            </circle>
          </g>

          {/* 7. Central AI Security Core (Integrated Shield + Bug Emblem) */}
          <g transform="translate(100, 100)">
            {/* Outer Shield Outline */}
            <path
              d="M0 -34 L26 -21 V-2 C26 18 11 31 0 36 C-11 31 -26 18 -26 -2 V-21 Z"
              fill="#030712"
              fillOpacity="0.85"
              stroke="url(#shieldGlowGradient)"
              strokeWidth="2.2"
              strokeLinejoin="round"
              className="drop-shadow-[0_0_12px_rgba(6,182,212,0.8)]"
            />

            {/* Inner Cyber Bug / AI Core Node Geometry */}
            <g opacity="0.95">
              {/* Bug Body / Core Nucleus */}
              <path
                d="M0 -16 C-7 -16 -12 -11 -12 -3 V8 C-12 15 -7 20 0 20 C7 20 12 15 12 8 V-3 C12 -11 7 -16 0 -16 Z"
                fill="url(#shieldGlowGradient)"
                fillOpacity="0.22"
                stroke="#22d3ee"
                strokeWidth="1.5"
              />

              {/* Center Vertical Backbone & AI Pulse Nodes */}
              <line x1="0" y1="-16" x2="0" y2="20" stroke="#22d3ee" strokeWidth="1.5" />
              <circle cx="0" cy="-6" r="2" fill="#22d3ee" />
              <circle cx="0" cy="2" r="2" fill="#60a5fa" />
              <circle cx="0" cy="10" r="2" fill="#a78bfa" />

              {/* Bug Circuit Legs (Left & Right) */}
              <path d="M-12 -3 H-20 M12 -3 H20" stroke="#22d3ee" strokeWidth="1.4" strokeLinecap="round" />
              <path d="M-12 5 H-21 M12 5 H21" stroke="#3b82f6" strokeWidth="1.4" strokeLinecap="round" />
              <path d="M-10 13 L-18 19 M10 13 L18 19" stroke="#8b5cf6" strokeWidth="1.4" strokeLinecap="round" />

              {/* Antennae Sensor Nodes */}
              <path d="M-5 -16 L-12 -24 M5 -16 L12 -24" stroke="#22d3ee" strokeWidth="1.4" strokeLinecap="round" />
              <circle cx="-12" cy="-24" r="1.5" fill="#22d3ee" />
              <circle cx="12" cy="-24" r="1.5" fill="#22d3ee" />
            </g>
          </g>
        </svg>
      </div>

      {/* Futuristic Animated Status Label Below Icon */}
      {showText && (
        <div className="mt-4 flex items-center gap-1 font-mono text-xs font-bold tracking-widest text-cyan-400 uppercase drop-shadow-[0_0_12px_rgba(6,182,212,0.6)]">
          <span>{text}</span>
          <span className="w-6 text-left text-cyan-300 font-mono font-bold">{dots}</span>
        </div>
      )}

    </div>
  );
};

export default CyberRadarLoader;
