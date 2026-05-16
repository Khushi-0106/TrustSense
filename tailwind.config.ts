import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        "trust-green":  "#10b981",   // emerald — verification, success
        "trust-yellow": "#c9a84c",   // gold — accents, highlights
        "trust-cyan":   "#38bdf8",   // sky blue — data, info
        "trust-dark":   "#0a1628",   // deepest navy
        "trust-slate":  "#0f1c3a",   // navy — primary dark bg
        "trust-navy":   "#1a2744",   // mid navy — cards
        "trust-gold":   "#c9a84c",   // gold alias
      },
      animation: {
        glow: "glow 2s infinite ease-in-out",
        glitch: "glitch 1s infinite linear alternate-reverse",
      },
      keyframes: {
        glow: {
          "0%, 100%": { textShadow: "0 0 10px #06b6d4, 0 0 20px #06b6d4" },
          "50%": { textShadow: "0 0 20px #06b6d4, 0 0 30px #10b981" },
        },
        glitch: {
          "0%": { clip: "rect(31px, 9999px, 94px, 0)" },
          "100%": { clip: "rect(82px, 9999px, 31px, 0)" },
        },
      },
    },
  },
  plugins: [],
};
export default config;
