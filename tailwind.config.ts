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
        "trust-green": "#B2F2BB",
        "trust-yellow": "#FFF3BF",
        "trust-cyan": "#06b6d4",
        "trust-dark": "#1A1A1A",
        "trust-slate": "#0b1120",
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
