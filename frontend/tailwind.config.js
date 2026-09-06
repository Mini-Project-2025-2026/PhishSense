/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        "surface-container-lowest": "#070a12",
        "surface-container-low": "#0f1522",
        "surface-container": "#141c2e",
        "surface-container-high": "#1c263c",
        "surface-container-highest": "#25324d",
        "surface": "#0a0e19",
        "on-background": "#e2e8f0",
        "on-surface": "#e2e8f0",
        "on-surface-variant": "#94a3b8",
        "outline": "#64748b",
        "primary": "#38bdf8",
        "primary-hover": "#0284c7",
        "on-primary": "#031726",
        "primary-fixed": "#bae6fd",
        "secondary": "#818cf8",
        "accent": "#06b6d4",
        "status-safe": "#10b981",
        "status-warning": "#f59e0b",
        "error": "#ef4444",
        "on-error": "#ffffff",
        "glass": "rgba(255, 255, 255, 0.04)",
        "glass-border": "rgba(255, 255, 255, 0.08)"
      },
      borderRadius: {
        "DEFAULT": "0.375rem",
        "lg": "0.5rem",
        "xl": "0.75rem",
        "2xl": "1rem",
        "full": "9999px"
      },
      spacing: {
        "base": "4px",
        "container-max": "1150px",
        "margin-mobile": "16px",
        "margin-desktop": "32px",
        "gutter": "24px"
      },
      fontFamily: {
        "geist": ["Geist", "Inter", "sans-serif"],
        "sans": ["Inter", "Geist", "sans-serif"],
        "body-md": ["Inter", "Geist", "sans-serif"],
        "body-sm": ["Inter", "Geist", "sans-serif"],
        "heading": ["Space Grotesk", "Sora", "Geist", "sans-serif"],
        "display": ["Space Grotesk", "Sora", "Geist", "sans-serif"],
        "headline-lg": ["Space Grotesk", "Sora", "Geist", "sans-serif"],
        "headline-md": ["Space Grotesk", "Sora", "Geist", "sans-serif"],
        "headline-lg-mobile": ["Space Grotesk", "Sora", "Geist", "sans-serif"],
        "title-md": ["Space Grotesk", "Sora", "Geist", "sans-serif"],
        "mono": ["JetBrains Mono", "monospace"],
        "code-sm": ["JetBrains Mono", "monospace"],
        "label-caps": ["JetBrains Mono", "monospace"]
      },
      fontSize: {
        "display-lg": ["44px", { lineHeight: "1.15", letterSpacing: "-0.02em", fontWeight: "700" }],
        "headline-lg": ["32px", { lineHeight: "1.25", letterSpacing: "-0.015em", fontWeight: "700" }],
        "headline-md": ["24px", { lineHeight: "1.3", letterSpacing: "-0.01em", fontWeight: "600" }],
        "title-md": ["20px", { lineHeight: "1.4", fontWeight: "600" }],
        "body-md": ["15px", { lineHeight: "1.6", fontWeight: "400" }],
        "body-sm": ["14px", { lineHeight: "1.5", fontWeight: "400" }],
        "code-sm": ["13px", { lineHeight: "1.5", fontWeight: "400" }],
        "label-caps": ["12px", { lineHeight: "1.4", letterSpacing: "0.06em", fontWeight: "600" }]
      }
    },
  },
  plugins: [],
}
