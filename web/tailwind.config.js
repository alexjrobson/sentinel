/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["IBM Plex Sans", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "Consolas", "monospace"],
      },
      colors: {
        ink: {
          950: "#070b14",
          900: "#0b1220",
          800: "#111a2c",
          700: "#182338",
        },
        mint: "#7ee0c6",
        warn: "#e7b86d",
      },
    },
  },
  plugins: [],
};
