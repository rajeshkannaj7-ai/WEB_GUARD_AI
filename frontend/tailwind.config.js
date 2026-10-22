/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#080C14',        // Deep SOC navy/dark background
          surface: '#0D1322',   // Primary panel surface
          card: '#111A2E',      // Card surface
          border: '#1E293B',    // Clean slate border
          subtle: '#162035',    // Subtle divider
          
          // Severity & Status Accents
          critical: '#EF4444',  // Critical / Malicious
          warning: '#F59E0B',   // Suspicious / Warning
          safe: '#10B981',      // Safe / Clean
          accent: '#0EA5E9',    // Primary SOC Sky/Blue
          cyan: '#06B6D4',      // Secondary Accent
          muted: '#64748B'      // Muted metadata
        },
        // Backwards compatibility for existing class mappings
        cyber: {
          bg: '#080C14',
          card: '#111A2E',
          border: '#1E293B',
          cyan: '#0EA5E9',
          green: '#10B981',
          red: '#EF4444',
          yellow: '#F59E0B'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Consolas', 'monospace']
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-in-out',
        'slide-up': 'slideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        }
      }
    },
  },
  plugins: [],
}
