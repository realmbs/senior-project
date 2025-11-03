/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Base glass surfaces
        glass: {
          primary: 'rgba(15, 23, 42, 0.6)',
          secondary: 'rgba(30, 41, 59, 0.4)',
          tertiary: 'rgba(51, 65, 85, 0.3)',
        },

        // Threat intelligence spectrum
        threat: {
          critical: '#dc2626',
          'critical-bg': 'rgba(220, 38, 38, 0.1)',
          'critical-border': 'rgba(220, 38, 38, 0.3)',

          high: '#ea580c',
          'high-bg': 'rgba(234, 88, 12, 0.1)',
          'high-border': 'rgba(234, 88, 12, 0.3)',

          medium: '#d97706',
          'medium-bg': 'rgba(217, 119, 6, 0.1)',
          'medium-border': 'rgba(217, 119, 6, 0.3)',

          low: '#0284c7',
          'low-bg': 'rgba(2, 132, 199, 0.1)',
          'low-border': 'rgba(2, 132, 199, 0.3)',

          info: '#0891b2',
          'info-bg': 'rgba(8, 145, 178, 0.1)',
          'info-border': 'rgba(8, 145, 178, 0.3)',

          safe: '#059669',
          'safe-bg': 'rgba(5, 150, 105, 0.1)',
          'safe-border': 'rgba(5, 150, 105, 0.3)',

          unknown: '#64748b',
          'unknown-bg': 'rgba(100, 116, 139, 0.1)',
          'unknown-border': 'rgba(100, 116, 139, 0.3)',
        },

        // Cyber security accent colors
        cyber: {
          primary: '#3b82f6',
          secondary: '#8b5cf6',
          accent: '#06b6d4',
          neon: '#00ff88',
        },

        // Status indicators
        status: {
          online: '#10b981',
          degraded: '#f59e0b',
          offline: '#ef4444',
          maintenance: '#6366f1',
        },

        // Dark mode background gradients
        bg: {
          primary: 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%)',
          surface: 'rgba(15, 23, 42, 0.8)',
          'surface-hover': 'rgba(30, 41, 59, 0.9)',
        },

        // Border colors
        border: {
          glass: 'rgba(148, 163, 184, 0.2)',
          accent: 'rgba(59, 130, 246, 0.3)',
          divider: 'rgba(71, 85, 105, 0.4)',
        },
      },

      backgroundImage: {
        'gradient-cyber': 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%)',
        'glass-gradient': 'linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%)',
      },

      backdropBlur: {
        xs: '2px',
        glass: '12px',
        heavy: '24px',
      },

      boxShadow: {
        'glass': '0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1)',
        'glass-sm': '0 4px 16px rgba(0, 0, 0, 0.2)',
        'glass-lg': '0 16px 64px rgba(0, 0, 0, 0.4)',
        'threat-critical': '0 0 20px rgba(220, 38, 38, 0.4), 0 8px 32px rgba(0, 0, 0, 0.3)',
        'threat-medium': '0 0 16px rgba(217, 119, 6, 0.3), 0 4px 16px rgba(0, 0, 0, 0.2)',
        'cyber-glow': '0 0 20px rgba(59, 130, 246, 0.3)',
      },

      animation: {
        'pulse-glow': 'pulse 2s infinite',
        'scan-line': 'scanLine 3s linear infinite',
        'data-flow': 'dataFlow 1.5s ease-in-out infinite',
        'float': 'float 6s ease-in-out infinite',
      },

      keyframes: {
        scanLine: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100vw)' },
        },
        dataFlow: {
          '0%, 100%': { opacity: '0.3', transform: 'translateY(0)' },
          '50%': { opacity: '1', transform: 'translateY(-4px)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
      },

      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        'sans': ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}