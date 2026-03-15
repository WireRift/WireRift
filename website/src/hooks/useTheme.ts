import { create } from 'zustand'

type Theme = 'light' | 'dark'

interface ThemeState {
  theme: Theme
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
}

function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark'

  const stored = localStorage.getItem('wirerift-theme') as Theme | null
  if (stored === 'light' || stored === 'dark') return stored

  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem('wirerift-theme', theme)
}

export const useTheme = create<ThemeState>((set) => {
  const initial = getInitialTheme()
  applyTheme(initial)

  return {
    theme: initial,
    setTheme: (theme: Theme) => {
      applyTheme(theme)
      set({ theme })
    },
    toggleTheme: () => {
      set((state) => {
        const next = state.theme === 'dark' ? 'light' : 'dark'
        applyTheme(next)
        return { theme: next }
      })
    },
  }
})
