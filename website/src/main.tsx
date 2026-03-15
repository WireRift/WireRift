import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'

// SPA redirect handling for GitHub Pages
// When GitHub Pages serves a 404, the custom 404.html redirects here with
// the original path encoded in the query string
const redirect = sessionStorage.getItem('spa-redirect')
if (redirect) {
  sessionStorage.removeItem('spa-redirect')
  const url = new URL(redirect, window.location.origin)
  window.history.replaceState(null, '', url.pathname + url.search + url.hash)
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
