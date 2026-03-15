import { Outlet } from 'react-router'
import { Header } from './Header'
import { Footer } from './Footer'

export function Layout() {
  return (
    <>
      <Header />
      <main className="flex-1">
        <Outlet />
      </main>
      <Footer />
    </>
  )
}
