import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router'
import { Layout } from '@/components/layout/Layout'
import { DocsLayout } from '@/components/layout/DocsLayout'

const HomePage = lazy(() => import('@/pages/HomePage'))
const DocsPage = lazy(() => import('@/pages/DocsPage'))
const ChangelogPage = lazy(() => import('@/pages/ChangelogPage'))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage'))

function LoadingFallback() {
  return (
    <div className="flex items-center justify-center min-h-[50vh]">
      <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<LoadingFallback />}>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<HomePage />} />
            <Route path="/changelog" element={<ChangelogPage />} />
            <Route path="/docs" element={<DocsLayout />}>
              <Route index element={<DocsPage />} />
              <Route path=":slug" element={<DocsPage />} />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  )
}
