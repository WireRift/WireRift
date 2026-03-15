import { Hero } from '@/components/home/Hero'
import { Features } from '@/components/home/Features'
import { QuickStart } from '@/components/home/QuickStart'
import { Architecture } from '@/components/home/Architecture'
import { CTA } from '@/components/home/CTA'

export default function HomePage() {
  return (
    <>
      <Hero />
      <Features />
      <QuickStart />
      <Architecture />
      <CTA />
    </>
  )
}
