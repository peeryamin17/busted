import { Nav } from './components/Nav';
import { Hero } from './components/Hero';
import { Ticker } from './components/Ticker';
import { Bento } from './components/Bento';
import { Swarm } from './components/Swarm';
import { HowItWorks } from './components/HowItWorks';
import { Pricing } from './components/Pricing';
import { Faq } from './components/Faq';
import { Download } from './components/Download';
import { Footer } from './components/Footer';

export default function App() {
  return (
    <div className="min-h-screen bg-ink text-body">
      <a
        href="#what"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-mint focus:px-4 focus:py-2 focus:text-ink"
      >
        Skip to content
      </a>
      <Nav />
      <main>
        <Hero />
        <Ticker />
        <Bento />
        <Swarm />
        <HowItWorks />
        <Pricing />
        <Faq />
        <Download />
      </main>
      <Footer />
    </div>
  );
}
