/**
 * Home page — Whistle Clean professional cleaning website
 * Design: Coastal Breeze / Organic Freshness
 * Sections: Hero, Trust Badges, About, Services, Clients, Testimonials, CTA, Gallery, FAQ, Contact, Footer
 */
import { Suspense, lazy } from "react";
import Navbar from "@/components/Navbar";
import HeroSection from "@/components/sections/HeroSection";
import TrustBadges from "@/components/sections/TrustBadges";

const AboutSection = lazy(() => import("@/components/sections/AboutSection"));
const ServicesSection = lazy(() => import("@/components/sections/ServicesSection"));
const ClientsSection = lazy(() => import("@/components/sections/ClientsSection"));
const TestimonialsSection = lazy(() => import("@/components/sections/TestimonialsSection"));
const CTASection = lazy(() => import("@/components/sections/CTASection"));
const GallerySection = lazy(() => import("@/components/sections/GallerySection"));
const FAQSection = lazy(() => import("@/components/sections/FAQSection"));
const ContactSection = lazy(() => import("@/components/sections/ContactSection"));
const Footer = lazy(() => import("@/components/Footer"));
const WaveDivider = lazy(() => import("@/components/WaveDivider"));

const SectionFallback = () => <div className="h-32 bg-transparent w-full" />;

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <HeroSection />
        <TrustBadges />
        <Suspense fallback={<SectionFallback />}>
          <div className="-mt-1"><WaveDivider position="top" color="oklch(0.955 0.025 237)" /></div>
          <AboutSection />
          <div className="-mb-1"><WaveDivider position="bottom" color="oklch(0.955 0.025 237)" /></div>
          <ServicesSection />
          <div className="-mt-1"><WaveDivider position="top" color="oklch(0.955 0.025 237)" /></div>
          <ClientsSection />
          <div className="-mb-1"><WaveDivider position="bottom" color="oklch(0.955 0.025 237)" /></div>
          <TestimonialsSection />
          <CTASection />
          <GallerySection />
          <FAQSection />
          <div className="-mt-1"><WaveDivider position="top" color="oklch(0.955 0.025 237)" /></div>
          <ContactSection />
          <div className="-mb-1"><WaveDivider position="bottom" color="oklch(0.955 0.025 237)" /></div>
        </Suspense>
      </main>
      <Suspense fallback={<SectionFallback />}>
        <Footer />
      </Suspense>
    </div>
  );
}
