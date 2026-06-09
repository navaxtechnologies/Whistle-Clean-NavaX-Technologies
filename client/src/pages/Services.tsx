/** Services page — dedicated route wrapping the services + trust sections. */
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import ServicesSection from "@/components/sections/ServicesSection";
import TrustBadges from "@/components/sections/TrustBadges";
import { useDocumentMeta } from "@/lib/seo";

export default function Services() {
  useDocumentMeta({
    title: "Services | Apartment, Office & Laundry Cleaning | Whistle Clean San Antonio",
    description:
      "Whistle Clean's cleaning services in San Antonio: apartment cleaning, office cleaning, laundry room cleaning, touch-up, heavy/deep cleaning, and move-out cleaning.",
    path: "/services",
  });
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <ServicesSection />
        <TrustBadges />
      </main>
      <Footer />
    </div>
  );
}
