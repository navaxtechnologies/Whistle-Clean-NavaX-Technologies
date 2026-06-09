/** Services page — dedicated route wrapping the services + trust sections. */
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import ServicesSection from "@/components/sections/ServicesSection";
import TrustBadges from "@/components/sections/TrustBadges";
import { useDocumentMeta } from "@/lib/seo";

export default function Services() {
  useDocumentMeta({
    title: "Services | Window Cleaning, Pressure Washing & More | Whistle Clean San Antonio",
    description:
      "Whistle Clean's exterior services in San Antonio: window cleaning, pressure washing, soft washing, mold & mildew removal, deck restoration, solar panel cleaning, gutters, painting & staining.",
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
