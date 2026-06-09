/** Gallery page — dedicated route wrapping the before/after gallery. */
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import GallerySection from "@/components/sections/GallerySection";
import { useDocumentMeta } from "@/lib/seo";

export default function Gallery() {
  useDocumentMeta({
    title: "Before & After Gallery | Whistle Clean San Antonio",
    description:
      "See real before/after results from Whistle Clean across San Antonio — pressure washing, soft washing, window cleaning, gutters, solar panels, and deck restoration.",
    path: "/gallery",
  });
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <GallerySection />
      </main>
      <Footer />
    </div>
  );
}
