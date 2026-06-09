/** Contact page — dedicated route wrapping the contact form + business info. */
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import ContactSection from "@/components/sections/ContactSection";
import { useDocumentMeta } from "@/lib/seo";

export default function Contact() {
  useDocumentMeta({
    title: "Contact | Whistle Clean San Antonio",
    description:
      "Contact Whistle Clean San Antonio for a free exterior cleaning quote. Call (210) 859-4422 or send a message. Serving San Antonio & surrounding areas. Se habla español.",
    path: "/contact",
  });
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <ContactSection />
      </main>
      <Footer />
    </div>
  );
}
