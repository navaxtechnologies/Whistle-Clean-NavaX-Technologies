/**
 * GallerySection — Before/After gallery placeholder
 * Design: Coastal Breeze — placeholder grid for future images
 */
import { Camera } from "lucide-react";
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

// NOTE: replace `image` paths with real before/after job photos as they're captured.
const galleryItems = [
  { label: "Driveway Pressure Wash — Stone Oak", labelEs: "Lavado a Presión de Entrada — Stone Oak", category: "Pressure Washing", categoryEs: "Lavado a Presión", image: "/images/gallery/driveway-pressure-wash.png" },
  { label: "Roof Soft Wash — Alamo Heights", labelEs: "Lavado Suave de Techo — Alamo Heights", category: "Soft Washing", categoryEs: "Lavado Suave", image: "/images/gallery/roof-soft-wash.png" },
  { label: "Window Cleaning — Downtown Storefront", labelEs: "Limpieza de Ventanas — Local en Downtown", category: "Window Cleaning", categoryEs: "Limpieza de Ventanas", image: "/images/gallery/window-cleaning.png" },
  { label: "Gutter Clear-Out — Helotes", labelEs: "Limpieza de Canaletas — Helotes", category: "Gutter Cleaning", categoryEs: "Limpieza de Canaletas", image: "/images/gallery/gutter-cleaning.png" },
  { label: "Solar Panel Restoration — Boerne", labelEs: "Restauración de Paneles Solares — Boerne", category: "Solar Panels", categoryEs: "Paneles Solares", image: "/images/gallery/solar-panel-clean.png" },
  { label: "Deck Restoration — Stone Oak", labelEs: "Restauración de Terraza — Stone Oak", category: "Deck Restoration", categoryEs: "Restauración de Terrazas", image: "/images/gallery/deck-restoration.png" },
];

export default function GallerySection() {
  const { t } = useLanguage();
  return (
    <section id="work" className="py-16 md:py-24 bg-[oklch(0.955_0.025_237)]">
      <div className="container">
        <AnimatedSection>
          <div className="text-center mb-12">
            <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Our Work", "Nuestro Trabajo")}</span>
            <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
              {t("Before & After Gallery", "Galería de Antes y Después")}
            </h2>
            <p className="text-slate-500 text-lg max-w-2xl mx-auto">
              {t(
                "See the Whistle Clean difference. Real results from real jobs across San Antonio.",
                "Vea la diferencia de Whistle Clean. Resultados reales de trabajos reales en todo San Antonio."
              )}
            </p>
          </div>
        </AnimatedSection>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
          {galleryItems.map((item, i) => (
            <AnimatedSection key={i} delay={i * 0.06}>
              <div className="group relative bg-white rounded-2xl border border-slate-100 overflow-hidden aspect-[4/3] shadow-sm hover:shadow-xl transition-all duration-500 hover:-translate-y-2">
                <img
                  src={item.image}
                  alt={t(item.label, item.labelEs)}
                  className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110"
                  loading="lazy"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-navy-900/80 via-navy-900/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex flex-col justify-end p-6">
                  <span className="text-xs font-bold text-sky-300 uppercase tracking-widest mb-1">{t(item.category, item.categoryEs)}</span>
                  <h4 className="text-white font-display font-semibold text-lg">{t(item.label, item.labelEs)}</h4>
                </div>
              </div>
            </AnimatedSection>
          ))}
        </div>
      </div>
    </section>
  );
}
