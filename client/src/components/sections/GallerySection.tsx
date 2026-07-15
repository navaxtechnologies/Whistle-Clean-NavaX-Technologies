/**
 * GallerySection — Before/After gallery
 * Design: Coastal Breeze — real job photos, before beside after.
 * Photos follow the `job#-room-before|after.jpg` convention in
 * /public/images/gallery. Add new jobs by appending to galleryItems.
 */
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

type GalleryItem = {
  before?: string;
  after: string;
  label: string;
  labelEs: string;
  category: string;
  categoryEs: string;
};

const galleryItems: GalleryItem[] = [
  {
    before: "/images/gallery/job2-bathroom-before.jpg",
    after: "/images/gallery/job2-bathroom-after.jpg",
    label: "Move-Out Turnover — Bathroom",
    labelEs: "Limpieza de Mudanza — Baño",
    category: "Move-Out Cleaning",
    categoryEs: "Limpieza de Mudanza",
  },
  {
    before: "/images/gallery/job1-tub-before.jpg",
    after: "/images/gallery/job1-bathroom-after.jpg",
    label: "Deep Clean — Tub & Shower",
    labelEs: "Limpieza Profunda — Bañera y Ducha",
    category: "Heavy / Deep Cleaning",
    categoryEs: "Limpieza Pesada / Profunda",
  },
  {
    before: "/images/gallery/job1-kitchen-before.jpg",
    after: "/images/gallery/job1-kitchen-after.jpg",
    label: "Deep Clean — Kitchen & Appliances",
    labelEs: "Limpieza Profunda — Cocina y Electrodomésticos",
    category: "Apartment Cleaning",
    categoryEs: "Limpieza de Apartamentos",
  },
  {
    before: "/images/gallery/job1-toilet-before.jpg",
    after: "/images/gallery/job1-bathroom-after.jpg",
    label: "Deep Clean — Toilet & Vanity",
    labelEs: "Limpieza Profunda — Inodoro y Lavabo",
    category: "Heavy / Deep Cleaning",
    categoryEs: "Limpieza Pesada / Profunda",
  },
  {
    before: "/images/gallery/job1-floor-before.jpg",
    after: "/images/gallery/job1-living-room-after.jpg",
    label: "Move-Out Turnover — Living Room & Floors",
    labelEs: "Limpieza de Mudanza — Sala y Pisos",
    category: "Move-Out Cleaning",
    categoryEs: "Limpieza de Mudanza",
  },
  {
    after: "/images/gallery/job2-kitchen-after.jpg",
    label: "Make-Ready — Kitchen",
    labelEs: "Lista para Entregar — Cocina",
    category: "Apartment Cleaning",
    categoryEs: "Limpieza de Apartamentos",
  },
];

function Badge({ children, tone }: { children: string; tone: "before" | "after" }) {
  const styles =
    tone === "before"
      ? "bg-slate-900/75 text-white"
      : "bg-sky-500/90 text-white";
  return (
    <span
      className={`absolute top-2 left-2 z-10 rounded-full px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest ${styles}`}
    >
      {children}
    </span>
  );
}

export default function GallerySection() {
  const { t } = useLanguage();
  return (
    <section id="work" className="py-16 md:py-24 bg-[oklch(0.955_0.025_237)]">
      <div className="container">
        <AnimatedSection>
          <div className="text-center mb-12">
            <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">
              {t("Our Work", "Nuestro Trabajo")}
            </span>
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

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
          {galleryItems.map((item, i) => (
            <AnimatedSection key={i} delay={i * 0.06}>
              <div className="group bg-white rounded-2xl border border-slate-100 overflow-hidden shadow-sm hover:shadow-xl transition-all duration-500 hover:-translate-y-2 h-full flex flex-col">
                <div className={item.before ? "grid grid-cols-2 gap-px bg-slate-200" : ""}>
                  {item.before && (
                    <div className="relative aspect-[3/4] overflow-hidden bg-slate-100">
                      <Badge tone="before">{t("Before", "Antes")}</Badge>
                      <img
                        src={item.before}
                        alt={t(
                          `${item.label} — before cleaning`,
                          `${item.labelEs} — antes de la limpieza`
                        )}
                        className="w-full h-full object-cover"
                        loading="lazy"
                      />
                    </div>
                  )}
                  <div
                    className={`relative overflow-hidden bg-slate-100 ${
                      item.before ? "aspect-[3/4]" : "aspect-[4/3]"
                    }`}
                  >
                    <Badge tone="after">{t("After", "Después")}</Badge>
                    <img
                      src={item.after}
                      alt={t(
                        `${item.label} — after cleaning`,
                        `${item.labelEs} — después de la limpieza`
                      )}
                      className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
                      loading="lazy"
                    />
                  </div>
                </div>

                <div className="p-5 flex-1">
                  <span className="block text-[11px] font-bold text-sky-600 uppercase tracking-widest mb-1">
                    {t(item.category, item.categoryEs)}
                  </span>
                  <h4 className="text-[oklch(0.208_0.042_265.75)] font-display font-semibold text-base leading-snug">
                    {t(item.label, item.labelEs)}
                  </h4>
                </div>
              </div>
            </AnimatedSection>
          ))}
        </div>
      </div>
    </section>
  );
}
