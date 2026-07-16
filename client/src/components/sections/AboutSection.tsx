/**
 * AboutSection — Company story with image
 * Design: Coastal Breeze — warm, professional, asymmetric layout
 */
import { CheckCircle2 } from "lucide-react";
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

const ABOUT_IMG = "/images/site/about.jpg";

const highlights = [
  { text: "Apartments, houses, and condos", es: "Apartamentos, casas y condominios" },
  { text: "Office spaces and commercial buildings", es: "Oficinas y edificios comerciales" },
  { text: "Large facilities and multi-family properties", es: "Instalaciones grandes y propiedades multifamiliares" },
  { text: "Construction and move-out cleanings", es: "Limpiezas de construcción y de mudanza" },
  { text: "Scheduled cleanings for real estate showings", es: "Limpiezas programadas para muestras de bienes raíces" },
];

export default function AboutSection() {
  const { t } = useLanguage();
  return (
    <section id="about" className="py-16 md:py-24 bg-[oklch(0.955_0.025_237)]">
      <div className="container">
        <div className="grid lg:grid-cols-2 gap-10 lg:gap-16 items-center">
          {/* Image */}
          <AnimatedSection>
            <div className="relative">
              <div className="rounded-2xl overflow-hidden shadow-xl">
                <img
                  src={ABOUT_IMG}
                  alt={t("A kitchen left spotless after a Whistle Clean make-ready", "Una cocina impecable después de una limpieza de Whistle Clean")}
                  className="w-full h-[320px] sm:h-[400px] lg:h-[480px] object-cover"
                  loading="lazy"
                />
              </div>
              {/* Floating badge */}
              <div className="absolute -bottom-5 -right-3 sm:right-6 bg-white rounded-xl shadow-lg p-4 border border-slate-100">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-gradient-to-br from-amber-400 to-amber-500 flex items-center justify-center">
                    <span className="font-display font-bold text-white text-lg">20+</span>
                  </div>
                  <div>
                    <p className="font-display font-bold text-[oklch(0.208_0.042_265.75)] text-sm">{t("Years in Business", "Años de experiencia")}</p>
                    <p className="text-xs text-slate-500">{t("Serving San Antonio", "Sirviendo a San Antonio")}</p>
                  </div>
                </div>
              </div>
            </div>
          </AnimatedSection>

          {/* Text */}
          <AnimatedSection delay={0.15}>
            <div>
              <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("About Us", "Quiénes somos")}</span>
              <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-5 leading-tight">
                {t("A Trusted San Antonio Cleaning Company", "Una empresa de limpieza de confianza en San Antonio")}
              </h2>
              <p className="text-slate-600 text-base sm:text-lg leading-relaxed mb-5">
                {t(
                  "Whistle Clean has proudly served San Antonio and surrounding areas for the last 20 years. We provide professional cleaning services that leave spaces looking clean, smelling fresh, and feeling renewed.",
                  "Whistle Clean ha tenido el orgullo de servir a San Antonio y sus alrededores durante los últimos 20 años. Ofrecemos servicios de limpieza profesionales que dejan sus espacios limpios, con un aroma fresco y una sensación de renovación.",
                )}
              </p>
              <p className="text-slate-600 text-base sm:text-lg leading-relaxed mb-6">
                {t(
                  "Our team is made up of experienced employees who take pride in doing the job right and making sure every space is truly Whistle Clean. We've worked with multi-family properties, commercial clients, large facilities, and real estate agents throughout the San Antonio area.",
                  "Nuestro equipo está formado por empleados con experiencia que se enorgullecen de hacer bien su trabajo y de asegurarse de que cada espacio quede verdaderamente Whistle Clean. Hemos trabajado con propiedades multifamiliares, clientes comerciales, instalaciones grandes y agentes de bienes raíces en toda el área de San Antonio.",
                )}
              </p>

              {/* Highlights */}
              <div className="space-y-2.5 mb-8">
                {highlights.map((item) => (
                  <div key={item.text} className="flex items-start gap-2.5">
                    <CheckCircle2 className="w-5 h-5 text-sky-500 mt-0.5 shrink-0" />
                    <span className="text-slate-700 font-medium text-sm sm:text-base">{t(item.text, item.es)}</span>
                  </div>
                ))}
              </div>

              {/* Quote */}
              <div className="bg-white rounded-xl p-5 border-l-4 border-amber-400 shadow-sm">
                <p className="font-display font-semibold text-[oklch(0.208_0.042_265.75)] text-lg italic">
                  {t(
                    "\"We don't just clean your space — we help it feel brand new.\"",
                    "«No solo limpiamos su espacio: hacemos que se sienta como nuevo.»",
                  )}
                </p>
              </div>
            </div>
          </AnimatedSection>
        </div>
      </div>
    </section>
  );
}
