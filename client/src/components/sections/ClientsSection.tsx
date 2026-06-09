/**
 * ClientsSection — Trusted by Multi-Family Properties and Commercial Clients
 * Design: Coastal Breeze — clean layout with real client names
 */
import { Building, Home, Briefcase, MapPin } from "lucide-react";
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

const COMMERCIAL_IMG = "/images/commercial-lobby.png";

const clients = [
  "Westland Real Estate Group",
  "Tarantino Properties Inc.",
  "Implicity Management Group",
  "Greystar Real Estate Partners",
];

const clientTypes = [
  { icon: Building, label: "Apartment Communities", es: "Comunidades de Apartamentos" },
  { icon: Home, label: "Real Estate Professionals", es: "Profesionales de Bienes Raíces" },
  { icon: Briefcase, label: "Office Buildings", es: "Edificios de Oficinas" },
  { icon: MapPin, label: "Large Commercial Spaces", es: "Espacios Comerciales Grandes" },
];

export default function ClientsSection() {
  const { t } = useLanguage();
  return (
    <section className="py-16 md:py-24 bg-[oklch(0.955_0.025_237)]">
      <div className="container">
        <div className="grid lg:grid-cols-2 gap-10 lg:gap-16 items-center">
          {/* Text */}
          <AnimatedSection>
            <div>
              <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Our Clients", "Nuestros Clientes")}</span>
              <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-5 leading-tight">
                {t("Trusted by Multi-Family Properties and Commercial Clients", "La confianza de propiedades multifamiliares y clientes comerciales")}
              </h2>
              <p className="text-slate-600 text-base sm:text-lg leading-relaxed mb-6">
                {t("Whistle Clean has experience serving apartment communities, real estate professionals, offices, and large commercial spaces throughout San Antonio and surrounding areas.", "Whistle Clean cuenta con experiencia atendiendo comunidades de apartamentos, profesionales de bienes raíces, oficinas y espacios comerciales grandes en todo San Antonio y las áreas cercanas.")}
              </p>

              {/* Client type badges */}
              <div className="grid grid-cols-2 gap-3 mb-8">
                {clientTypes.map((ct) => (
                  <div key={ct.label} className="flex items-center gap-2.5 bg-white rounded-lg px-4 py-3 border border-slate-100">
                    <ct.icon className="w-5 h-5 text-sky-500 shrink-0" />
                    <span className="text-sm font-medium text-slate-700">{t(ct.label, ct.es)}</span>
                  </div>
                ))}
              </div>

              {/* Client list */}
              <div className="bg-white rounded-xl p-5 border border-slate-100">
                <h4 className="font-display font-semibold text-[oklch(0.208_0.042_265.75)] text-sm mb-3 uppercase tracking-wider">{t("Properties We Serve", "Propiedades que Atendemos")}</h4>
                <div className="space-y-2">
                  {clients.map((name, i) => (
                    <div key={i} className="flex items-center gap-2.5 text-slate-600 text-sm font-medium">
                      <div className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                      {name}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </AnimatedSection>

          {/* Image */}
          <AnimatedSection delay={0.15}>
            <div className="rounded-2xl overflow-hidden shadow-xl">
              <img
                src={COMMERCIAL_IMG}
                alt={t("Spotless commercial building lobby", "Vestíbulo impecable de un edificio comercial")}
                className="w-full h-[320px] sm:h-[400px] lg:h-[480px] object-cover"
                loading="lazy"
              />
            </div>
          </AnimatedSection>
        </div>
      </div>
    </section>
  );
}
