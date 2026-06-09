/**
 * ServicesSection — Service cards with icons
 * Design: Coastal Breeze — clean cards, hover lift, staggered grid
 * Content: Whistle Clean's real INTERIOR cleaning services (per company proposal)
 */
import {
  Building2, Briefcase, Shirt, Sparkles, SprayCan, Truck
} from "lucide-react";
import { Link } from "wouter";
import AnimatedSection from "@/components/AnimatedSection";
import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";

const services = [
  {
    icon: Building2,
    title: "Apartment Cleaning",
    titleEs: "Limpieza de Apartamentos",
    desc: "Full top-to-bottom cleaning for efficiencies and 1×1, 2×2, and 3×2 units. Move-in ready every time.",
    descEs: "Limpieza completa de arriba a abajo para eficiencias y apartamentos de 1×1, 2×2 y 3×2. Listos para mudarse, siempre.",
    best: "Renters, tenants, property managers",
    bestEs: "Inquilinos, residentes, administradores de propiedades",
  },
  {
    icon: Briefcase,
    title: "Office Cleaning",
    titleEs: "Limpieza de Oficinas",
    desc: "Professional office cleaning priced by the size of your space — we assess and give you a custom quote.",
    descEs: "Limpieza profesional de oficinas con precio según el tamaño de su espacio — evaluamos y le damos una cotización personalizada.",
    best: "Small businesses and offices",
    bestEs: "Pequeños negocios y oficinas",
  },
  {
    icon: Shirt,
    title: "Laundry Room Cleaning",
    titleEs: "Limpieza de Cuartos de Lavado",
    desc: "Deep cleaning for shared and commercial laundry rooms — sanitized, organized, and spotless.",
    descEs: "Limpieza profunda de cuartos de lavado compartidos y comerciales — desinfectados, organizados e impecables.",
    best: "Apartment complexes, property managers",
    bestEs: "Complejos de apartamentos, administradores de propiedades",
  },
  {
    icon: Sparkles,
    title: "Touch-Up Cleaning",
    titleEs: "Limpieza de Retoque",
    desc: "A quick refresh between deep cleans to keep your space looking and feeling spotless.",
    descEs: "Un repaso rápido entre limpiezas profundas para mantener su espacio impecable.",
    best: "Regular upkeep between visits",
    bestEs: "Mantenimiento regular entre visitas",
  },
  {
    icon: SprayCan,
    title: "Heavy / Deep Cleaning",
    titleEs: "Limpieza Pesada / Profunda",
    desc: "Detailed, heavy-duty cleaning for heavily soiled or neglected units — we get it back to spotless.",
    descEs: "Limpieza detallada y a fondo para unidades muy sucias o descuidadas — las dejamos impecables de nuevo.",
    best: "Turnovers, deep resets",
    bestEs: "Cambios de inquilino, limpiezas a fondo",
  },
  {
    icon: Truck,
    title: "Move-Out Cleaning",
    titleEs: "Limpieza de Mudanza",
    desc: "Full move-out and turnover cleaning to get units rent-ready and help tenants get their deposit back.",
    descEs: "Limpieza completa de mudanza y cambio de inquilino para dejar las unidades listas para rentar y ayudar a recuperar el depósito.",
    best: "Tenants, landlords, property managers",
    bestEs: "Inquilinos, propietarios, administradores de propiedades",
  },
];

export default function ServicesSection() {
  const { t } = useLanguage();
  return (
    <section id="services" className="py-16 md:py-24 bg-background">
      <div className="container">
        <AnimatedSection>
          <div className="text-center mb-14">
            <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Our Services", "Nuestros Servicios")}</span>
            <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
              {t("Cleaning for Every Space", "Limpieza para Cada Espacio")}
            </h2>
            <p className="text-slate-500 text-lg max-w-2xl mx-auto">
              {t("Apartments, offices, and laundry rooms — thorough, reliable cleaning backed by 20 years and a perfect 5-star record. Materials and labor included.", "Apartamentos, oficinas y cuartos de lavado — limpieza minuciosa y confiable, respaldada por 20 años y un historial perfecto de 5 estrellas. Materiales y mano de obra incluidos.")}
            </p>
          </div>
        </AnimatedSection>

        {/* Featured: Recurring Cleaning Plan */}
        <AnimatedSection>
          <div className="mb-10 rounded-2xl overflow-hidden bg-gradient-to-br from-[oklch(0.208_0.042_265.75)] to-sky-700 shadow-sm hover:shadow-lg transition-shadow duration-300">
            <div className="p-6 md:p-10 flex flex-col md:flex-row md:items-center md:justify-between gap-6">
              <div className="max-w-2xl">
                <span className="text-sm font-semibold text-amber-300 uppercase tracking-wider mb-2 block">{t("Most Popular", "Más Popular")}</span>
                <h3 className="font-display font-bold text-2xl text-white mb-3">{t("Recurring Cleaning Plan", "Plan de Limpieza Recurrente")}</h3>
                <p className="text-sky-100 leading-relaxed">
                  {t("Weekly, biweekly, or monthly cleaning kept on a schedule — locked-in member pricing and first priority on the calendar. Set it and forget it.", "Limpieza semanal, quincenal o mensual en un calendario fijo — precio de miembro garantizado y prioridad en el calendario. Configúrelo y olvídese.")}
                </p>
              </div>
              <div className="flex flex-col sm:flex-row md:flex-col gap-3 shrink-0">
                <Link href="/pricing">
                  <Button className="w-full bg-white text-sky-700 hover:bg-sky-50 font-semibold shadow-md">{t("See Pricing", "Ver Precios")}</Button>
                </Link>
                <Link href="/book">
                  <Button className="w-full bg-amber-400 text-slate-900 hover:bg-amber-300 font-semibold shadow-md">{t("Book Now", "Reservar")}</Button>
                </Link>
              </div>
            </div>
          </div>
        </AnimatedSection>

        {/* Service cards grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-5">
          {services.map((service, i) => (
            <AnimatedSection key={service.title} delay={i * 0.06}>
              <div className="group bg-white rounded-xl border border-slate-100 p-5 md:p-6 hover:shadow-lg hover:border-sky-200 transition-all duration-300 hover:-translate-y-1 h-full flex flex-col">
                <div className="w-11 h-11 rounded-lg bg-gradient-to-br from-sky-50 to-sky-100 flex items-center justify-center mb-4 group-hover:from-sky-100 group-hover:to-sky-200 transition-colors duration-300">
                  <service.icon className="w-5.5 h-5.5 text-sky-600" />
                </div>
                <h3 className="font-display font-semibold text-[oklch(0.208_0.042_265.75)] text-base mb-2">{t(service.title, service.titleEs)}</h3>
                <p className="text-sm text-slate-500 leading-relaxed mb-3 flex-1">{t(service.desc, service.descEs)}</p>
                <p className="text-xs text-slate-400">
                  <span className="font-semibold text-slate-500">{t("Best for:", "Ideal para:")}</span> {t(service.best, service.bestEs)}
                </p>
              </div>
            </AnimatedSection>
          ))}
        </div>
      </div>
    </section>
  );
}
