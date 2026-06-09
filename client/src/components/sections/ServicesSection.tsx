/**
 * ServicesSection — Service cards with icons
 * Design: Coastal Breeze — clean cards, hover lift, staggered grid
 * Content: Whistle Clean's real EXTERIOR cleaning services
 */
import {
  AppWindow, Droplets, Waves, SprayCan, Hammer, Sun, CloudRain, Paintbrush
} from "lucide-react";
import { Link } from "wouter";
import AnimatedSection from "@/components/AnimatedSection";
import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";

const services = [
  {
    icon: AppWindow,
    title: "Window Cleaning",
    titleEs: "Limpieza de Ventanas",
    desc: "Streak-free interior and exterior window cleaning for homes and businesses. Screens, tracks, and sills included.",
    descEs: "Limpieza de ventanas interiores y exteriores sin rayas para casas y negocios. Incluye mallas, rieles y marcos.",
    best: "Homeowners, real estate, storefronts",
    bestEs: "Propietarios de casa, bienes raíces, locales comerciales",
  },
  {
    icon: Droplets,
    title: "Pressure Washing",
    titleEs: "Lavado a Presión",
    desc: "High-pressure cleaning for driveways, sidewalks, patios, and concrete. Blast away years of dirt, oil, and grime.",
    descEs: "Limpieza de alta presión para entradas de autos, banquetas, patios y concreto. Eliminamos años de tierra, aceite y mugre.",
    best: "Driveways, patios, walkways, fences",
    bestEs: "Entradas de autos, patios, andadores, cercas",
  },
  {
    icon: Waves,
    title: "Soft Washing",
    titleEs: "Lavado Suave",
    desc: "Low-pressure, detergent-based cleaning that safely removes algae and buildup from roofs, siding, and delicate surfaces.",
    descEs: "Limpieza de baja presión a base de detergente que elimina de forma segura el alga y la acumulación de techos, paredes exteriores y superficies delicadas.",
    best: "Roofs, siding, stucco, painted surfaces",
    bestEs: "Techos, paredes exteriores, estuco, superficies pintadas",
  },
  {
    icon: SprayCan,
    title: "Mold & Mildew Removal",
    titleEs: "Eliminación de Moho y Hongos",
    desc: "Targeted treatment that kills and removes mold, mildew, and algae — and helps keep it from coming back.",
    descEs: "Tratamiento específico que elimina el moho, los hongos y el alga, y ayuda a evitar que vuelvan a aparecer.",
    best: "North-facing walls, shaded exteriors, fences",
    bestEs: "Paredes orientadas al norte, exteriores con sombra, cercas",
  },
  {
    icon: Hammer,
    title: "Deck Restoration",
    titleEs: "Restauración de Terrazas",
    desc: "Clean, strip, and restore wood and composite decks so they look new and last longer against the Texas sun.",
    descEs: "Limpiamos, decapamos y restauramos terrazas de madera y material compuesto para que luzcan como nuevas y duren más bajo el sol de Texas.",
    best: "Wood decks, pergolas, outdoor living spaces",
    bestEs: "Terrazas de madera, pérgolas, espacios al aire libre",
  },
  {
    icon: Sun,
    title: "Solar Panel Cleaning",
    titleEs: "Limpieza de Paneles Solares",
    desc: "Safe, residue-free cleaning that restores panel efficiency. Dirty panels lose output — we get it back.",
    descEs: "Limpieza segura y sin residuos que restaura la eficiencia de los paneles. Los paneles sucios pierden producción; nosotros la recuperamos.",
    best: "Homeowners with rooftop solar",
    bestEs: "Propietarios con paneles solares en el techo",
  },
  {
    icon: CloudRain,
    title: "Gutter Cleaning",
    titleEs: "Limpieza de Canaletas",
    desc: "Full gutter clear-out and flush to prevent overflow, water damage, and foundation issues during SA storms.",
    descEs: "Limpieza y enjuague completo de canaletas para evitar desbordamientos, daños por agua y problemas en los cimientos durante las tormentas de San Antonio.",
    best: "Every home, especially before storm season",
    bestEs: "Toda casa, en especial antes de la temporada de tormentas",
  },
  {
    icon: Paintbrush,
    title: "Painting & Staining",
    titleEs: "Pintura y Tinte",
    desc: "Exterior painting and deck/fence staining to protect and refresh your property's surfaces and curb appeal.",
    descEs: "Pintura exterior y tinte de terrazas y cercas para proteger y renovar las superficies de su propiedad y mejorar su apariencia.",
    best: "Fences, decks, trim, exterior surfaces",
    bestEs: "Cercas, terrazas, molduras, superficies exteriores",
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
              {t("Exterior Cleaning for Every Surface", "Limpieza de Exteriores para Cada Superficie")}
            </h2>
            <p className="text-slate-500 text-lg max-w-2xl mx-auto">
              {t("Windows, pressure washing, soft washing, gutters, solar panels and more — spotless results, backed by 20 years and a perfect 5-star record.", "Ventanas, lavado a presión, lavado suave, canaletas, paneles solares y más: resultados impecables, respaldados por 20 años y un historial perfecto de 5 estrellas.")}
            </p>
          </div>
        </AnimatedSection>

        {/* Featured: Monthly Maintenance Plan */}
        <AnimatedSection>
          <div className="mb-10 rounded-2xl overflow-hidden bg-gradient-to-br from-[oklch(0.208_0.042_265.75)] to-sky-700 shadow-sm hover:shadow-lg transition-shadow duration-300">
            <div className="p-6 md:p-10 flex flex-col md:flex-row md:items-center md:justify-between gap-6">
              <div className="max-w-2xl">
                <span className="text-sm font-semibold text-amber-300 uppercase tracking-wider mb-2 block">{t("Most Popular", "Más Popular")}</span>
                <h3 className="font-display font-bold text-2xl text-white mb-3">{t("Monthly Maintenance Plan", "Plan de Mantenimiento Mensual")}</h3>
                <p className="text-sky-100 leading-relaxed">
                  {t("Window + pressure wash combo on a recurring schedule, from ", "Combo de ventanas + lavado a presión en un calendario recurrente, desde ")}<span className="font-semibold text-white">$199–$349/month</span>{t(" based on property size. Keep your home spotless year-round and never think about it again.", " según el tamaño de la propiedad. Mantenga su casa impecable todo el año sin tener que volver a pensar en ello.")}
                </p>
              </div>
              <div className="flex flex-col sm:flex-row md:flex-col gap-3 shrink-0">
                <Link href="/pricing">
                  <Button className="w-full bg-white text-sky-700 hover:bg-sky-50 font-semibold shadow-md">{t("See Plans & Pricing", "Ver Planes y Precios")}</Button>
                </Link>
                <Link href="/book">
                  <Button className="w-full bg-amber-400 text-slate-900 hover:bg-amber-300 font-semibold shadow-md">{t("Book Now", "Reservar")}</Button>
                </Link>
              </div>
            </div>
          </div>
        </AnimatedSection>

        {/* Service cards grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-5">
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
