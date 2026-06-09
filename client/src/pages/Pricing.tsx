/**
 * Pricing page — service tiers, Monthly Maintenance Plan highlight, and a
 * commercial-quote CTA. Prices are starting estimates; final quotes confirmed
 * after a free assessment.
 */
import { Check, Star, Building2, Phone } from "lucide-react";
import { Link } from "wouter";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Button } from "@/components/ui/button";
import AnimatedSection from "@/components/AnimatedSection";
import { useDocumentMeta } from "@/lib/seo";
import { useLanguage } from "@/contexts/LanguageContext";

const tiers = [
  {
    name: "Standard",
    nameEs: "Estándar",
    blurb: "Single service, one-time visit.",
    blurbEs: "Un solo servicio, visita única.",
    price: "from $99",
    features: [
      "One exterior service of your choice",
      "Free quote & assessment",
      "Licensed & insured crew",
      "Satisfaction guaranteed",
    ],
    featuresEs: [
      "Un servicio exterior de su elección",
      "Cotización y evaluación gratuitas",
      "Equipo con licencia y asegurado",
      "Satisfacción garantizada",
    ],
    cta: "Book a Service",
    ctaEs: "Reservar un Servicio",
    highlighted: false,
  },
  {
    name: "Premium Bundle",
    nameEs: "Paquete Premium",
    blurb: "Multiple services, one visit, bundle savings.",
    blurbEs: "Varios servicios, una sola visita, ahorros por paquete.",
    price: "from $249",
    features: [
      "2+ services bundled (e.g. windows + pressure wash)",
      "Priority scheduling",
      "Before/after photos",
      "10% bundle discount",
      "Satisfaction guaranteed",
    ],
    featuresEs: [
      "2 o más servicios combinados (p. ej. ventanas + lavado a presión)",
      "Programación prioritaria",
      "Fotos de antes y después",
      "10% de descuento por paquete",
      "Satisfacción garantizada",
    ],
    cta: "Book a Bundle",
    ctaEs: "Reservar un Paquete",
    highlighted: false,
  },
  {
    name: "Monthly Maintenance",
    nameEs: "Mantenimiento Mensual",
    blurb: "Recurring care — set it and forget it.",
    blurbEs: "Cuidado recurrente — configúrelo y olvídese.",
    price: "$199–$349/mo",
    features: [
      "Window + pressure wash combo, recurring",
      "Scheduled by property size",
      "Locked-in member pricing",
      "First priority on the calendar",
      "Card on file — no chasing invoices",
    ],
    featuresEs: [
      "Combo de ventanas + lavado a presión, recurrente",
      "Programado según el tamaño de la propiedad",
      "Precio de miembro fijo garantizado",
      "Primera prioridad en el calendario",
      "Tarjeta registrada — sin perseguir facturas",
    ],
    cta: "Start a Plan",
    ctaEs: "Iniciar un Plan",
    highlighted: true,
  },
];

const serviceStarters = [
  { service: "Window Cleaning", serviceEs: "Limpieza de Ventanas", from: "$99+" },
  { service: "Pressure Washing", serviceEs: "Lavado a Presión", from: "$149+" },
  { service: "Soft Washing", serviceEs: "Lavado Suave", from: "$199+" },
  { service: "Mold & Mildew Removal", serviceEs: "Eliminación de Moho y Hongos", from: "$179+" },
  { service: "Gutter Cleaning", serviceEs: "Limpieza de Canaletas", from: "$129+" },
  { service: "Solar Panel Cleaning", serviceEs: "Limpieza de Paneles Solares", from: "$149+" },
  { service: "Deck Restoration", serviceEs: "Restauración de Terrazas", from: "Quote", fromEs: "Cotización" },
  { service: "Painting & Staining", serviceEs: "Pintura y Tinte", from: "Quote", fromEs: "Cotización" },
];

export default function Pricing() {
  const { t } = useLanguage();
  useDocumentMeta({
    title: "Pricing & Plans | Whistle Clean San Antonio",
    description:
      "Transparent exterior cleaning pricing in San Antonio. One-time services from $99, bundle savings, and a Monthly Maintenance Plan from $199–$349/mo. Free quotes.",
    path: "/pricing",
  });

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1">
        <section className="py-12 md:py-16 bg-background">
          <div className="container">
            <AnimatedSection>
              <div className="text-center mb-12">
                <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Pricing", "Precios")}</span>
                <h1 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
                  {t("Simple, Honest Pricing", "Precios Simples y Honestos")}
                </h1>
                <p className="text-slate-500 text-lg max-w-2xl mx-auto">
                  {t(
                    "Every job starts with a free quote. Prices below are starting estimates — your final price depends on property size and condition.",
                    "Cada trabajo comienza con una cotización gratuita. Los precios a continuación son estimaciones iniciales — su precio final depende del tamaño y la condición de la propiedad."
                  )}
                </p>
              </div>
            </AnimatedSection>

            {/* Tiers */}
            <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto mb-16">
              {tiers.map((tier, i) => (
                <AnimatedSection key={tier.name} delay={i * 0.08}>
                  <div
                    className={`relative h-full flex flex-col rounded-2xl border p-6 md:p-8 transition-all duration-300 ${
                      tier.highlighted
                        ? "border-sky-400 bg-gradient-to-br from-[oklch(0.208_0.042_265.75)] to-sky-700 text-white shadow-xl scale-[1.02]"
                        : "border-slate-100 bg-white shadow-sm hover:shadow-lg"
                    }`}
                  >
                    {tier.highlighted && (
                      <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-amber-400 text-slate-900 text-xs font-bold uppercase tracking-wider px-3 py-1 rounded-full flex items-center gap-1">
                        <Star className="w-3 h-3 fill-slate-900" /> {t("Most Popular", "Más Popular")}
                      </span>
                    )}
                    <h3 className={`font-display font-bold text-xl mb-1 ${tier.highlighted ? "text-white" : "text-[oklch(0.208_0.042_265.75)]"}`}>{t(tier.name, tier.nameEs)}</h3>
                    <p className={`text-sm mb-4 ${tier.highlighted ? "text-sky-100" : "text-slate-500"}`}>{t(tier.blurb, tier.blurbEs)}</p>
                    <div className={`font-display font-bold text-3xl mb-5 ${tier.highlighted ? "text-white" : "text-[oklch(0.208_0.042_265.75)]"}`}>{tier.price}</div>
                    <ul className="space-y-2.5 mb-6 flex-1">
                      {tier.features.map((f, fi) => (
                        <li key={f} className="flex items-start gap-2 text-sm">
                          <Check className={`w-4.5 h-4.5 shrink-0 mt-0.5 ${tier.highlighted ? "text-amber-300" : "text-sky-600"}`} />
                          <span className={tier.highlighted ? "text-sky-50" : "text-slate-600"}>{t(f, tier.featuresEs[fi])}</span>
                        </li>
                      ))}
                    </ul>
                    <Link href="/book">
                      <Button
                        className={`w-full font-semibold shadow-md ${
                          tier.highlighted
                            ? "bg-amber-400 text-slate-900 hover:bg-amber-300"
                            : "bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-600 hover:to-sky-700 text-white"
                        }`}
                      >
                        {t(tier.cta, tier.ctaEs)}
                      </Button>
                    </Link>
                  </div>
                </AnimatedSection>
              ))}
            </div>

            {/* Per-service starting prices */}
            <AnimatedSection>
              <div className="max-w-3xl mx-auto mb-16">
                <h2 className="font-display font-bold text-2xl text-[oklch(0.208_0.042_265.75)] text-center mb-6">{t("Starting Prices by Service", "Precios Iniciales por Servicio")}</h2>
                <div className="grid sm:grid-cols-2 gap-3">
                  {serviceStarters.map((s) => (
                    <div key={s.service} className="flex items-center justify-between bg-white border border-slate-100 rounded-xl px-5 py-3.5 shadow-sm">
                      <span className="text-slate-700 font-medium text-sm">{t(s.service, s.serviceEs)}</span>
                      <span className="text-sky-600 font-bold text-sm">{s.fromEs ? t(s.from, s.fromEs) : s.from}</span>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-slate-400 text-center mt-4">{t("Final pricing confirmed after a free, no-obligation assessment.", "El precio final se confirma después de una evaluación gratuita y sin compromiso.")}</p>
              </div>
            </AnimatedSection>

            {/* Commercial CTA */}
            <AnimatedSection>
              <div className="max-w-4xl mx-auto rounded-2xl bg-[oklch(0.955_0.025_237)] border border-sky-100 p-8 md:p-10 text-center">
                <Building2 className="w-10 h-10 text-sky-600 mx-auto mb-3" />
                <h2 className="font-display font-bold text-2xl text-[oklch(0.208_0.042_265.75)] mb-3">{t("Commercial, HOA & Property Management", "Comercial, Asociaciones de Propietarios y Administración de Propiedades")}</h2>
                <p className="text-slate-600 max-w-2xl mx-auto mb-6">
                  {t(
                    "Recurring exterior cleaning for apartment complexes, medical offices, storefronts, and HOAs across San Antonio. Custom contract pricing and a free first demo cleaning for new accounts.",
                    "Limpieza exterior recurrente para complejos de apartamentos, oficinas médicas, locales comerciales y asociaciones de propietarios en todo San Antonio. Precios de contrato personalizados y una primera limpieza de demostración gratuita para cuentas nuevas."
                  )}
                </p>
                <div className="flex flex-col sm:flex-row gap-3 justify-center">
                  <a href="tel:+12108594422">
                    <Button className="bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-600 hover:to-sky-700 text-white font-semibold shadow-md">
                      <Phone className="w-4 h-4 mr-2" /> {t("Call (210) 859-4422", "Llame al (210) 859-4422")}
                    </Button>
                  </a>
                  <Link href="/contact">
                    <Button variant="outline" className="border-sky-300 text-sky-700 font-semibold">{t("Request a Commercial Quote", "Solicitar Cotización Comercial")}</Button>
                  </Link>
                </div>
              </div>
            </AnimatedSection>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
