/**
 * Pricing page — Whistle Clean's real apartment-cleaning price list (per the
 * company proposal), office & laundry room custom quote, and a recurring /
 * commercial CTA. Materials and labor are included.
 */
import { Check, Building2, Briefcase, Phone, Repeat } from "lucide-react";
import { Link } from "wouter";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Button } from "@/components/ui/button";
import AnimatedSection from "@/components/AnimatedSection";
import { useDocumentMeta } from "@/lib/seo";
import { useLanguage } from "@/contexts/LanguageContext";

const apartmentPrices = [
  { label: "Full Cleaning — Efficiency", labelEs: "Limpieza Completa — Eficiencia", price: "$95" },
  { label: "Full Cleaning — 1×1 Apartment", labelEs: "Limpieza Completa — Apartamento 1×1", price: "$115" },
  { label: "Full Cleaning — 2×2 Apartment", labelEs: "Limpieza Completa — Apartamento 2×2", price: "$125" },
  { label: "Full Cleaning — 3×2 Apartment", labelEs: "Limpieza Completa — Apartamento 3×2", price: "$135" },
  { label: "Touch-Up Cleaning", labelEs: "Limpieza de Retoque", price: "$60" },
  { label: "Heavy / Deep Cleaning (add-on)", labelEs: "Limpieza Pesada / Profunda (adicional)", price: "$40" },
];

export default function Pricing() {
  const { t } = useLanguage();
  useDocumentMeta({
    title: "Pricing | Apartment & Office Cleaning | Whistle Clean San Antonio",
    description:
      "Whistle Clean San Antonio pricing: apartment cleaning from $95 (efficiency, 1×1, 2×2, 3×2), touch-up and deep cleaning, plus custom quotes for offices & laundry rooms. Materials and labor included.",
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
                    "Flat-rate apartment cleaning, with custom quotes for offices and laundry rooms. Materials and labor are always included.",
                    "Limpieza de apartamentos a precio fijo, con cotizaciones personalizadas para oficinas y cuartos de lavado. Los materiales y la mano de obra siempre están incluidos."
                  )}
                </p>
              </div>
            </AnimatedSection>

            {/* Apartment cleaning price list */}
            <AnimatedSection>
              <div className="max-w-3xl mx-auto mb-12">
                <div className="flex items-center gap-2 mb-5">
                  <Building2 className="w-6 h-6 text-sky-600" />
                  <h2 className="font-display font-bold text-2xl text-[oklch(0.208_0.042_265.75)]">{t("Apartment Cleaning", "Limpieza de Apartamentos")}</h2>
                </div>
                <div className="bg-white rounded-2xl border border-slate-100 shadow-sm divide-y divide-slate-100 overflow-hidden">
                  {apartmentPrices.map((row) => (
                    <div key={row.label} className="flex items-center justify-between px-5 md:px-6 py-4">
                      <span className="text-slate-700 font-medium text-sm md:text-base">{t(row.label, row.labelEs)}</span>
                      <span className="font-display font-bold text-lg text-sky-600">{row.price}</span>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-slate-400 mt-3">
                  {t(
                    "Flat rates for standard units. Heavily soiled or neglected units may require the Heavy / Deep Cleaning add-on. Materials and labor included.",
                    "Tarifas fijas para unidades estándar. Las unidades muy sucias o descuidadas pueden requerir el adicional de Limpieza Pesada / Profunda. Materiales y mano de obra incluidos."
                  )}
                </p>
                <div className="mt-6 text-center">
                  <Link href="/book">
                    <Button className="bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-600 hover:to-sky-700 text-white font-semibold shadow-md">{t("Book a Cleaning", "Reservar una Limpieza")}</Button>
                  </Link>
                </div>
              </div>
            </AnimatedSection>

            {/* Office & Laundry — custom quote */}
            <AnimatedSection>
              <div className="max-w-3xl mx-auto mb-12">
                <div className="bg-[oklch(0.955_0.025_237)] border border-sky-100 rounded-2xl p-6 md:p-8">
                  <div className="flex items-center gap-2 mb-3">
                    <Briefcase className="w-6 h-6 text-sky-600" />
                    <h2 className="font-display font-bold text-2xl text-[oklch(0.208_0.042_265.75)]">{t("Office & Laundry Room Cleaning", "Limpieza de Oficinas y Cuartos de Lavado")}</h2>
                  </div>
                  <p className="text-slate-600 mb-5">
                    {t(
                      "Pricing depends on the size of the area, so we send an expert to assess your space and give you a customized quote — no obligation.",
                      "El precio depende del tamaño del área, así que enviamos a un experto a evaluar su espacio y darle una cotización personalizada — sin compromiso."
                    )}
                  </p>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <a href="tel:+12108594422">
                      <Button className="bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-600 hover:to-sky-700 text-white font-semibold shadow-md">
                        <Phone className="w-4 h-4 mr-2" /> {t("Call (210) 859-4422", "Llame al (210) 859-4422")}
                      </Button>
                    </a>
                    <Link href="/contact">
                      <Button variant="outline" className="border-sky-300 text-sky-700 font-semibold">{t("Request a Free Quote", "Solicitar Cotización Gratis")}</Button>
                    </Link>
                  </div>
                </div>
              </div>
            </AnimatedSection>

            {/* Recurring / commercial */}
            <AnimatedSection>
              <div className="max-w-4xl mx-auto rounded-2xl bg-gradient-to-br from-[oklch(0.208_0.042_265.75)] to-sky-700 p-8 md:p-10 text-center text-white">
                <Repeat className="w-10 h-10 text-amber-300 mx-auto mb-3" />
                <h2 className="font-display font-bold text-2xl mb-3">{t("Recurring & Property-Manager Plans", "Planes Recurrentes y para Administradores")}</h2>
                <p className="text-sky-100 max-w-2xl mx-auto mb-6">
                  {t(
                    "Cleaning the same units every week, biweekly, or month? Apartment complexes and property managers get locked-in member pricing and priority scheduling. Ask about a recurring account.",
                    "¿Limpieza de las mismas unidades cada semana, quincena o mes? Los complejos de apartamentos y administradores reciben precio de miembro garantizado y programación prioritaria. Pregunte por una cuenta recurrente."
                  )}
                </p>
                <div className="flex flex-col sm:flex-row gap-3 justify-center">
                  <Link href="/contact">
                    <Button className="bg-amber-400 text-slate-900 hover:bg-amber-300 font-semibold shadow-md">{t("Set Up a Recurring Plan", "Crear un Plan Recurrente")}</Button>
                  </Link>
                  <Link href="/book">
                    <Button className="bg-white text-sky-700 hover:bg-sky-50 font-semibold shadow-md">{t("Book Now", "Reservar")}</Button>
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
