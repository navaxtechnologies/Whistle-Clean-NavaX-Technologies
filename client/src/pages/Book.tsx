/**
 * Book page — Calendly inline embed with service-type selector and
 * call/text fallbacks. Calendly URL comes from VITE_CALENDLY_URL.
 */
import { useEffect, useState } from "react";
import { Phone, MessageSquare, CalendarCheck } from "lucide-react";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { Button } from "@/components/ui/button";
import { useDocumentMeta } from "@/lib/seo";
import { useLanguage } from "@/contexts/LanguageContext";

const CALENDLY_URL =
  (import.meta as any).env?.VITE_CALENDLY_URL || "https://calendly.com/whistleclean-sa";

const SERVICE_TYPES = [
  { en: "Apartment Cleaning", es: "Limpieza de Apartamentos" },
  { en: "Office Cleaning", es: "Limpieza de Oficinas" },
  { en: "Laundry Room Cleaning", es: "Limpieza de Cuartos de Lavado" },
  { en: "Touch-Up Cleaning", es: "Limpieza de Retoque" },
  { en: "Heavy / Deep Cleaning", es: "Limpieza Pesada / Profunda" },
  { en: "Move-Out Cleaning", es: "Limpieza de Mudanza" },
  { en: "Recurring / Property Manager", es: "Recurrente / Administrador" },
];

export default function Book() {
  const { t } = useLanguage();
  useDocumentMeta({
    title: "Book Online | Whistle Clean San Antonio",
    description:
      "Book your apartment, office, or laundry-room cleaning in San Antonio online in 60 seconds. Move-out and deep cleaning available.",
    path: "/book",
  });

  const [service, setService] = useState<string>("");

  // Load Calendly's embed script once.
  useEffect(() => {
    const id = "calendly-widget-script";
    if (document.getElementById(id)) return;
    const s = document.createElement("script");
    s.id = id;
    s.src = "https://assets.calendly.com/assets/external/widget.js";
    s.async = true;
    document.body.appendChild(s);
  }, []);

  const calendlySrc = service
    ? `${CALENDLY_URL}?a1=${encodeURIComponent(service)}`
    : CALENDLY_URL;

  // Re-initialize the inline widget when the selected service changes.
  useEffect(() => {
    const w = (window as any).Calendly;
    if (w?.initInlineWidgets) w.initInlineWidgets();
  }, [calendlySrc]);

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 bg-[oklch(0.955_0.025_237)]">
        <section className="py-12 md:py-16">
          <div className="container max-w-4xl">
            <div className="text-center mb-8">
              <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Book Now", "Reservar")}</span>
              <h1 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
                {t("Schedule Your Cleaning", "Programe su Limpieza")}
              </h1>
              <p className="text-slate-500 text-lg max-w-2xl mx-auto">
                {t(
                  "Pick a service and a time that works for you. Prefer to talk? Call or text us — we answer fast.",
                  "Elija un servicio y la hora que mejor le convenga. ¿Prefiere hablar? Llámenos o envíenos un mensaje de texto — respondemos rápido.",
                )}
              </p>
            </div>

            {/* Call / text fallbacks */}
            <div className="grid sm:grid-cols-2 gap-3 mb-8">
              <a
                href="tel:+12108594422"
                className="flex items-center justify-center gap-2 bg-white border border-slate-200 rounded-xl py-4 font-semibold text-[oklch(0.208_0.042_265.75)] hover:border-sky-300 hover:shadow-md transition-all"
              >
                <Phone className="w-5 h-5 text-sky-600" />
                {t("Call", "Llamar")} (210) 859-4422
              </a>
              <a
                href="sms:+12104145688"
                className="flex items-center justify-center gap-2 bg-white border border-slate-200 rounded-xl py-4 font-semibold text-[oklch(0.208_0.042_265.75)] hover:border-sky-300 hover:shadow-md transition-all"
              >
                <MessageSquare className="w-5 h-5 text-sky-600" />
                {t("Text", "Texto")} (210) 414-5688
              </a>
            </div>

            {/* Service selector */}
            <div className="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 md:p-8">
              <label className="block text-sm font-semibold text-slate-700 mb-3">
                {t("Which service do you need?", "¿Qué servicio necesita?")}
              </label>
              <div className="flex flex-wrap gap-2 mb-6">
                {SERVICE_TYPES.map((s) => (
                  <button
                    key={s.en}
                    onClick={() => setService(s.en)}
                    className={`px-3.5 py-2 rounded-full text-sm font-medium border transition-all ${
                      service === s.en
                        ? "bg-sky-600 text-white border-sky-600"
                        : "bg-white text-slate-600 border-slate-200 hover:border-sky-300"
                    }`}
                  >
                    {t(s.en, s.es)}
                  </button>
                ))}
              </div>

              {/* Calendly inline embed */}
              <div
                key={calendlySrc}
                className="calendly-inline-widget rounded-xl overflow-hidden border border-slate-100"
                data-url={calendlySrc}
                style={{ minWidth: "320px", height: "680px" }}
              />
              <p className="text-xs text-slate-400 mt-3 text-center">
                {t("Trouble booking? Call ", "¿Problemas para reservar? Llame al ")}<a href="tel:+12108594422" className="text-sky-600 font-medium">(210) 859-4422</a>{t(" and we'll get you scheduled.", " y le ayudaremos a agendar su cita.")}
              </p>
            </div>

            <div className="text-center mt-8">
              <CalendarCheck className="w-5 h-5 text-sky-600 inline mr-2" />
              <span className="text-slate-500 text-sm">{t("Free quotes · Licensed & insured · 20+ years · 5-star rated", "Cotizaciones gratis · Con licencia y asegurados · Más de 20 años · Calificación de 5 estrellas")}</span>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
