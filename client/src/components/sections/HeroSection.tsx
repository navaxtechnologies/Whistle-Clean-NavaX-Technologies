/**
 * HeroSection — Full-width hero with background image, headline, CTAs
 * Design: Coastal Breeze — asymmetric layout, wave overlay at bottom
 * Features prominent logo display on first page load
 */
import { Phone, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import { useLanguage } from "@/contexts/LanguageContext";

const HERO_IMG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663477928365/9rtbpj8p5t4fRVrV2mhGb4/hero-bg-RjsgfhNY6KuBFVWstLEnPe.webp";

const serviceChips = [
  { en: "Apartments", es: "Apartamentos" },
  { en: "Homes", es: "Casas" },
  { en: "Offices", es: "Oficinas" },
  { en: "Commercial Buildings", es: "Edificios Comerciales" },
  { en: "Move-Outs", es: "Mudanzas" },
  { en: "Construction Cleanups", es: "Limpieza de Construcción" },
];

export default function HeroSection() {
  const { t } = useLanguage();
  const scrollTo = (id: string) => {
    document.querySelector(id)?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <section id="home" className="relative overflow-hidden">
      {/* Background image with overlay */}
      <div className="absolute inset-0">
        <img
          src={HERO_IMG}
          alt={t("Beautifully clean living room", "Sala de estar hermosamente limpia")}
          className="w-full h-full object-cover"
          fetchPriority="high"
        />
        <div className="absolute inset-0" style={{ background: 'linear-gradient(to right, rgba(10,20,40,0.97) 0%, rgba(10,20,40,0.93) 35%, rgba(10,20,40,0.82) 55%, rgba(10,20,40,0.5) 80%, rgba(10,20,40,0.3) 100%)' }} />
      </div>

      {/* Content */}
      <div className="relative container py-20 sm:py-28 md:py-36 lg:py-40">
        <div className="max-w-2xl">
          {/* Logo Badge - Prominent display on first load */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8, y: 30 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.7, ease: "easeOut" }}
            className="mb-8"
          >
            <div className="inline-flex items-center gap-4 bg-white/10 backdrop-blur-md border border-white/20 rounded-2xl px-5 py-3">
              <img
                src="/images/whistle-clean-logo.jpg"
                alt={t("Whistle Clean Logo", "Logotipo de Whistle Clean")}
                className="w-16 h-16 sm:w-20 sm:h-20 rounded-full object-cover shadow-xl border-2 border-amber-400/50"
              />
              <div>
                <span className="font-display font-bold text-xl sm:text-2xl text-white block leading-tight">Whistle Clean</span>
                <span className="text-amber-400 text-sm font-medium">{t("We Will Leave It Clean As A Whistle.", "Lo dejaremos impecable, limpio como una patena.")}</span>
              </div>
            </div>
          </motion.div>

          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded-full px-4 py-1.5 mb-6"
          >
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            <span className="text-sm font-medium text-white/90">{t("Trusted for 20+ Years in San Antonio", "Con la confianza de San Antonio por más de 20 años")}</span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="font-display font-extrabold text-4xl sm:text-5xl md:text-6xl text-white leading-[1.1] mb-5"
          >
            {t("Professional Cleaning Services", "Servicios de Limpieza Profesional")}{" "}
            <span className="text-amber-400">{t("Done Right", "Bien Hechos")}</span>
          </motion.h1>

          {/* Subheadline */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.5 }}
            className="text-lg sm:text-xl text-white/80 mb-8 leading-relaxed max-w-xl"
          >
            {t(
              "Licensed, insured, locally owned, and committed to spotless results. We go beyond cleaning — we care for your space like it's our own.",
              "Con licencia, asegurados, de propiedad local y comprometidos con resultados impecables. Vamos más allá de la limpieza: cuidamos su espacio como si fuera nuestro."
            )}
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.6 }}
            className="flex flex-wrap gap-3 mb-6"
          >
            <Button
              size="lg"
              onClick={() => scrollTo("#contact")}
              className="bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-500 hover:to-amber-600 text-[oklch(0.208_0.042_265.75)] font-bold shadow-lg hover:shadow-xl transition-all duration-300 px-7 py-6 text-base"
            >
              {t("Get a Free Quote", "Obtenga una Cotización Gratis")}
              <ArrowRight className="w-4.5 h-4.5 ml-1.5" />
            </Button>
            <Button
              size="lg"
              variant="outline"
              asChild
              className="border-white/30 text-white hover:bg-white/10 font-semibold px-7 py-6 text-base backdrop-blur-sm"
            >
              <a href="tel:+12108594422">
                <Phone className="w-4.5 h-4.5 mr-1.5" />
                (210) 859-4422
              </a>
            </Button>
          </motion.div>

          {/* Second phone number */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.7 }}
            className="mb-10"
          >
            <a href="tel:+12104145688" className="inline-flex items-center gap-1.5 text-sm text-white/60 hover:text-white/90 transition-colors">
              <Phone className="w-3.5 h-3.5" />
              {t("Also call:", "También llame al:")} (210) 414-5688
            </a>
          </motion.div>

          {/* Service chips */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.8 }}
            className="flex flex-wrap gap-2"
          >
            {serviceChips.map((chip) => (
              <span
                key={chip.en}
                className="text-xs sm:text-sm text-white/70 bg-white/8 border border-white/10 rounded-full px-3 py-1"
              >
                {t(chip.en, chip.es)}
              </span>
            ))}
          </motion.div>
        </div>
      </div>

      {/* Wave bottom */}
      <div className="absolute bottom-0 left-0 right-0 overflow-hidden leading-[0]">
        <svg
          viewBox="0 0 1440 80"
          preserveAspectRatio="none"
          className="w-full h-[40px] sm:h-[60px] md:h-[80px] block"
        >
          <path
            d="M0,0 L0,40 C120,15 240,5 360,20 C480,35 600,65 720,70 C840,75 960,55 1080,40 C1200,25 1320,15 1380,12 L1440,10 L1440,0 Z"
            fill="oklch(0.995 0.002 240)"
          />
        </svg>
      </div>
    </section>
  );
}
