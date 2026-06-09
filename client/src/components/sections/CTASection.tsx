/**
 * CTASection — Ready for a Spotless Space?
 * Design: Coastal Breeze — gradient background with wave CTA image
 */
import { Phone, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

const CTA_BG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663477928365/9rtbpj8p5t4fRVrV2mhGb4/cta-bg-2NsZmZwcgoK3a6SbcGX4gZ.webp";

export default function CTASection() {
  const { t } = useLanguage();
  const scrollTo = (id: string) => {
    document.querySelector(id)?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <section className="relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0">
        <img src={CTA_BG} alt="" className="w-full h-full object-cover" loading="lazy" />
        <div className="absolute inset-0 bg-gradient-to-br from-sky-600/85 to-sky-800/90" />
      </div>

      <div className="relative container py-16 md:py-24 text-center">
        <AnimatedSection>
          {/* Logo in CTA */}
          <img
            src="/images/whistle-clean-logo.jpg"
            alt="Whistle Clean Logo"
            className="w-20 h-20 rounded-full object-cover mx-auto mb-6 border-3 border-white/30 shadow-xl"
            loading="lazy"
          />
          <h2 className="font-display font-bold text-3xl sm:text-4xl md:text-5xl text-white mb-5 leading-tight">
            {t("Ready for a Spotless Space?", "¿Listo para un Espacio Impecable?")}
          </h2>
          <p className="text-white/85 text-lg sm:text-xl max-w-2xl mx-auto mb-8 leading-relaxed">
            {t(
              "Whether you need apartment cleaning, office cleaning, recurring service, or a move-out clean, Whistle Clean is ready to help.",
              "Ya sea que necesite limpieza de apartamentos, limpieza de oficinas, servicio recurrente o una limpieza de mudanza, Whistle Clean está listo para ayudarle."
            )}
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Button
              size="lg"
              onClick={() => scrollTo("#contact")}
              className="bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-500 hover:to-amber-600 text-[oklch(0.208_0.042_265.75)] font-bold shadow-lg hover:shadow-xl transition-all duration-300 px-8 py-6 text-base"
            >
              {t("Request a Quote", "Solicite una Cotización")}
              <ArrowRight className="w-4.5 h-4.5 ml-1.5" />
            </Button>
            <Button
              size="lg"
              variant="outline"
              asChild
              className="border-white/30 text-white hover:bg-white/10 font-semibold px-8 py-6 text-base backdrop-blur-sm"
            >
              <a href="tel:+12108594422">
                <Phone className="w-4.5 h-4.5 mr-1.5" />
                (210) 859-4422
              </a>
            </Button>
          </div>
          {/* Secondary phone */}
          <p className="mt-4 text-white/60 text-sm">
            {t("Or call", "O llame al")} <a href="tel:+12104145688" className="text-white/80 hover:text-white underline underline-offset-2 transition-colors">(210) 414-5688</a>
          </p>
        </AnimatedSection>
      </div>
    </section>
  );
}
