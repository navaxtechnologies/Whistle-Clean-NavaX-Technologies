/**
 * TrustBadges — Why Choose Whistle Clean
 * Design: Coastal Breeze — icon badges with staggered animation
 */
import { Shield, BadgeCheck, MapPin, Clock, Users, Star, Languages } from "lucide-react";
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

const badges = [
  { icon: BadgeCheck, label: "Licensed", labelEs: "Con Licencia", desc: "Fully licensed cleaning professionals", descEs: "Profesionales de limpieza con licencia completa" },
  { icon: Shield, label: "Insured", labelEs: "Asegurados", desc: "Complete liability coverage for your peace of mind", descEs: "Cobertura de responsabilidad completa para su tranquilidad" },
  { icon: MapPin, label: "Locally Owned", labelEs: "Negocio Local", desc: "Proudly serving San Antonio since day one", descEs: "Sirviendo con orgullo a San Antonio desde el primer día" },
  { icon: Clock, label: "20+ Years", labelEs: "Más de 20 Años", desc: "Two decades of trusted cleaning experience", descEs: "Dos décadas de experiencia confiable en limpieza" },
  { icon: Users, label: "Experienced Staff", labelEs: "Personal con Experiencia", desc: "Trained, reliable, and detail-oriented team", descEs: "Un equipo capacitado, confiable y atento a los detalles" },
  { icon: Star, label: "Top Reviews", labelEs: "Mejores Reseñas", desc: "Consistently rated 5 stars by our clients", descEs: "Calificados constantemente con 5 estrellas por nuestros clientes" },
  { icon: Languages, label: "Se Habla Español", labelEs: "Se Habla Español", desc: "Bilingual service for our community", descEs: "Servicio bilingüe para nuestra comunidad" },
];

export default function TrustBadges() {
  const { t } = useLanguage();
  return (
    <section className="py-16 md:py-20 bg-background">
      <div className="container">
        <AnimatedSection>
          <div className="text-center mb-12">
            <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Why Choose Us", "Por Qué Elegirnos")}</span>
            <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
              {t("Why Choose Whistle Clean?", "¿Por qué elegir Whistle Clean?")}
            </h2>
            <p className="text-slate-500 text-lg max-w-2xl mx-auto">
              {t("Spotless. Reliable. Whistle Clean. Here's what sets us apart from the rest.", "Impecable. Confiable. Whistle Clean. Esto es lo que nos distingue de los demás.")}
            </p>
          </div>
        </AnimatedSection>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 md:gap-6 max-w-5xl mx-auto">
          {badges.map((badge, i) => (
            <AnimatedSection key={badge.label} delay={i * 0.08}>
              <div className="group relative bg-white rounded-xl border border-slate-100 p-5 md:p-6 text-center hover:shadow-lg hover:border-sky-200 transition-all duration-300 hover:-translate-y-1 h-full">
                <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-gradient-to-br from-sky-50 to-sky-100 flex items-center justify-center group-hover:from-sky-100 group-hover:to-sky-200 transition-colors duration-300">
                  <badge.icon className="w-6 h-6 text-sky-600" />
                </div>
                <h3 className="font-display font-semibold text-[oklch(0.208_0.042_265.75)] text-sm md:text-base mb-1">{t(badge.label, badge.labelEs)}</h3>
                <p className="text-xs md:text-sm text-slate-500 leading-relaxed">{t(badge.desc, badge.descEs)}</p>
              </div>
            </AnimatedSection>
          ))}
        </div>
      </div>
    </section>
  );
}
