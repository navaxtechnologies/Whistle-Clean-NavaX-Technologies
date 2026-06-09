/**
 * TestimonialsSection — Reviews / Testimonials
 * Design: Coastal Breeze — card carousel with star ratings
 */
import { Star, Quote } from "lucide-react";
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

const testimonials = [
  {
    text: "They handled our office move-out cleaning like pros — spotless and right on time. We couldn't be happier with the results.",
    textEs: "Realizaron la limpieza de salida de nuestra oficina como verdaderos profesionales: impecable y justo a tiempo. No podríamos estar más satisfechos con los resultados.",
    author: "Maria G.",
    role: "Office Manager",
    roleEs: "Gerente de Oficina",
    rating: 5,
  },
  {
    text: "My apartment looked brand new after their deep clean. Every corner was spotless. I got my full deposit back!",
    textEs: "Mi apartamento quedó como nuevo después de su limpieza profunda. Cada rincón quedó impecable. ¡Recuperé mi depósito completo!",
    author: "James R.",
    role: "Apartment Tenant",
    roleEs: "Inquilino de Apartamento",
    rating: 5,
  },
  {
    text: "Our weekly visits are always consistent, professional, and friendly. The team is reliable and does an amazing job every single time.",
    textEs: "Nuestras visitas semanales son siempre constantes, profesionales y amables. El equipo es confiable y hace un trabajo excelente cada vez.",
    author: "Sarah L.",
    role: "Business Owner",
    roleEs: "Dueña de Negocio",
    rating: 5,
  },
  {
    text: "We use Whistle Clean for all our property showings. They always deliver a spotless space that impresses our buyers.",
    textEs: "Usamos Whistle Clean para todas nuestras presentaciones de propiedades. Siempre entregan un espacio impecable que impresiona a nuestros compradores.",
    author: "David M.",
    role: "Real Estate Agent",
    roleEs: "Agente de Bienes Raíces",
    rating: 5,
  },
  {
    text: "After our renovation, the construction cleanup was incredible. They removed every trace of dust and debris. Highly recommend!",
    textEs: "Después de nuestra renovación, la limpieza posconstrucción fue increíble. Eliminaron cada rastro de polvo y escombros. ¡Muy recomendados!",
    author: "Patricia H.",
    role: "Homeowner",
    roleEs: "Propietaria de Vivienda",
    rating: 5,
  },
];

export default function TestimonialsSection() {
  const { t } = useLanguage();
  return (
    <section id="reviews" className="py-16 md:py-24 bg-background">
      <div className="container">
        <AnimatedSection>
          <div className="text-center mb-12">
            <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Testimonials", "Testimonios")}</span>
            <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
              {t("What Our Clients Say", "Lo que dicen nuestros clientes")}
            </h2>
            <p className="text-slate-500 text-lg max-w-2xl mx-auto">
              {t("Don't just take our word for it — hear from the people who trust us with their spaces.", "No se quede solo con nuestra palabra: escuche a las personas que confían en nosotros con sus espacios.")}
            </p>
          </div>
        </AnimatedSection>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5 max-w-6xl mx-auto">
          {testimonials.slice(0, 3).map((item, i) => (
            <AnimatedSection key={i} delay={i * 0.1}>
              <div className="bg-white rounded-xl border border-slate-100 p-6 hover:shadow-lg hover:border-sky-200 transition-all duration-300 h-full flex flex-col">
                <Quote className="w-8 h-8 text-sky-200 mb-3" />
                <p className="text-slate-600 leading-relaxed mb-5 flex-1 italic">"{t(item.text, item.textEs)}"</p>
                <div className="flex items-center gap-1 mb-3">
                  {Array.from({ length: item.rating }).map((_, j) => (
                    <Star key={j} className="w-4 h-4 fill-amber-400 text-amber-400" />
                  ))}
                </div>
                <div>
                  <p className="font-display font-semibold text-[oklch(0.208_0.042_265.75)] text-sm">{item.author}</p>
                  <p className="text-xs text-slate-400">{t(item.role, item.roleEs)}</p>
                </div>
              </div>
            </AnimatedSection>
          ))}
        </div>

        {/* Second row */}
        <div className="grid sm:grid-cols-2 gap-5 max-w-4xl mx-auto mt-5">
          {testimonials.slice(3).map((item, i) => (
            <AnimatedSection key={i + 3} delay={(i + 3) * 0.1}>
              <div className="bg-white rounded-xl border border-slate-100 p-6 hover:shadow-lg hover:border-sky-200 transition-all duration-300 h-full flex flex-col">
                <Quote className="w-8 h-8 text-sky-200 mb-3" />
                <p className="text-slate-600 leading-relaxed mb-5 flex-1 italic">"{t(item.text, item.textEs)}"</p>
                <div className="flex items-center gap-1 mb-3">
                  {Array.from({ length: item.rating }).map((_, j) => (
                    <Star key={j} className="w-4 h-4 fill-amber-400 text-amber-400" />
                  ))}
                </div>
                <div>
                  <p className="font-display font-semibold text-[oklch(0.208_0.042_265.75)] text-sm">{item.author}</p>
                  <p className="text-xs text-slate-400">{t(item.role, item.roleEs)}</p>
                </div>
              </div>
            </AnimatedSection>
          ))}
        </div>
      </div>
    </section>
  );
}
