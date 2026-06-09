/**
 * FAQSection — Frequently Asked Questions
 * Design: Coastal Breeze — accordion style
 */
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import AnimatedSection from "@/components/AnimatedSection";
import { useLanguage } from "@/contexts/LanguageContext";

const faqs = [
  {
    q: "What areas do you serve?",
    qEs: "¿En qué áreas prestan servicio?",
    a: "We proudly serve San Antonio and all surrounding areas. Whether you're in the city center or in a nearby community, we're happy to provide our professional cleaning services.",
    aEs: "Con orgullo prestamos servicio en San Antonio y todas las áreas cercanas. Ya sea que se encuentre en el centro de la ciudad o en una comunidad cercana, con gusto le ofrecemos nuestros servicios de limpieza profesional.",
  },
  {
    q: "Are you licensed and insured?",
    qEs: "¿Cuentan con licencia y seguro?",
    a: "Yes! Whistle Clean is fully licensed and insured. We carry complete liability coverage so you can have peace of mind knowing your property is protected.",
    aEs: "¡Sí! Whistle Clean cuenta con licencia y seguro completos. Tenemos cobertura total de responsabilidad civil para que usted tenga la tranquilidad de saber que su propiedad está protegida.",
  },
  {
    q: "What types of cleaning do you offer?",
    qEs: "¿Qué tipos de limpieza ofrecen?",
    a: "We offer residential cleaning, apartment cleaning, office cleaning, commercial building cleaning, large facility cleaning, move-out cleaning, post-construction cleaning, recurring cleaning visits, and real estate showing cleanings.",
    aEs: "Ofrecemos limpieza residencial, limpieza de apartamentos, limpieza de oficinas, limpieza de edificios comerciales, limpieza de instalaciones grandes, limpieza de mudanza, limpieza posterior a la construcción, visitas de limpieza recurrentes y limpiezas para mostrar propiedades inmobiliarias.",
  },
  {
    q: "How do I get a free quote?",
    qEs: "¿Cómo puedo obtener una cotización gratuita?",
    a: "Simply fill out the contact form on our website, give us a call, or send us a message. We'll discuss your needs and provide a free, no-obligation quote tailored to your space.",
    aEs: "Simplemente complete el formulario de contacto en nuestro sitio web, llámenos o envíenos un mensaje. Conversaremos sobre sus necesidades y le brindaremos una cotización gratuita y sin compromiso, hecha a la medida de su espacio.",
  },
  {
    q: "Do you offer recurring cleaning services?",
    qEs: "¿Ofrecen servicios de limpieza recurrentes?",
    a: "Absolutely! We offer weekly, bi-weekly, and monthly cleaning schedules. Many of our clients enjoy the consistency and reliability of regular visits.",
    aEs: "¡Por supuesto! Ofrecemos programas de limpieza semanales, quincenales y mensuales. Muchos de nuestros clientes disfrutan de la constancia y la confiabilidad de las visitas regulares.",
  },
  {
    q: "Do you bring your own cleaning supplies?",
    qEs: "¿Traen sus propios productos de limpieza?",
    a: "Yes, we bring all necessary professional-grade cleaning products and equipment. Our products leave spaces looking clean, smelling fresh, and feeling renewed.",
    aEs: "Sí, traemos todos los productos y equipos de limpieza de grado profesional necesarios. Nuestros productos dejan los espacios limpios, con un aroma fresco y una sensación renovada.",
  },
  {
    q: "Can you clean before a real estate showing?",
    qEs: "¿Pueden limpiar antes de mostrar una propiedad inmobiliaria?",
    a: "Yes! We work with real estate agents throughout San Antonio to provide scheduled cleanings before open houses and property showings. We ensure every listing looks its best.",
    aEs: "¡Sí! Trabajamos con agentes inmobiliarios en todo San Antonio para realizar limpiezas programadas antes de las casas abiertas y las muestras de propiedades. Nos aseguramos de que cada propiedad luzca de la mejor manera.",
  },
  {
    q: "Do you speak Spanish?",
    qEs: "¿Hablan español?",
    a: "Sí, hablamos español. Our bilingual team is happy to assist you in both English and Spanish.",
    aEs: "Sí, hablamos español. Nuestro equipo bilingüe con gusto le atiende tanto en inglés como en español.",
  },
];

export default function FAQSection() {
  const { t } = useLanguage();
  return (
    <section id="faq" className="py-16 md:py-24 bg-background">
      <div className="container">
        <AnimatedSection>
          <div className="text-center mb-12">
            <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">FAQ</span>
            <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
              {t("Frequently Asked Questions", "Preguntas Frecuentes")}
            </h2>
            <p className="text-slate-500 text-lg max-w-2xl mx-auto">
              {t(
                "Have questions? We've got answers. If you don't see what you're looking for, feel free to contact us.",
                "¿Tiene preguntas? Tenemos las respuestas. Si no encuentra lo que busca, no dude en contactarnos."
              )}
            </p>
          </div>
        </AnimatedSection>

        <AnimatedSection delay={0.1}>
          <div className="max-w-3xl mx-auto">
            <Accordion type="single" collapsible className="space-y-3">
              {faqs.map((faq, i) => (
                <AccordionItem
                  key={i}
                  value={`faq-${i}`}
                  className="bg-white rounded-xl border border-slate-100 px-5 md:px-6 overflow-hidden data-[state=open]:shadow-md data-[state=open]:border-sky-200 transition-all duration-200"
                >
                  <AccordionTrigger className="text-left font-display font-semibold text-[oklch(0.208_0.042_265.75)] text-sm md:text-base py-4 hover:no-underline hover:text-sky-600 transition-colors">
                    {t(faq.q, faq.qEs)}
                  </AccordionTrigger>
                  <AccordionContent className="text-slate-600 text-sm md:text-base leading-relaxed pb-4">
                    {t(faq.a, faq.aEs)}
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          </div>
        </AnimatedSection>
      </div>
    </section>
  );
}
