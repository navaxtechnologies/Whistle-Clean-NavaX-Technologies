/**
 * ContactSection — Contact form + business info
 * Design: Coastal Breeze — split layout, clean form
 */
import { useState } from "react";
import { Phone, MapPin, Clock, Languages, Mail, Send, type LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import AnimatedSection from "@/components/AnimatedSection";
import { toast } from "sonner";
import { useLanguage } from "@/contexts/LanguageContext";

type ContactItem = {
  icon: LucideIcon;
  label: string;
  labelEs: string;
  value: string;
  valueEs: string | null;
  href: string | null;
};

const contactInfo: ContactItem[] = [
  { icon: Phone, label: "Phone (Primary)", labelEs: "Teléfono (Principal)", value: "(210) 859-4422", valueEs: null, href: "tel:+12108594422" },
  { icon: Phone, label: "Leo Romero", labelEs: "Leo Romero", value: "(210) 414-5688", valueEs: null, href: "tel:+12104145688" },
  { icon: Mail, label: "Email", labelEs: "Correo", value: "whistleclean100@gmail.com", valueEs: null, href: "mailto:whistleclean100@gmail.com" },
  { icon: MapPin, label: "Address", labelEs: "Dirección", value: "19179 Blanco Rd. Suite 105-482, San Antonio, TX 78258", valueEs: null, href: null },
  { icon: MapPin, label: "Service Area", labelEs: "Área de Servicio", value: "San Antonio, TX & Surrounding Areas", valueEs: "San Antonio, TX y Áreas Cercanas", href: null },
  { icon: Clock, label: "Business Hours", labelEs: "Horario", value: "Mon-Fri: 7AM-6PM | Sat: 8AM-4PM", valueEs: "Lun-Vie: 7AM-6PM | Sáb: 8AM-4PM", href: null },
  { icon: Languages, label: "Se Habla Espanol", labelEs: "Se Habla Español", value: "Bilingual service available", valueEs: "Servicio bilingüe disponible", href: null },
];

// Basic input sanitization to prevent XSS
function sanitizeInput(value: string): string {
  return value
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

// Email validation
function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Phone validation
function isValidPhone(phone: string): boolean {
  if (!phone) return true; // optional field
  const phoneRegex = /^[\d\s\-\(\)\+]+$/;
  return phoneRegex.test(phone);
}

export default function ContactSection() {
  const { t } = useLanguage();
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    phone: "",
    service: "",
    date: "",
    message: "",
    wcx_note: "", // honeypot — must stay empty for real users
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate inputs
    if (!formData.name.trim() || !formData.email.trim()) {
      toast.error(t("Please fill in all required fields.", "Por favor complete todos los campos obligatorios."));
      return;
    }

    if (!isValidEmail(formData.email)) {
      toast.error(t("Please enter a valid email address.", "Por favor ingrese un correo electrónico válido."));
      return;
    }

    if (!isValidPhone(formData.phone)) {
      toast.error(t("Please enter a valid phone number.", "Por favor ingrese un número de teléfono válido."));
      return;
    }

    // Rate limiting - prevent rapid submissions
    setIsSubmitting(true);

    // Sanitize all inputs before submission
    const sanitizedData = {
      name: sanitizeInput(formData.name.trim()),
      email: sanitizeInput(formData.email.trim()),
      phone: sanitizeInput(formData.phone.trim()),
      service: sanitizeInput(formData.service),
      date: sanitizeInput(formData.date),
      message: sanitizeInput(formData.message.trim()),
      wcx_note: formData.wcx_note, // honeypot — forwarded so the server can drop bots
    };

    // In production, this would send to a secure backend endpoint
    console.log("Sanitized form data:", sanitizedData);

    try {
      // Send actual API request to the backend
      const response = await fetch('/api/quote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sanitizedData)
      });
      
      if (!response.ok) throw new Error("Failed to send quote request.");

      toast.success(t("Thank you! We'll get back to you within 24 hours.", "¡Gracias! Le responderemos dentro de las próximas 24 horas."), {
        description: t("Your quote request for ", "Su solicitud de cotización para ") + (formData.date || t("as soon as possible", "lo antes posible")) + t(" has been received.", " ha sido recibida."),
      });
      setFormData({ name: "", email: "", phone: "", service: "", date: "", message: "", wcx_note: "" });
    } catch (err) {
      toast.error(t("Something went wrong. Please try again later.", "Algo salió mal. Por favor intente de nuevo más tarde."), {
        description: t("You can also call us directly at (210) 859-4422.", "También puede llamarnos directamente al (210) 859-4422.")
      });
    }

    // Re-enable after cooldown
    setTimeout(() => setIsSubmitting(false), 3000);
  };

  return (
    <section id="contact" className="py-16 md:py-24 bg-[oklch(0.955_0.025_237)]">
      <div className="container">
        <AnimatedSection>
          <div className="text-center mb-12">
            <span className="inline-block text-sm font-semibold text-sky-600 tracking-wider uppercase mb-3">{t("Contact Us", "Contáctenos")}</span>
            <h2 className="font-display font-bold text-3xl sm:text-4xl text-[oklch(0.208_0.042_265.75)] mb-4">
              {t("Get Your Free Quote Today", "Obtenga Su Cotización Gratis Hoy")}
            </h2>
            <p className="text-slate-500 text-lg max-w-2xl mx-auto">
              {t("Fill out the form below and we'll get back to you within 24 hours. Or give us a call.", "Complete el formulario a continuación y le responderemos dentro de las próximas 24 horas. O llámenos.")}
            </p>
          </div>
        </AnimatedSection>

        <div className="grid lg:grid-cols-5 gap-8 lg:gap-12 max-w-6xl mx-auto">
          {/* Form */}
          <AnimatedSection className="lg:col-span-3">
            <form onSubmit={handleSubmit} className="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 md:p-8">
              {/* Honeypot: hidden from real users; only bots fill it. */}
              <div className="absolute w-px h-px overflow-hidden -left-[9999px]" aria-hidden="true">
                <label htmlFor="wcx_note">Leave this field empty</label>
                <input
                  id="wcx_note"
                  name="wcx_note"
                  type="text"
                  tabIndex={-1}
                  autoComplete="off"
                  value={formData.wcx_note}
                  onChange={(e) => setFormData({ ...formData, wcx_note: e.target.value })}
                />
              </div>
              <div className="grid sm:grid-cols-2 gap-4 mb-4">
                <div className="space-y-2">
                  <Label htmlFor="name" className="text-sm font-medium text-slate-700">{t("Full Name *", "Nombre Completo *")}</Label>
                  <Input
                    id="name"
                    required
                    placeholder={t("Your name", "Su nombre")}
                    maxLength={100}
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="h-11 border-slate-200 focus:border-sky-400 focus:ring-sky-400/20"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-sm font-medium text-slate-700">{t("Email *", "Correo *")}</Label>
                  <Input
                    id="email"
                    type="email"
                    required
                    placeholder="your@email.com"
                    maxLength={200}
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="h-11 border-slate-200 focus:border-sky-400 focus:ring-sky-400/20"
                  />
                </div>
              </div>

              <div className="grid sm:grid-cols-2 gap-4 mb-4">
                <div className="space-y-2">
                  <Label htmlFor="phone" className="text-sm font-medium text-slate-700">{t("Phone Number", "Número de Teléfono")}</Label>
                  <Input
                    id="phone"
                    type="tel"
                    placeholder="(210) 555-0000"
                    maxLength={20}
                    value={formData.phone}
                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                    className="h-11 border-slate-200 focus:border-sky-400 focus:ring-sky-400/20"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="service" className="text-sm font-medium text-slate-700">{t("Service Needed", "Servicio Requerido")}</Label>
                  <Select value={formData.service} onValueChange={(val) => setFormData({ ...formData, service: val })}>
                    <SelectTrigger className="h-11 border-slate-200">
                      <SelectValue placeholder={t("Select a service", "Seleccione un servicio")} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="apartment">{t("Apartment Cleaning", "Limpieza de Apartamentos")}</SelectItem>
                      <SelectItem value="office">{t("Office Cleaning", "Limpieza de Oficinas")}</SelectItem>
                      <SelectItem value="laundry">{t("Laundry Room Cleaning", "Limpieza de Cuartos de Lavado")}</SelectItem>
                      <SelectItem value="touchup">{t("Touch-Up Cleaning", "Limpieza de Retoque")}</SelectItem>
                      <SelectItem value="deep">{t("Heavy / Deep Cleaning", "Limpieza Pesada / Profunda")}</SelectItem>
                      <SelectItem value="moveout">{t("Move-Out Cleaning", "Limpieza de Mudanza")}</SelectItem>
                      <SelectItem value="recurring">{t("Recurring / Property Manager", "Recurrente / Administrador")}</SelectItem>
                      <SelectItem value="other">{t("Other", "Otro")}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="grid sm:grid-cols-1 gap-4 mb-4">
                <div className="space-y-2">
                  <Label htmlFor="date" className="text-sm font-medium text-slate-700">{t("Preferred Service Date", "Fecha de Servicio Preferida")}</Label>
                  <Input
                    id="date"
                    type="date"
                    value={formData.date}
                    onChange={(e) => setFormData({ ...formData, date: e.target.value })}
                    className="h-11 border-slate-200 focus:border-sky-400 focus:ring-sky-400/20"
                    min={new Date().toISOString().split('T')[0]}
                  />
                </div>
              </div>

              <div className="space-y-2 mb-6">
                <Label htmlFor="message" className="text-sm font-medium text-slate-700">{t("Message", "Mensaje")}</Label>
                <Textarea
                  id="message"
                  rows={4}
                  placeholder={t("Tell us about your cleaning needs...", "Cuéntenos sobre sus necesidades de limpieza...")}
                  maxLength={2000}
                  value={formData.message}
                  onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                  className="border-slate-200 focus:border-sky-400 focus:ring-sky-400/20 resize-none"
                />
              </div>

              <Button
                type="submit"
                size="lg"
                disabled={isSubmitting}
                className="w-full bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-600 hover:to-sky-700 text-white font-bold shadow-md hover:shadow-lg transition-all duration-300 py-6 text-base disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Send className="w-4.5 h-4.5 mr-2" />
                {isSubmitting ? t("Sending...", "Enviando...") : t("Send Quote Request", "Enviar Solicitud de Cotización")}
              </Button>
            </form>
          </AnimatedSection>

          {/* Contact Info */}
          <AnimatedSection delay={0.15} className="lg:col-span-2">
            <div className="space-y-4">
              {contactInfo.map((item) => (
                <div key={item.label} className="bg-white rounded-xl border border-slate-100 p-4 hover:shadow-md transition-shadow duration-200">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-sky-50 to-sky-100 flex items-center justify-center shrink-0">
                      <item.icon className="w-5 h-5 text-sky-600" />
                    </div>
                    <div>
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-0.5">{t(item.label, item.labelEs)}</p>
                      {item.href ? (
                        <a href={item.href} className="text-sm font-medium text-[oklch(0.208_0.042_265.75)] hover:text-sky-600 transition-colors">
                          {item.valueEs ? t(item.value, item.valueEs) : item.value}
                        </a>
                      ) : (
                        <p className="text-sm font-medium text-[oklch(0.208_0.042_265.75)]">{item.valueEs ? t(item.value, item.valueEs) : item.value}</p>
                      )}
                    </div>
                  </div>
                </div>
              ))}

              {/* Map + Logo */}
              <div className="bg-white rounded-xl border border-slate-100 p-2 overflow-hidden shadow-sm">
                <div className="relative aspect-video rounded-lg overflow-hidden border border-slate-50">
                  <img
                    src="/images/service-map.png"
                    alt="Whistle Clean Service Area - San Antonio"
                    className="w-full h-full object-cover"
                    loading="lazy"
                  />
                  <div className="absolute inset-0 bg-sky-600/5 pointer-events-none" />
                  <div className="absolute bottom-3 left-3 bg-white/90 backdrop-blur-sm px-3 py-1.5 rounded-full border border-slate-100 shadow-sm">
                    <div className="flex items-center gap-1.5">
                      <MapPin className="w-3.5 h-3.5 text-sky-600" />
                      <span className="text-[10px] font-bold text-slate-700 tracking-tight uppercase">{t("50-Mile Service Area", "Área de Servicio de 50 Millas")}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-br from-sky-500 to-sky-600 rounded-xl p-6 text-center shadow-lg relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full -mr-16 -mt-16 transition-transform duration-700 group-hover:scale-125" />
                <img
                  src="/images/whistle-clean-logo.jpg"
                  alt="Whistle Clean Logo"
                  className="w-16 h-16 rounded-full object-cover mx-auto mb-3 border-2 border-white/50 shadow-md relative z-10"
                  loading="lazy"
                />
                <p className="font-display font-bold text-white text-xl mb-1 relative z-10">{t("We Clean. You Shine.", "Nosotros Limpiamos. Usted Brilla.")}</p>
                <p className="text-sky-100 text-sm mb-4 relative z-10">{t("Professional cleaning services for when you need it done right.", "Servicios de limpieza profesional para cuando necesita que se haga bien.")}</p>
                <a
                  href="tel:+12108594422"
                  className="inline-flex items-center gap-2 bg-white text-sky-600 px-5 py-2.5 rounded-full font-bold text-sm shadow-sm hover:bg-sky-50 transition-colors relative z-10"
                >
                  <Phone className="w-4 h-4" />
                  {t("Click to Call Now", "Llame Ahora")}
                </a>
              </div>
            </div>
          </AnimatedSection>
        </div>
      </div>
    </section>
  );
}
