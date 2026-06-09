/**
 * Footer — Site footer with links and branding
 * Design: Coastal Breeze — dark navy footer
 */
import { Phone, Mail, MapPin } from "lucide-react";
import { Link } from "wouter";
import { useLanguage } from "@/contexts/LanguageContext";

const quickLinks = [
  { label: "Home", es: "Inicio", href: "/" },
  { label: "Services", es: "Servicios", href: "/services" },
  { label: "Gallery", es: "Galería", href: "/gallery" },
  { label: "Pricing", es: "Precios", href: "/pricing" },
  { label: "Book Now", es: "Reservar", href: "/book" },
  { label: "Contact", es: "Contacto", href: "/contact" },
];

const services = [
  { en: "Apartment Cleaning", es: "Limpieza de Apartamentos" },
  { en: "Office Cleaning", es: "Limpieza de Oficinas" },
  { en: "Laundry Room Cleaning", es: "Limpieza de Cuartos de Lavado" },
  { en: "Touch-Up Cleaning", es: "Limpieza de Retoque" },
  { en: "Heavy / Deep Cleaning", es: "Limpieza Pesada / Profunda" },
  { en: "Move-Out Cleaning", es: "Limpieza de Mudanza" },
];

export default function Footer() {
  const { t } = useLanguage();
  return (
    <footer className="bg-[oklch(0.208_0.042_265.75)] text-white">
      <div className="container py-12 md:py-16">
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8 lg:gap-10">
          {/* Brand */}
          <div className="sm:col-span-2 lg:col-span-1">
            <div className="flex items-center gap-2.5 mb-4">
              <img
                src="/images/whistle-clean-logo.jpg"
                alt="Whistle Clean Logo"
                className="w-11 h-11 rounded-full object-cover border-2 border-sky-400/30"
                loading="lazy"
              />
              <span className="font-display font-bold text-lg">Whistle Clean</span>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed mb-4">
              {t(
                "Professional apartment, office & laundry-room cleaning in San Antonio, TX. Licensed, insured, and locally owned for over 20 years.",
                "Limpieza profesional de apartamentos, oficinas y cuartos de lavado en San Antonio, TX. Con licencia, asegurados y de propiedad local por más de 20 años."
              )}
            </p>
            <p className="text-amber-400 font-semibold text-sm">Se Habla Espanol</p>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="font-display font-semibold text-sm uppercase tracking-wider mb-4 text-slate-300">{t("Quick Links", "Enlaces Rápidos")}</h4>
            <ul className="space-y-2">
              {quickLinks.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-slate-400 hover:text-white text-sm transition-colors"
                  >
                    {t(link.label, link.es)}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Services */}
          <div>
            <h4 className="font-display font-semibold text-sm uppercase tracking-wider mb-4 text-slate-300">{t("Services", "Servicios")}</h4>
            <ul className="space-y-2">
              {services.map((s) => (
                <li key={s.en}>
                  <span className="text-slate-400 text-sm">{t(s.en, s.es)}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact */}
          <div>
            <h4 className="font-display font-semibold text-sm uppercase tracking-wider mb-4 text-slate-300">{t("Contact", "Contacto")}</h4>
            <div className="space-y-3">
              <a href="tel:+12108594422" className="flex items-center gap-2 text-slate-400 hover:text-white text-sm transition-colors">
                <Phone className="w-4 h-4 shrink-0" />
                (210) 859-4422
              </a>
              <a href="tel:+12104145688" className="flex items-center gap-2 text-slate-400 hover:text-white text-sm transition-colors">
                <Phone className="w-4 h-4 shrink-0" />
                (210) 414-5688
              </a>
              <a href="mailto:whistleclean100@gmail.com" className="flex items-center gap-2 text-slate-400 hover:text-white text-sm transition-colors">
                <Mail className="w-4 h-4 shrink-0" />
                whistleclean100@gmail.com
              </a>
              <div className="flex items-start gap-2 text-slate-400 text-sm">
                <MapPin className="w-4 h-4 shrink-0 mt-0.5" />
                <span>19179 Blanco Rd. Suite 105-482<br />San Antonio, TX 78258</span>
              </div>
              <div className="flex items-start gap-2 text-slate-400 text-sm">
                <MapPin className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{t("San Antonio, TX & Surrounding Areas", "San Antonio, TX y Áreas Cercanas")}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-10 pt-6 border-t border-white/10 flex flex-col sm:flex-row justify-between items-center gap-3">
          <div className="flex items-center gap-2">
            <img
              src="/images/whistle-clean-logo.jpg"
              alt="Whistle Clean"
              className="w-6 h-6 rounded-full object-cover opacity-60"
              loading="lazy"
            />
            <p className="text-slate-500 text-xs">
              &copy; {new Date().getFullYear()} Whistle Clean. {t("All rights reserved.", "Todos los derechos reservados.")}
            </p>
          </div>
          <p className="text-slate-500 text-xs">
            {t("Serving San Antonio and Surrounding Areas", "Servicio en San Antonio y Áreas Cercanas")}
          </p>
        </div>
      </div>
    </footer>
  );
}
