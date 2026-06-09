/**
 * Navbar — Sticky top navigation
 * Design: Coastal Breeze / Organic Freshness
 * - Glass-morphism effect on scroll
 * - Mobile hamburger menu with slide-in drawer
 * - Click-to-call on mobile
 * - Multi-page routing via wouter
 */
import { useState, useEffect } from "react";
import { Phone, Menu, X, Globe } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";
import { Link } from "wouter";
import { useLanguage } from "@/contexts/LanguageContext";

const navLinks = [
  { en: "Home", es: "Inicio", href: "/" },
  { en: "Services", es: "Servicios", href: "/services" },
  { en: "Gallery", es: "Galería", href: "/gallery" },
  { en: "Pricing", es: "Precios", href: "/pricing" },
  { en: "Contact", es: "Contacto", href: "/contact" },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const { t, lang, toggle } = useLanguage();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const closeMobile = () => setMobileOpen(false);

  return (
    <>
      {/* Top bar */}
      <div className="bg-[oklch(0.208_0.042_265.75)] text-white text-sm py-2 hidden md:block">
        <div className="container flex justify-between items-center">
          <div className="flex items-center gap-4">
            <span>{t("Serving San Antonio & Surrounding Areas", "Servicio en San Antonio y Áreas Cercanas")}</span>
            <span className="text-amber-400 font-semibold">Se Habla Español</span>
          </div>
          <div className="flex items-center gap-4">
            <span>{t("Licensed • Insured • Locally Owned", "Con Licencia • Asegurados • Negocio Local")}</span>
            <a href="tel:+12108594422" className="flex items-center gap-1.5 text-amber-400 font-semibold hover:text-amber-300 transition-colors">
              <Phone className="w-3.5 h-3.5" />
              (210) 859-4422
            </a>
            <span className="text-white/40">|</span>
            <a href="tel:+12104145688" className="flex items-center gap-1.5 text-amber-400 font-semibold hover:text-amber-300 transition-colors">
              <Phone className="w-3.5 h-3.5" />
              (210) 414-5688
            </a>
          </div>
        </div>
      </div>

      {/* Main nav */}
      <nav
        className={`sticky top-0 z-50 transition-all duration-300 ${scrolled
          ? "bg-white/90 backdrop-blur-lg shadow-md border-b border-slate-200/50"
          : "bg-white shadow-sm"
          }`}
      >
        <div className="container flex items-center justify-between h-16 md:h-18">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 group" onClick={closeMobile}>
            <img
              src="/images/whistle-clean-logo.jpg"
              alt="Whistle Clean Logo"
              className="w-11 h-11 rounded-full object-cover shadow-md group-hover:shadow-lg transition-shadow border-2 border-sky-100"
            />
            <div className="leading-tight">
              <span className="font-display font-bold text-lg text-[oklch(0.208_0.042_265.75)] tracking-tight">Whistle Clean</span>
              <span className="block text-[10px] text-slate-500 font-medium tracking-widest uppercase -mt-0.5">San Antonio, TX</span>
            </div>
          </Link>

          {/* Desktop links */}
          <div className="hidden lg:flex items-center gap-1">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="px-3.5 py-2 text-sm font-medium text-slate-600 hover:text-sky-600 rounded-lg hover:bg-sky-50 transition-all duration-200"
              >
                {t(link.en, link.es)}
              </Link>
            ))}
          </div>

          {/* Desktop CTA */}
          <div className="hidden lg:flex items-center gap-3">
            <button
              onClick={toggle}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold text-slate-600 hover:text-sky-600 rounded-lg hover:bg-sky-50 transition-all duration-200"
              aria-label={lang === "en" ? "Ver en español" : "View in English"}
            >
              <Globe className="w-4 h-4" />
              {lang === "en" ? "ES" : "EN"}
            </button>
            <div className="flex flex-col items-end gap-0.5">
              <a href="tel:+12108594422" className="flex items-center gap-1.5 text-sm font-semibold text-slate-700 hover:text-sky-600 transition-colors">
                <Phone className="w-3.5 h-3.5" />
                (210) 859-4422
              </a>
              <a href="tel:+12104145688" className="flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-sky-600 transition-colors">
                <Phone className="w-3 h-3" />
                (210) 414-5688
              </a>
            </div>
            <Link href="/book">
              <Button
                className="bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-600 hover:to-sky-700 text-white font-semibold shadow-md hover:shadow-lg transition-all duration-200 px-5"
              >
                {t("Book Now", "Reservar")}
              </Button>
            </Link>
          </div>

          {/* Mobile buttons */}
          <div className="flex lg:hidden items-center gap-2">
            <button
              onClick={toggle}
              className="flex items-center justify-center gap-1 px-2.5 h-10 rounded-lg text-sm font-semibold text-slate-600 hover:bg-slate-100 transition-colors"
              aria-label={lang === "en" ? "Ver en español" : "View in English"}
            >
              <Globe className="w-4 h-4" />
              {lang === "en" ? "ES" : "EN"}
            </button>
            <a
              href="tel:+12108594422"
              className="flex items-center justify-center w-10 h-10 rounded-full bg-sky-50 text-sky-600 hover:bg-sky-100 transition-colors"
            >
              <Phone className="w-5 h-5" />
            </a>
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="flex items-center justify-center w-10 h-10 rounded-lg text-slate-700 hover:bg-slate-100 transition-colors"
              aria-label="Toggle menu"
            >
              {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile menu overlay */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-x-0 top-[64px] md:top-[96px] z-40 bg-white shadow-xl border-t border-slate-100 lg:hidden"
          >
            <div className="container py-4 space-y-1">
              {navLinks.map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  onClick={closeMobile}
                  className="block w-full text-left px-4 py-3 text-base font-medium text-slate-700 hover:text-sky-600 hover:bg-sky-50 rounded-lg transition-colors"
                >
                  {t(link.en, link.es)}
                </Link>
              ))}
              {/* Phone numbers in mobile menu */}
              <div className="pt-2 space-y-2">
                <a href="tel:+12108594422" className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-sky-600">
                  <Phone className="w-4 h-4" />
                  (210) 859-4422
                </a>
                <a href="tel:+12104145688" className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-sky-600">
                  <Phone className="w-4 h-4" />
                  (210) 414-5688
                </a>
              </div>
              <div className="pt-3 border-t border-slate-100 mt-2">
                <Link href="/book" onClick={closeMobile}>
                  <Button
                    className="w-full bg-gradient-to-r from-sky-500 to-sky-600 text-white font-semibold shadow-md py-3"
                  >
                    {t("Book Now", "Reservar")}
                  </Button>
                </Link>
                <p className="text-center text-sm text-amber-600 font-semibold mt-3">Se Habla Español</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
