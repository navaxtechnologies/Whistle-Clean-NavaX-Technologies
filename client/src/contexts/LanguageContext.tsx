/**
 * LanguageContext — lightweight EN/ES bilingual layer for Whistle Clean.
 *
 * Usage in any component:
 *   const { t, lang, toggle } = useLanguage();
 *   <h1>{t("Book Now", "Reservar")}</h1>
 *
 * `t(en, es)` returns the string for the active language. Choice is persisted
 * to localStorage and seeded from the browser language on first visit. The
 * <html lang> attribute is kept in sync for SEO/accessibility.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

type Lang = "en" | "es";

interface LanguageContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  toggle: () => void;
  t: (en: string, es: string) => string;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);

const STORAGE_KEY = "wc-lang";

function getInitialLang(): Lang {
  if (typeof window === "undefined") return "en";
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (saved === "en" || saved === "es") return saved;
  const browser = window.navigator.language?.toLowerCase() ?? "";
  return browser.startsWith("es") ? "es" : "en";
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(getInitialLang);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      /* ignore storage errors (private mode, etc.) */
    }
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = (l: Lang) => setLangState(l);
  const toggle = () => setLangState((prev) => (prev === "en" ? "es" : "en"));
  const t = (en: string, es: string) => (lang === "es" ? es : en);

  return (
    <LanguageContext.Provider value={{ lang, setLang, toggle, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useLanguage() {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error("useLanguage must be used within a LanguageProvider");
  return ctx;
}
