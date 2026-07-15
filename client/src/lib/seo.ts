import { useEffect } from "react";

/**
 * Lightweight per-route SEO for this SPA. Sets the document title, meta
 * description, and canonical link on mount, and restores the base title on
 * unmount. Use on each page component.
 */
export function useDocumentMeta(opts: { title: string; description?: string; path?: string }) {
  useEffect(() => {
    window.scrollTo(0, 0);
    const prevTitle = document.title;
    document.title = opts.title;

    let descEl: HTMLMetaElement | null = null;
    if (opts.description) {
      descEl = document.querySelector('meta[name="description"]');
      if (!descEl) {
        descEl = document.createElement("meta");
        descEl.setAttribute("name", "description");
        document.head.appendChild(descEl);
      }
      descEl.setAttribute("content", opts.description);
    }

    let canonical: HTMLLinkElement | null = null;
    if (opts.path) {
      canonical = document.querySelector('link[rel="canonical"]');
      if (!canonical) {
        canonical = document.createElement("link");
        canonical.setAttribute("rel", "canonical");
        document.head.appendChild(canonical);
      }
      canonical.setAttribute("href", `https://whistlecleantexas.com${opts.path}`);
    }

    return () => {
      document.title = prevTitle;
    };
  }, [opts.title, opts.description, opts.path]);
}
