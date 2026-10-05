import { useCallback, useEffect, useRef, useState } from 'react';
import { activeSettingsSection, settingsScrollTarget } from '../utils/settingsNavigation';

export function useSettingsNavigation<T extends string>(ids: readonly T[]) {
  const containerRef = useRef<HTMLDivElement>(null);
  const navRef = useRef<HTMLDivElement>(null);
  const [activeSection, setActiveSection] = useState(ids[0]);
  const lock = useRef<T | null>(null);
  const measureRef = useRef<(() => { sections: { id: T; top: number }[]; offset: number }) | null>(null);
  const updateRef = useRef<(() => void) | null>(null);

  const navigate = useCallback((id: T) => {
    const container = containerRef.current, geometry = measureRef.current?.();
    const section = geometry?.sections.find(item => item.id === id);
    if (!container || !geometry || !section) return;
    lock.current = id;
    setActiveSection(current => current === id ? current : id);
    const top = settingsScrollTarget(section.top, geometry.offset, container.scrollHeight - container.clientHeight);
    const alreadyThere = Math.abs(container.scrollTop - top) <= 1;
    container.scrollTo({ top, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
    if (alreadyThere) lock.current = null;
    updateRef.current?.();
  }, []);

  useEffect(() => {
    const container = containerRef.current, nav = navRef.current;
    if (!container || !nav) return;
    const supportsScrollEnd = Reflect.has(container, 'onscrollend');
    const sections = ids.flatMap(id => {
      const element = container.querySelector<HTMLElement>(`#settings-${id}`);
      return element ? [{ id, element }] : [];
    });
    let frame: number | null = null;
    const measure = () => {
      const origin = container.getBoundingClientRect().top + container.clientTop;
      // The gap is the existing section grid spacing; the sticky height is measured.
      const grid = container.querySelector('.settings-redesign-grid');
      const gap = grid ? parseFloat(getComputedStyle(grid).rowGap) || 0 : 0;
      const inset = parseFloat(getComputedStyle(container).paddingTop) || 0;
      const offset = nav.getBoundingClientRect().height + gap + inset;
      return { offset, sections: sections.map(({ id, element }) => ({ id, top: element.getBoundingClientRect().top - origin + container.scrollTop })) };
    };
    const update = () => {
      if (frame !== null) return;
      frame = requestAnimationFrame(() => {
        frame = null;
        const geometry = measure();
        if (lock.current) {
          // Current WebView/Chromium emits scrollend. Older engines use geometric
          // arrival, preserving the chosen section on that frame (no timer).
          if (!supportsScrollEnd) {
            const section = geometry.sections.find(item => item.id === lock.current);
            const goal = section && settingsScrollTarget(section.top, geometry.offset, container.scrollHeight - container.clientHeight);
            if (goal !== undefined && Math.abs(container.scrollTop - goal) <= 1) lock.current = null;
          }
          return;
        }
        const next = activeSettingsSection(geometry.sections, container.scrollTop, geometry.offset, container.scrollHeight - container.clientHeight);
        if (next) setActiveSection(current => current === next ? current : next);
      });
    };
    const interrupt = (event: Event) => {
      if (event instanceof KeyboardEvent && !['PageDown','PageUp','Home','End','ArrowDown','ArrowUp',' '].includes(event.key)) return;
      // Text/radio keys belong to controls; PageUp/Down/Home/End on ordinary
      // navigation buttons still scroll and must cancel a smooth-scroll lock.
      if (event instanceof KeyboardEvent && event.target instanceof HTMLElement) {
        if (event.target.closest('input,textarea,[role="radiogroup"]')) return;
        if (event.key === ' ' && event.target.closest('button')) return;
      }
      lock.current = null; update();
    };
    const resize = () => {
      if (lock.current) navigate(lock.current);
      update();
    };
    const scrollEnd = () => {
      if (lock.current) { lock.current = null; return; }
      update();
    };
    measureRef.current = measure; updateRef.current = update;
    const observer = new ResizeObserver(resize);
    observer.observe(container); observer.observe(nav); sections.forEach(section => observer.observe(section.element));
    container.addEventListener('scroll', update, { passive: true });
    container.addEventListener('scrollend', scrollEnd);
    container.addEventListener('wheel', interrupt, { passive: true });
    container.addEventListener('pointerdown', interrupt, { passive: true });
    container.addEventListener('keydown', interrupt);
    resize();
    return () => {
      observer.disconnect();
      container.removeEventListener('scroll', update); container.removeEventListener('scrollend', scrollEnd); container.removeEventListener('wheel', interrupt);
      container.removeEventListener('pointerdown', interrupt); container.removeEventListener('keydown', interrupt);
      if (frame !== null) cancelAnimationFrame(frame);
      measureRef.current = null; updateRef.current = null; lock.current = null;
    };
  }, [ids, navigate]);
  return { containerRef, navRef, activeSection, navigate };
}
