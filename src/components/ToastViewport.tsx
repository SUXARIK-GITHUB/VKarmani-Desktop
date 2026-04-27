import type { ToastItem } from '../types/vpn';

interface ToastViewportProps {
  items: ToastItem[];
}

export function ToastViewport({ items }: ToastViewportProps) {
  return (
    <div className="toast-viewport" aria-live="polite" aria-atomic="true">
      {items.map((item) => (
        <article key={item.id} className={`toast toast-card ${item.tone}`} role="status">
          <strong>{item.title}</strong>
        </article>
      ))}
    </div>
  );
}
