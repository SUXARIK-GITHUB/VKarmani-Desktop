import type { ToastItem } from '../types/vpn';

interface ToastViewportProps {
  items: ToastItem[];
}

export function ToastViewport({ items }: ToastViewportProps) {
  return (
    <div className="toast-viewport" aria-live="polite">
      {items.map((item) => (
        <article key={item.id} className={`toast-card ${item.tone}`}>
          <strong>{item.title}</strong>
        </article>
      ))}
    </div>
  );
}
