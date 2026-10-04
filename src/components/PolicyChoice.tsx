import { useRef } from 'react';
import '../styles/policyControls.css';

interface PolicyChoiceProps<T extends string> {
  label: string;
  value: T;
  options: ReadonlyArray<{ value: T; label: string }>;
  onChange: (value: T) => void;
  disabled?: boolean;
}

// Local segmented control: native button behavior, one tab stop, arrow navigation.
export function PolicyChoice<T extends string>({ label, value, options, onChange, disabled = false }: PolicyChoiceProps<T>) {
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);
  return <div className="vk-policy-choice" role="radiogroup" aria-label={label} aria-disabled={disabled || undefined}>
    {options.map((option, index) => <button key={option.value} ref={element => { buttons.current[index] = element; }} type="button" role="radio"
      aria-checked={value === option.value} tabIndex={value === option.value ? 0 : -1} disabled={disabled}
      className={value === option.value ? 'active' : ''} onClick={() => onChange(option.value)}
      onKeyDown={event => {
        let next: number;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % options.length;
        else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index + options.length - 1) % options.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = options.length - 1;
        else return;
        event.preventDefault(); onChange(options[next].value); buttons.current[next]?.focus();
      }}>{option.label}</button>)}
  </div>;
}
