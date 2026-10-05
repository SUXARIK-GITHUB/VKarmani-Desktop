export interface SectionPosition<T extends string> { id: T; top: number }

export function activeSettingsSection<T extends string>(sections: SectionPosition<T>[], scrollTop: number, activationOffset: number, maximum?: number): T | undefined {
  if (maximum !== undefined && maximum > 0 && scrollTop >= maximum - 1) return sections[sections.length-1]?.id;
  let active = sections[0]?.id;
  for (const section of sections) if (section.top <= scrollTop + activationOffset + 1) active = section.id;
  return active;
}

export function settingsScrollTarget(sectionTop: number, activationOffset: number, maximum: number) {
  return Math.max(0, Math.min(maximum, sectionTop - activationOffset));
}
