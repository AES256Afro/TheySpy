export function parseColor(value: string): [number, number, number, number];
export function over(top: string, bottom: string): string;
export function mix(a: string, pct: number, b: string): string;
export function contrast(a: string, b: string): number;
export function lookContrastFailures(look: { id: string; tokens: Record<string, string>; background?: string }): { pair: string; ratio: number; needs: number }[];
