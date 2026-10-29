import screensFile from "../shared/screens.json";

export type Screen = {
  id: string;
  path: string;
  label: string;
  icon: string;
  group: string;
  look: string;
  milestone: string;
  mockup: string | null;
  summary: string;
};

export const screens = screensFile.screens as Screen[];
export const screenGroups: string[] = screensFile.groups;

export function screenForPath(pathname: string): Screen | undefined {
  const clean = pathname.replace(/\/+$/, "") || "/";
  return screens.find((screen) => screen.path === clean);
}

export function screenById(id: string): Screen | undefined {
  return screens.find((screen) => screen.id === id);
}
