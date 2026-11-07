import screensFile from "../shared/screens.json";

export type Screen = {
  id: string;
  path: string;
  label: string;
  icon: string;
  group: string;
  look: string;
  summary: string;
};

export const screens = screensFile.screens as Screen[];
export const screenGroups: string[] = screensFile.groups;
/** The five screens the short sidebar shows; the rest go under More. */
export const screenPlaces: string[] = screensFile.places;

export function screenForPath(pathname: string): Screen | undefined {
  const clean = pathname.replace(/\/+$/, "") || "/";
  return screens.find((screen) => screen.path === clean);
}

export function screenById(id: string): Screen | undefined {
  return screens.find((screen) => screen.id === id);
}
