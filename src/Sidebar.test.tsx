// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Sidebar } from "./Sidebar.tsx";
import { mergeAppearance } from "./looks/looks.ts";
import { screenById, screens } from "./screens.ts";

afterEach(cleanup);

describe("the sidebar for the household (M37)", () => {
  it("shows the household only the screens its password opens, and says it is looking only", () => {
    const appearance = mergeAppearance({}, {});
    const current = screenById("overview") ?? screens[0];
    const owner = render(<Sidebar appearance={appearance} current={current} onSignedOut={() => {}} />);
    expect(owner.container.querySelectorAll("a.nav")).toHaveLength(screens.length);
    cleanup();
    const household = render(<Sidebar appearance={appearance} current={current} role="household" onSignedOut={() => {}} />);
    const labels = [...household.container.querySelectorAll("a.nav")].map((a) => (a.textContent ?? "").replace(a.querySelector(".icon")?.textContent ?? "", "").trim());
    expect(labels).toEqual(["Overview", "Checks", "Fleet", "This device", "Ad exposure"]);
    expect(household.container.textContent).toContain("looking only");
  });
});
