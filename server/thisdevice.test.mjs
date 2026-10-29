import { describe, expect, it } from "vitest";
import { identifyBrowser } from "./thisdevice.mjs";

const chromeUa = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const safariUa = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";

describe("This device: reading the browser", () => {
  it("takes Chrome's exact version from Client Hints, and the OS version too", () => {
    const r = identifyBrowser({ userAgent: chromeUa, uaData: { platform: "macOS", platformVersion: "15.6.1", fullVersionList: [{ brand: "Not=A?Brand", version: "24.0.0.0" }, { brand: "Chromium", version: "141.0.7390.54" }, { brand: "Google Chrome", version: "141.0.7390.54" }] } });
    expect(r).toEqual({ browser: { name: "Chrome", vendor: "google", product: "chrome", version: "141.0.7390.54", exact: true, source: "Client Hints" }, os: "macOS 15.6" });
  });

  it("says when a version cannot be read exactly: Chrome's reduced user agent and Safari (M6 exit criterion)", () => {
    expect(identifyBrowser({ userAgent: chromeUa }).browser).toMatchObject({ version: "141.0.0.0", exact: false });
    expect(identifyBrowser({ userAgent: safariUa })).toMatchObject({ browser: { name: "Safari", exact: false }, os: "macOS (version hidden by the browser)" });
    expect(identifyBrowser({ userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0" }).browser).toMatchObject({ name: "Firefox", version: "144.0", exact: true });
    expect(identifyBrowser({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", uaData: { platform: "Windows", platformVersion: "15.0.0", fullVersionList: [{ brand: "Microsoft Edge", version: "141.0.3537.71" }] } })).toMatchObject({ browser: { name: "Edge", product: "edge_chromium" }, os: "Windows 11" });
  });
});
