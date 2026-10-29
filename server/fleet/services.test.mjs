import http from "node:http";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { checkPort, checkPorts, identify, profiles } from "./services.mjs";

const servers = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); });
const listen = (server) => new Promise((resolve) => { servers.push(server); server.listen(0, "127.0.0.1", () => resolve(/** @type {any} */ (server.address()).port)); });

describe("port checks", () => {
  it("names products from banners and Server headers", () => {
    expect(identify("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")).toEqual({ product: "OpenSSH", version: "9.6p1" });
    expect(identify("nginx/1.24.0")).toEqual({ product: "nginx", version: "1.24.0" });
    expect(identify("Apache/2.4.58 (Ubuntu)")).toEqual({ product: "Apache httpd", version: "2.4.58" });
    expect(identify("220 (vsFTPd 3.0.5)")).toEqual({ product: "vsftpd", version: "3.0.5" });
    expect(identify("AirTunes/1005.13.1")).toEqual({ product: "AirPlay receiver", version: "1005.13.1" });
    expect(identify("RFB 003.889\n")).toEqual({ product: "VNC server (RFB)", version: "003.889" });
    expect(identify("something else")).toBeNull();
    expect(profiles.deep.ports.length).toBeGreaterThan(1024);
    expect(profiles.standard.ports).toContain(5555);
  });

  it("reads what a real server says: an SSH banner, an HTTP Server header, nothing from a closed port", async () => {
    const ssh = await listen(net.createServer((socket) => socket.end("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")));
    const web = await listen(http.createServer((_req, res) => { res.setHeader("Server", "nginx/1.24.0"); res.end(); }));
    const closed = await listen(net.createServer());
    servers.at(-1).close();
    expect(await checkPort("127.0.0.1", ssh)).toMatchObject({ port: ssh, product: "OpenSSH", version: "9.6p1", banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3" });
    expect(await checkPort("127.0.0.1", web)).toMatchObject({ product: "nginx", version: "1.24.0", banner: "nginx/1.24.0", service: "http" });
    expect(await checkPort("127.0.0.1", closed)).toBeNull();
    const open = await checkPorts("127.0.0.1", [closed, web, ssh]);
    expect(open.map((o) => o.port)).toEqual([ssh, web].sort((a, b) => a - b));
  });
});
