# TheySpy guide

How to set TheySpy up, roll it out to your devices, and read what it tells you.

## 1. Install

**On BoxPilot.** Find TheySpy in the App catalog and install it. BoxPilot generates the owner password and the session secret, and shows both on the app's card. It also:
- backs TheySpy up before every update;
- rolls back an update whose health check fails;
- can update it on a schedule: Automations → "Update every app that has an update".

**On its own.** On any machine with Docker (amd64 or arm64, so a Raspberry Pi beside Pi-hole works):

```bash
docker compose up -d
```

Open `http://<that machine>:8797` and sign in. Without `TS_ADMIN_PASSWORD`, the first start prints a password once (`docker compose logs theyspy`). Put `TS_SESSION_SECRET` in `.env` too. Stored passwords are sealed with it, so keep it with your backups.

## 2. Connect Pi-hole

TheySpy needs Pi-hole 6.

1. In Pi-hole: Settings → Web interface / API → **App password** → create one.
2. In TheySpy: **Pi-hole Sentinel** → enter Pi-hole's address, for example `http://192.168.1.2`. Leave off `/admin`; TheySpy strips it if you paste it.
3. Paste the app password, then press **Save and test**. TheySpy then:
   - can hunt Pi-hole's history (choose the hunt window);
   - watches new queries every 30 seconds.
4. *Optional:* allow TheySpy to change Pi-hole. Nothing changes until you press a button, and every change can be undone.
   - **Add missing indicators** blocks the spyware domains your lists miss.
   - **Subscribe** adds TheySpy's compiled lists (Blocklist library).
   - **Baselines** apply a blocking level per device.

On **Fleet**, devices Pi-hole already knows are marked **in Pi-hole**. **Trust all** next to that count marks them known in one step, so only new devices raise alerts.

## 3. Alerts and the weekly briefing

**Briefing** → ntfy:
1. Enter your ntfy server and topic.
2. Press **Send a test**.

You then get a message for:
- a new device;
- an indicator lookup;
- an exploited CVE on software you run;
- an agent finding;
- Pi-hole going unreachable;
- a held blocklist update.

The briefing arrives every Monday morning. API tokens for other tools (read-only `/api/v1` and MCP) are created on the same screen.

## 4. Computers: the agent

**Evidence locker** → **Add a computer** gives you three commands for that machine (Python 3.9+ on Windows, macOS or Linux):

```bash
curl -fsSLo theyspy-agent.py http://theyspy:8797/agent/theyspy-agent.py
```

```bash
python3 theyspy-agent.py enroll http://theyspy:8797 tse_…
```

```bash
python3 theyspy-agent.py run
```

Schedule the last one daily, with cron (Linux), launchd (macOS) or Task Scheduler (Windows; use `py`). The agent:
- downloads zero-breach's scanner and checks it against the hash TheySpy verified from the signed release;
- runs it unmodified: it only reads, and never contacts an indicator;
- reports the OS and browser versions, so their CVEs are matched.

To roll the agent out to many machines, create one enrollment per machine; each token works once. Revoke a machine on the same screen.

## 5. Phones: MVT

Phones cannot run the agent. Use Amnesty's [Mobile Verification Toolkit](https://docs.mvt.re):
1. Export TheySpy's indicators as STIX (Indicators → Export).
2. Run MVT against an iPhone backup or an Android device with that file.
3. Import MVT's `*_detected.json` files in **Evidence locker → Phones**.
4. Record what the phone runs (system, browser, ad ID) so its CVEs and exposure are counted.

## 6. What a finding means

| You see | It means | Do this |
| --- | --- | --- |
| **Indicator lookup** (Pi-hole) | A device asked DNS for a domain used to deliver spyware or track through ads. Blocked lookups are still shown | One lookup is often an ad that tried to load. Repeated lookups, or lookups Pi-hole did not block, deserve a closer look: run the agent or MVT on that device |
| **Contacted** (agent or MVT) | The device holds a trace of an indicator: a history entry, a cache file, a process | Strong evidence, not proof of infection. Keep the device as it is and export the STIX file. See section 7 |
| **Gap** | A check could not run (no permission, a browser not found, `--quick`) | Never read as clean. Fix the cause and run again |
| **Exploited CVE / zero-day** | Software on a device has a bug attackers are using now (CISA KEV, or a vendor saying so) | Update to the version shown. These come first for a reason |
| **New device** | Something joined the network | Name it and trust it, or find out what it is |
| **Exposure score** | How much of the ad-targeting surface is closed on that device, from live checks | Follow each check's fix; the hardening kits do most of them at once |

## 7. When to get help

If a device shows a **contacted** finding, especially on a phone, and you are a journalist, activist, lawyer, or otherwise at risk:
- Don't wipe or update the device yet: it removes the evidence experts need.
- Contact **Access Now's Digital Security Helpline** (accessnow.org/help). It is free and works around the clock in many languages.
- Or contact **Amnesty International's Security Lab** (securitylab.amnesty.org) or **Citizen Lab** (citizenlab.ca).
- Share the STIX file and the MVT output. Don't send the device's full backup unless they ask for it.

## 8. Backups and restore

| Where | How to back up | How to restore |
| --- | --- | --- |
| **BoxPilot** | Each update makes a backup; the app's card also offers **Back up now**. Either way, BoxPilot stops TheySpy, archives `/data` and the settings, then starts it again | Pick a backup on the card |
| **Standalone** | **Activity → Download a backup**: a checked copy of the database, taken while TheySpy runs | Stop TheySpy, put the file in place of `data/theyspy.db`, and start it with the same `TS_SESSION_SECRET` |

With a different `TS_SESSION_SECRET`, the restore still works, but stored passwords (Pi-hole, ntfy) must be entered again.

CI runs the full cycle against the real image on every change: stop, archive, wipe, restore, then check that settings, tokens, devices and findings came back.
