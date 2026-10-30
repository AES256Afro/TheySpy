#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zero Breach (single-file build) - local check for published AdFection /
Candiru spyware indicators.

WHAT THIS IS
  A read-only checker. It searches this computer's own leftover records -
  browser cache and cookies, file fingerprints, auto-start registrations, the
  DNS resolver cache - for 405 indicators published by The Citizen Lab,
  Confiant, Recorded Future, Microsoft, ESET, Avast / Gen, Google TAG and
  Amnesty Security Lab. The original citations are embedded.

WHAT IT WILL NOT DO
  - It does not change source files, registry entries or system settings.
    It writes temporary database snapshots and embedded indicator data,
    removes those after use, and retains a report only when requested.
  - It makes no intentional network requests or indicator lookups. Redirected
    paths and Windows remote drives are skipped; POSIX network mounts can
    appear local and may be read. Authenticode checks are disabled.
    Python network calls are blocked during the scan. This guard is not an
    operating-system network sandbox.
  - It does not decrypt credentials. Cookie queries select metadata, not
    cookie values; temporary snapshots copy the entire source database.

IMPORTANT - WHAT A CLEAN RESULT MEANS
  "No known indicators found" means exactly that, and nothing more. It is not
  a clean bill of health. Spyware of this grade is built to defeat this class
  of check, most of the evidence it would leave expires within weeks, and
  Windows does not record DNS history unless someone turned it on. If you have
  real reason for concern, the answer is expert help, not this script:
    Access Now Digital Security Helpline  https://www.accessnow.org/help/
    Amnesty International Security Lab    https://securitylab.amnesty.org/
    The Citizen Lab                       https://citizenlab.ca/

LICENCE
  Software: Apache License 2.0. Indicator data: CC0 1.0 (public domain).
  Optional Candiru rules retain their separate DRL 1.1 / CC BY-SA 4.0
  licences and author credits, embedded below with their provenance.
  Copyright 2026 archivegenocide.com. Provided AS IS, without warranty.
  Full text, and the sources every indicator came from:
    https://github.com/interplains/zero-breach
  NOT affiliated with, and NOT endorsed by, The Citizen Lab, Confiant,
  Recorded Future, Amnesty International or Access Now.

USAGE
  python -X utf8 zero-breach.py
  python -X utf8 zero-breach.py --json report.json
  python -X utf8 zero-breach.py --patterns   # optional YARA-X setup required

Requires Python 3.8 or newer. Needs no administrator. All supported platforms
get browser and file checks; Windows also gets host checks.
Experimental --patterns also requires Python 3.9+ and yara-x==1.21.0.
"""
from __future__ import annotations

import argparse
import datetime
import sys
import time

__version__ = "0.1.8 (single-file build)"

# --- embedded indicator data ------------------------------------------------
# The real file is iocs/adfection_iocs.txt in the project. Its provenance
# comments are kept verbatim so every indicator can be traced to its report.
IOC_BUILD_EPOCH = 1792281600.0  # the IOC set's "as-of" date (deterministic)
IOC_DATA = r'''
# AdFection / Discover-Tech / Candiru - indicators of compromise
#
# as-of: 2026-10-18
# ^ The date this indicator set was last curated. It is the tool's staleness
#   reference AND it makes the single-file build reproducible: the build embeds
#   THIS date, not the file's modification time, so anyone can rebuild the
#   standalone from a fresh checkout and get a byte-identical file. Update this
#   line (and only deliberately) whenever the indicators below change.
#
# Source: The Citizen Lab, "Exposing AdFection: How Discover-Tech Turned Targeted Ads
# Into a Pipeline for Zero-Click Mercenary Spyware", published 2026-10-15.
# https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/
# Companion: Confiant, "ADINT: Weaponized Ad Tech for Zero-Click Spyware and Mass
# Identity Vacuuming" (same date).
#
# Extended 2026-10-18 from the report's own Appendix C ("Domains linked to Discover-Tech
# and Controlium") and its body text. Every line below was read out of the report itself
# and cross-checked by two independent reads of the page before being added.
#
# Format: indicator <TAB> tier <TAB> confidence <TAB> source-tag
#   tier       = cc | validator | delivery | historical | sample | vuln-driver
#                | candiru | candiru-ip
#                (`sample` = the spyware itself; `vuln-driver` = legitimate signed
#                 software this actor abuses - a match is a lead, never proof)
#   confidence = primary   (read from the cited current-campaign primary report)
#                secondary (from a third-party summary of that report, OR from a
#                           primary report of a separate/older campaign - verify
#                           currency before acting; the source column says which)
#
# The indicator TYPE is inferred from its shape: 64 hex chars -> SHA-256,
# dotted quad -> IP, otherwise -> domain. Scope is Candiru / DevilsTongue and
# its AdFection delivery infrastructure; other spyware vendors are not imported.
# Scanner evidence is distinct from live blocklist membership: the denylist
# emitter excludes bare adtimizer.co while keeping named operational subhosts.
#
# Appendix C lists its entries as wildcards (`*.controlium[.]net`). Matching here is
# case-insensitive boundary matching, so a registrable domain matches its subdomains
# automatically. Named subdomains are kept anyway, because knowing WHICH endpoint was
# contacted is worth more than a bare domain hit when someone has to triage it.
#
# IMPORTANT, from the report itself: an ad impression from this infrastructure in your
# logs is NOT proof of infection. Not every ad carried a payload, and the validator
# server decided per-device whether to continue. A hit here means "investigate", never
# "you are compromised".
#
# ---------------------------------------------------------------------------------
# DELIBERATELY NOT IMPORTED
#
# 1. The validator server set. The report states verbatim: "In all, we found 305
#    distinct domain names on 319 IP addresses" - but it does NOT publish that list.
#    Only the two below are named. So this file carries 2 of 305 validator domains and
#    none of the 319 IPs, and that gap CANNOT be closed from the public report. It is
#    the single largest known hole in this data set. Anyone with access to the full set
#    (Citizen Lab, Sekoia and Recorded Future are named as having attributed some of
#    them) could close it.
# 2. Discover-Tech's own corporate websites (intelos.io, tekma.io, tekma-dmp.ai, and
#    the shared Wix account linking them). These appear in the report as ATTRIBUTION
#    evidence - they are how the companies were tied together - not as attack
#    infrastructure. Matching them would flag anyone who merely read about the company,
#    which is a false positive, not a finding.
# 3. 10.0.0.52 (an internal address seen in login records, explicitly not infrastructure)
#    and 62.90.129.xxx (redacted in the source, so unusable).
# ---------------------------------------------------------------------------------
#
# Candiru command-and-control. These four matched the report's C&C "Fingerprint C1".
fearevolve.com	cc	primary	citizenlab-adfection-2026
jobmarcher.com	cc	primary	citizenlab-adfection-2026
insightenterprisells.com	cc	primary	citizenlab-adfection-2026
plasticbells.com	cc	primary	citizenlab-adfection-2026
#
# Two further Fingerprint C1 domains, registered within two hours of each other on
# 2025-03-18.
outdooutcome.com	cc	primary	citizenlab-adfection-2026
suggestutterly.com	cc	primary	citizenlab-adfection-2026
#
# An IP that matched the same fingerprint, plus the two shared-hosting hostnames the
# report says pointed at it. The hostnames are specific enough to match safely; the
# IP is an Azure address, so note that cloud IPs get reassigned to innocent tenants
# over time - treat an IP-only hit as weaker than a domain hit.
52.174.65.77	cc	primary	citizenlab-adfection-2026
archer.westeurope.cloudapp.azure.com	cc	primary	citizenlab-adfection-2026
bd-mainserver.herokuapp.com	cc	primary	citizenlab-adfection-2026
#
# Candiru validator servers (device profiling / target selection).
# Only these two are named in the report. See "DELIBERATELY NOT IMPORTED" above: the
# other 303 domains and all 319 IPs are counted in the report but never listed.
keyadapter.com	validator	primary	citizenlab-adfection-2026
sharethere.net	validator	primary	citizenlab-adfection-2026
#
# Discover-Tech / Controlium infrastructure - Appendix C, "General".
discover-tech.io	delivery	primary	citizenlab-adfection-2026
mtrtb.com	delivery	primary	citizenlab-adfection-2026
mydsp.io	delivery	primary	citizenlab-adfection-2026
controlium.net	delivery	primary	citizenlab-adfection-2026
powerium.net	delivery	primary	citizenlab-adfection-2026
platc-tester.com	delivery	primary	citizenlab-adfection-2026
myweb3id.io	delivery	primary	citizenlab-adfection-2026
myipinfo.io	delivery	primary	citizenlab-adfection-2026
akedo.gg	delivery	primary	citizenlab-adfection-2026
volasim.com	delivery	primary	citizenlab-adfection-2026
#
# Appendix C, "NOAS Servers" - the ad-serving endpoints (the report lists these with a
# /getAd or /cplatform/getAd path; the host is what is matchable in local artifacts).
noas.mtrtb.com	delivery	primary	citizenlab-adfection-2026
infinoas.mtrtb.com	delivery	primary	citizenlab-adfection-2026
ppv2.mtrtb.com	delivery	primary	citizenlab-adfection-2026
pqv2.mtrtb.com	delivery	primary	citizenlab-adfection-2026
events.platc-tester.com	delivery	primary	citizenlab-adfection-2026
events.myweb3id.io	delivery	primary	citizenlab-adfection-2026
noas.powerium.net	delivery	primary	citizenlab-adfection-2026
qa-noas.powerium.net	delivery	primary	citizenlab-adfection-2026
noas.adtimizer.co	delivery	primary	citizenlab-adfection-2026
noas.impchkdsp.com	delivery	primary	citizenlab-adfection-2026
noas.trakking.co	delivery	primary	citizenlab-adfection-2026
#
# Appendix C, "Ad Tracking Domains".
tracookiepixel.xyz	delivery	primary	citizenlab-adfection-2026
cookiesurfer.com	delivery	primary	citizenlab-adfection-2026
cookie-sync.xyz	delivery	primary	citizenlab-adfection-2026
ads-monitor.xyz	delivery	primary	citizenlab-adfection-2026
checkmyimp.com	delivery	primary	citizenlab-adfection-2026
ads-impressions.com	delivery	primary	citizenlab-adfection-2026
nutralove.co	delivery	primary	citizenlab-adfection-2026
#
# Further delivery infrastructure named in the report body.
adtimizer.co	delivery	primary	citizenlab-adfection-2026
dtech.adtimizer.co	delivery	primary	citizenlab-adfection-2026
tracker.mtrtb.com	delivery	primary	citizenlab-adfection-2026
sincereaccertain.com	delivery	primary	citizenlab-adfection-2026
d1fcoizt7mje85.cloudfront.net	delivery	primary	citizenlab-adfection-2026
discovertech-alb-100966113.us-east-1.elb.amazonaws.com	delivery	primary	citizenlab-adfection-2026
#
# Candiru infrastructure from the 2021 "Hooking Candiru" report - a SEPARATE, older
# campaign. Included because a hit would still be significant, not because it is part
# of AdFection.
msstore.io	historical	primary	citizenlab-adfection-2026
adtracker.link	historical	primary	citizenlab-adfection-2026
cdnmobile.io	historical	primary	citizenlab-adfection-2026
185.181.8.155	historical	primary	citizenlab-adfection-2026
#
# Known sample - the one Candiru Windows DLL published for this campaign.
# SHA-256 of the DLL delivered through Discover-Tech ads (Citizen Lab, 2026-10-15).
# This is ONE build. Another victim's DLL is compiled differently and will not match,
# so a clean hash result is close to meaningless on its own - it is here because a
# match would be conclusive, not because a miss is reassuring.
255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8	sample	primary	citizenlab-adfection-2026
#
# ---------------------------------------------------------------------------------
# SECOND SOURCE: Recorded Future, Insikt Group, "Tracking Candiru's DevilsTongue
# Spyware in Multiple Countries" (CTA-2025-0805), published 2025-08-05.
# https://www.recordedfuture.com/research/tracking-candirus-devilstongue-spyware
# Imported 2026-10-18 from that report's Appendix A, transcribed by script rather
# than by hand so a typo cannot invent a domain.
#
# WHY THIS IS HERE: the Citizen Lab report says its 305-domain validator set
# "includes ones publicly attributed to Candiru by Sekoia, as well as Recorded
# Future". This is that Recorded Future set. It does NOT recover the 305 (see
# VALIDATOR-GAP.md), but it is the largest body of independently-attributed
# Candiru infrastructure that is actually published.
#
# CROSS-VALIDATION, and the reason to trust this import: four domains in this
# appendix - fearevolve.com, jobmarcher.com, outdooutcome.com, suggestutterly.com -
# were ALREADY in this file from the Citizen Lab report, where they are named as
# command-and-control servers. And the DevilsTongue SHA-256 in this appendix is
# byte-identical to the AdFection sample hash below. Two vendors, 14 months apart,
# describing the same infrastructure and the same binary.
#
# TIER CHOICE: Recorded Future describes eight clusters mixing victim-facing C2
# with higher-tier operator infrastructure, and does not say which domain is
# which. Filing them as `cc` would claim precision the source does not give, so
# they are `candiru` = "Candiru-attributed, role unspecified". A hit is serious.
#
# THE IPs ARE WEAKER THAN THE DOMAINS, deliberately tiered apart as `candiru-ip`.
# Nearly all are Vultr / DigitalOcean addresses from a report dated 2025-08. Cloud
# IPs get reassigned to unrelated, innocent tenants within months. An undated hit
# on one of these is far more likely to be a coincidence than a finding; it is
# only meaningful if the hit carries a DATE inside the period (a DNS log entry,
# say). Do not treat an IP hit as evidence on its own.
# ---------------------------------------------------------------------------------
ambiguouscommerce.com	candiru	primary	recordedfuture-2025-08
antperspective.com	candiru	primary	recordedfuture-2025-08
aperturebelt.com	candiru	primary	recordedfuture-2025-08
asknapkin.com	candiru	primary	recordedfuture-2025-08
barnsecret.com	candiru	primary	recordedfuture-2025-08
baseagriculture.com	candiru	primary	recordedfuture-2025-08
basicstraw.com	candiru	primary	recordedfuture-2025-08
basinapposite.com	candiru	primary	recordedfuture-2025-08
beneathbreadth.com	candiru	primary	recordedfuture-2025-08
bizarreclassify.com	candiru	primary	recordedfuture-2025-08
blockroster.net	candiru	primary	recordedfuture-2025-08
bondmuscle.com	candiru	primary	recordedfuture-2025-08
breadgroomer.com	candiru	primary	recordedfuture-2025-08
bronzemonth.com	candiru	primary	recordedfuture-2025-08
browniebell.com	candiru	primary	recordedfuture-2025-08
bypassbirch.com	candiru	primary	recordedfuture-2025-08
bypasscalculate.com	candiru	primary	recordedfuture-2025-08
bypasscommerce.com	candiru	primary	recordedfuture-2025-08
calmbase.org	candiru	primary	recordedfuture-2025-08
cartoondrop.net	candiru	primary	recordedfuture-2025-08
chickenstrawberry.com	candiru	primary	recordedfuture-2025-08
citecivilization.com	candiru	primary	recordedfuture-2025-08
closetmeat.com	candiru	primary	recordedfuture-2025-08
commonclever.com	candiru	primary	recordedfuture-2025-08
concretebottle.com	candiru	primary	recordedfuture-2025-08
conquerconfess.com	candiru	primary	recordedfuture-2025-08
containsnow.com	candiru	primary	recordedfuture-2025-08
contradictionblindness.com	candiru	primary	recordedfuture-2025-08
convincechaotic.com	candiru	primary	recordedfuture-2025-08
cooperatedisinfect.net	candiru	primary	recordedfuture-2025-08
cottonbread.com	candiru	primary	recordedfuture-2025-08
cranberrybear.com	candiru	primary	recordedfuture-2025-08
cropcritique.com	candiru	primary	recordedfuture-2025-08
crossoverdue.com	candiru	primary	recordedfuture-2025-08
damageconsider.com	candiru	primary	recordedfuture-2025-08
deardrill.com	candiru	primary	recordedfuture-2025-08
dediccatedconsideration.com	candiru	primary	recordedfuture-2025-08
deducedefend.com	candiru	primary	recordedfuture-2025-08
deliverconcern.net	candiru	primary	recordedfuture-2025-08
densefoot.com	candiru	primary	recordedfuture-2025-08
desireeclipse.com	candiru	primary	recordedfuture-2025-08
detaincharity.net	candiru	primary	recordedfuture-2025-08
deterdiffusion.com	candiru	primary	recordedfuture-2025-08
devotionbelief.com	candiru	primary	recordedfuture-2025-08
distractionfar.com	candiru	primary	recordedfuture-2025-08
drivesplash.com	candiru	primary	recordedfuture-2025-08
drummerjourney.com	candiru	primary	recordedfuture-2025-08
dumplingbell.com	candiru	primary	recordedfuture-2025-08
electric-prime.com	candiru	primary	recordedfuture-2025-08
elifluousscintillam.com	candiru	primary	recordedfuture-2025-08
eminententwine.com	candiru	primary	recordedfuture-2025-08
exhibitexpanse.com	candiru	primary	recordedfuture-2025-08
fallaciousessential.net	candiru	primary	recordedfuture-2025-08
fileswaper.com	candiru	primary	recordedfuture-2025-08
finalsalami.com	candiru	primary	recordedfuture-2025-08
flexibleelevator.com	candiru	primary	recordedfuture-2025-08
foamdirection.com	candiru	primary	recordedfuture-2025-08
forecastgarden.com	candiru	primary	recordedfuture-2025-08
goatsandals.com	candiru	primary	recordedfuture-2025-08
golfconcert.com	candiru	primary	recordedfuture-2025-08
groundbreakinginitative.com	candiru	primary	recordedfuture-2025-08
guitarcalculate.com	candiru	primary	recordedfuture-2025-08
hostilefauna.com	candiru	primary	recordedfuture-2025-08
isolatelecture.com	candiru	primary	recordedfuture-2025-08
jellybat.net	candiru	primary	recordedfuture-2025-08
journeyjest.net	candiru	primary	recordedfuture-2025-08
kartingrumble.com	candiru	primary	recordedfuture-2025-08
labyrinthextravagance.org	candiru	primary	recordedfuture-2025-08
leafconfuse.net	candiru	primary	recordedfuture-2025-08
lessonhandle.com	candiru	primary	recordedfuture-2025-08
macrodrop.net	candiru	primary	recordedfuture-2025-08
macromint.net	candiru	primary	recordedfuture-2025-08
maturitygenesis.com	candiru	primary	recordedfuture-2025-08
measurecabin.com	candiru	primary	recordedfuture-2025-08
mushroompalm.com	candiru	primary	recordedfuture-2025-08
notableexam.org	candiru	primary	recordedfuture-2025-08
notionnowadays.com	candiru	primary	recordedfuture-2025-08
parkourbus.com	candiru	primary	recordedfuture-2025-08
patternperiod.com	candiru	primary	recordedfuture-2025-08
penslice.com	candiru	primary	recordedfuture-2025-08
pepperdominate.com	candiru	primary	recordedfuture-2025-08
prawnbasket.com	candiru	primary	recordedfuture-2025-08
predictproper.com	candiru	primary	recordedfuture-2025-08
pressaviation.com	candiru	primary	recordedfuture-2025-08
profligatecensure.com	candiru	primary	recordedfuture-2025-08
rollstrech.com	candiru	primary	recordedfuture-2025-08
romancedrum.com	candiru	primary	recordedfuture-2025-08
sacrificeprincipal.net	candiru	primary	recordedfuture-2025-08
salmonpride.net	candiru	primary	recordedfuture-2025-08
scoreparade.com	candiru	primary	recordedfuture-2025-08
selectedpazzle.com	candiru	primary	recordedfuture-2025-08
shareitwork.com	candiru	primary	recordedfuture-2025-08
signifyslight.com	candiru	primary	recordedfuture-2025-08
spongefruit.com	candiru	primary	recordedfuture-2025-08
stablesurface.com	candiru	primary	recordedfuture-2025-08
strangegarden.org	candiru	primary	recordedfuture-2025-08
stylebrakedown.com	candiru	primary	recordedfuture-2025-08
sunsetpotential.com	candiru	primary	recordedfuture-2025-08
tacticscheap.net	candiru	primary	recordedfuture-2025-08
tidalscreen.com	candiru	primary	recordedfuture-2025-08
tubeshape.com	candiru	primary	recordedfuture-2025-08
ultimatematter.info	candiru	primary	recordedfuture-2025-08
velvetpremier.com	candiru	primary	recordedfuture-2025-08
windomination.com	candiru	primary	recordedfuture-2025-08
5.181.159.109	candiru-ip	primary	recordedfuture-2025-08
5.252.178.158	candiru-ip	primary	recordedfuture-2025-08
23.29.115.188	candiru-ip	primary	recordedfuture-2025-08
23.227.198.196	candiru-ip	primary	recordedfuture-2025-08
38.132.101.35	candiru-ip	primary	recordedfuture-2025-08
45.32.109.170	candiru-ip	primary	recordedfuture-2025-08
45.32.150.100	candiru-ip	primary	recordedfuture-2025-08
45.76.31.6	candiru-ip	primary	recordedfuture-2025-08
45.76.252.109	candiru-ip	primary	recordedfuture-2025-08
45.77.57.173	candiru-ip	primary	recordedfuture-2025-08
45.77.105.76	candiru-ip	primary	recordedfuture-2025-08
64.225.3.138	candiru-ip	primary	recordedfuture-2025-08
64.226.103.163	candiru-ip	primary	recordedfuture-2025-08
65.20.96.9	candiru-ip	primary	recordedfuture-2025-08
65.20.105.177	candiru-ip	primary	recordedfuture-2025-08
65.20.106.49	candiru-ip	primary	recordedfuture-2025-08
66.42.73.169	candiru-ip	primary	recordedfuture-2025-08
66.42.126.125	candiru-ip	primary	recordedfuture-2025-08
68.183.169.21	candiru-ip	primary	recordedfuture-2025-08
68.183.186.185	candiru-ip	primary	recordedfuture-2025-08
70.34.194.5	candiru-ip	primary	recordedfuture-2025-08
70.34.251.208	candiru-ip	primary	recordedfuture-2025-08
84.247.51.183	candiru-ip	primary	recordedfuture-2025-08
88.119.175.56	candiru-ip	primary	recordedfuture-2025-08
88.119.175.75	candiru-ip	primary	recordedfuture-2025-08
91.207.173.115	candiru-ip	primary	recordedfuture-2025-08
95.179.215.54	candiru-ip	primary	recordedfuture-2025-08
104.207.153.0	candiru-ip	primary	recordedfuture-2025-08
107.170.37.216	candiru-ip	primary	recordedfuture-2025-08
107.170.42.32	candiru-ip	primary	recordedfuture-2025-08
107.170.42.56	candiru-ip	primary	recordedfuture-2025-08
134.209.3.89	candiru-ip	primary	recordedfuture-2025-08
134.209.220.157	candiru-ip	primary	recordedfuture-2025-08
136.244.69.219	candiru-ip	primary	recordedfuture-2025-08
137.184.254.107	candiru-ip	primary	recordedfuture-2025-08
138.197.43.97	candiru-ip	primary	recordedfuture-2025-08
139.59.14.26	candiru-ip	primary	recordedfuture-2025-08
139.84.208.188	candiru-ip	primary	recordedfuture-2025-08
140.82.5.20	candiru-ip	primary	recordedfuture-2025-08
143.198.64.22	candiru-ip	primary	recordedfuture-2025-08
146.70.20.203	candiru-ip	primary	recordedfuture-2025-08
146.70.29.228	candiru-ip	primary	recordedfuture-2025-08
146.70.53.156	candiru-ip	primary	recordedfuture-2025-08
146.70.81.218	candiru-ip	primary	recordedfuture-2025-08
146.70.86.251	candiru-ip	primary	recordedfuture-2025-08
146.70.102.108	candiru-ip	primary	recordedfuture-2025-08
146.70.102.110	candiru-ip	primary	recordedfuture-2025-08
146.70.102.121	candiru-ip	primary	recordedfuture-2025-08
146.70.102.134	candiru-ip	primary	recordedfuture-2025-08
146.70.116.7	candiru-ip	primary	recordedfuture-2025-08
146.70.131.224	candiru-ip	primary	recordedfuture-2025-08
146.70.147.9	candiru-ip	primary	recordedfuture-2025-08
146.70.160.49	candiru-ip	primary	recordedfuture-2025-08
146.70.169.165	candiru-ip	primary	recordedfuture-2025-08
147.182.161.167	candiru-ip	primary	recordedfuture-2025-08
149.28.57.173	candiru-ip	primary	recordedfuture-2025-08
149.28.71.25	candiru-ip	primary	recordedfuture-2025-08
149.28.77.207	candiru-ip	primary	recordedfuture-2025-08
149.28.142.211	candiru-ip	primary	recordedfuture-2025-08
149.28.242.133	candiru-ip	primary	recordedfuture-2025-08
149.28.250.35	candiru-ip	primary	recordedfuture-2025-08
149.28.253.112	candiru-ip	primary	recordedfuture-2025-08
149.248.1.147	candiru-ip	primary	recordedfuture-2025-08
152.42.226.197	candiru-ip	primary	recordedfuture-2025-08
155.138.163.117	candiru-ip	primary	recordedfuture-2025-08
155.138.202.66	candiru-ip	primary	recordedfuture-2025-08
155.138.240.74	candiru-ip	primary	recordedfuture-2025-08
157.230.128.10	candiru-ip	primary	recordedfuture-2025-08
157.245.176.133	candiru-ip	primary	recordedfuture-2025-08
158.247.194.199	candiru-ip	primary	recordedfuture-2025-08
159.89.14.225	candiru-ip	primary	recordedfuture-2025-08
159.223.151.126	candiru-ip	primary	recordedfuture-2025-08
159.223.208.191	candiru-ip	primary	recordedfuture-2025-08
161.35.150.79	candiru-ip	primary	recordedfuture-2025-08
164.92.225.66	candiru-ip	primary	recordedfuture-2025-08
164.92.235.125	candiru-ip	primary	recordedfuture-2025-08
165.22.5.231	candiru-ip	primary	recordedfuture-2025-08
165.22.51.81	candiru-ip	primary	recordedfuture-2025-08
165.22.71.71	candiru-ip	primary	recordedfuture-2025-08
165.227.145.109	candiru-ip	primary	recordedfuture-2025-08
167.99.3.150	candiru-ip	primary	recordedfuture-2025-08
167.99.85.48	candiru-ip	primary	recordedfuture-2025-08
174.138.34.46	candiru-ip	primary	recordedfuture-2025-08
178.128.49.106	candiru-ip	primary	recordedfuture-2025-08
185.234.52.230	candiru-ip	primary	recordedfuture-2025-08
188.208.141.190	candiru-ip	primary	recordedfuture-2025-08
194.37.97.159	candiru-ip	primary	recordedfuture-2025-08
194.180.158.45	candiru-ip	primary	recordedfuture-2025-08
194.180.158.71	candiru-ip	primary	recordedfuture-2025-08
194.180.191.84	candiru-ip	primary	recordedfuture-2025-08
198.211.98.248	candiru-ip	primary	recordedfuture-2025-08
199.247.10.38	candiru-ip	primary	recordedfuture-2025-08
206.81.14.237	candiru-ip	primary	recordedfuture-2025-08
207.246.87.188	candiru-ip	primary	recordedfuture-2025-08
207.246.90.6	candiru-ip	primary	recordedfuture-2025-08
207.246.105.206	candiru-ip	primary	recordedfuture-2025-08
207.246.113.7	candiru-ip	primary	recordedfuture-2025-08
208.76.221.167	candiru-ip	primary	recordedfuture-2025-08
208.76.223.59	candiru-ip	primary	recordedfuture-2025-08
208.85.18.104	candiru-ip	primary	recordedfuture-2025-08
213.252.232.129	candiru-ip	primary	recordedfuture-2025-08
213.252.232.141	candiru-ip	primary	recordedfuture-2025-08
216.128.178.12	candiru-ip	primary	recordedfuture-2025-08
216.238.77.17	candiru-ip	primary	recordedfuture-2025-08
216.238.80.164	candiru-ip	primary	recordedfuture-2025-08
216.238.86.164	candiru-ip	primary	recordedfuture-2025-08
216.238.91.249	candiru-ip	primary	recordedfuture-2025-08
217.69.6.58	candiru-ip	primary	recordedfuture-2025-08
217.69.10.11	candiru-ip	primary	recordedfuture-2025-08

# --- Historical Candiru infrastructure (separate, older campaigns) --------
# Added 2026-10-18 from PRIMARY reports (not news coverage). Attacker-
# controlled infrastructure only; compromised victim sites, real-org look-
# alikes, decayed IPs and SHA-1 hashes were deliberately excluded. A hit is
# tier=historical: significant if dated, but these domains are old and some
# may since have lapsed and been re-registered, so confidence is secondary.
#   eset-swc-2021            ESET, 'Strategic web compromises ... Candiru' (2021-11-16)
#   avast-2022               Avast/Gen, 'The Return of Candiru' (CVE-2022-2294, 2022)
#   citizenlab-candiru-2021  The Citizen Lab, 'Hooking Candiru' (2021-07)
piwiks.com	historical	secondary	eset-swc-2021
static-doubleclick.net	historical	secondary	eset-swc-2021
fonts-gstatic.net	historical	secondary	eset-swc-2021
bootstrapcdn.net	historical	secondary	eset-swc-2021
hotjar.net	historical	secondary	eset-swc-2021
moatads.co	historical	secondary	eset-swc-2021
doubleclick.ac	historical	secondary	eset-swc-2021
code-afsanalytics.com	historical	secondary	eset-swc-2021
site-improve.net	historical	secondary	eset-swc-2021
sitei-mprove.net	historical	secondary	eset-swc-2021
addthis.events	historical	secondary	eset-swc-2021
sherathis.com	historical	secondary	eset-swc-2021
webfx.bz	historical	secondary	eset-swc-2021
webffx.bz	historical	secondary	eset-swc-2021
webfex.bz	historical	secondary	eset-swc-2021
visitortrack.net	historical	secondary	eset-swc-2021
livesession.bid	historical	secondary	eset-swc-2021
livesesion.bid	historical	secondary	eset-swc-2021
engagebay.app	historical	secondary	eset-swc-2021
engagebaay.app	historical	secondary	eset-swc-2021
clickcease.app	historical	secondary	eset-swc-2021
useproof.cc	historical	secondary	eset-swc-2021
yektenet.com	historical	secondary	eset-swc-2021
rebrandly.site	historical	secondary	eset-swc-2021
medica-tradefair.co	historical	secondary	eset-swc-2021
bitly.bz	historical	secondary	eset-swc-2021
bitly.tw	historical	secondary	eset-swc-2021
bitly.zone	historical	secondary	eset-swc-2021
bitly.tel	historical	secondary	eset-swc-2021
bit-ly.site	historical	secondary	eset-swc-2021
tinyurl.ist	historical	secondary	eset-swc-2021
tinyurl.bz	historical	secondary	eset-swc-2021
tinyurl.one	historical	secondary	eset-swc-2021
tinyurl.photos	historical	secondary	eset-swc-2021
tinyurl.plus	historical	secondary	eset-swc-2021
shortlinkcut.link	historical	secondary	eset-swc-2021
cuturl.app	historical	secondary	eset-swc-2021
cuturl.space	historical	secondary	eset-swc-2021
url-tiny.co	historical	secondary	eset-swc-2021
llink.link	historical	secondary	eset-swc-2021
instagrarn.co	historical	secondary	eset-swc-2021
stylishblock.com	historical	secondary	avast-2022
cnn24-7.online	historical	secondary	citizenlab-candiru-2021
dw-arabic.com	historical	secondary	citizenlab-candiru-2021
euro-news.online	historical	secondary	citizenlab-candiru-2021
rasef22.com	historical	secondary	citizenlab-candiru-2021
france-24.news	historical	secondary	citizenlab-candiru-2021
amnestyreports.com	historical	secondary	citizenlab-candiru-2021
blacklivesmatters.info	historical	secondary	citizenlab-candiru-2021
womanstudies.co	historical	secondary	citizenlab-candiru-2021
cortanaupdates.com	historical	secondary	citizenlab-candiru-2021
googlplay.store	historical	secondary	citizenlab-candiru-2021
apple-updates.online	historical	secondary	citizenlab-candiru-2021
amazon-cz.eu	historical	secondary	citizenlab-candiru-2021
drpbx-update.net	historical	secondary	citizenlab-candiru-2021
lenovo-setup.tk	historical	secondary	citizenlab-candiru-2021
konferenciya-zoom.com	historical	secondary	citizenlab-candiru-2021
zcombinator.co	historical	secondary	citizenlab-candiru-2021
linkedin-jobs.com	historical	secondary	citizenlab-candiru-2021
faceb00k-live.com	historical	secondary	citizenlab-candiru-2021
minstagram.net	historical	secondary	citizenlab-candiru-2021
twitt-live.com	historical	secondary	citizenlab-candiru-2021
youtubee.life	historical	secondary	citizenlab-candiru-2021
wikipediaathome.net	historical	secondary	citizenlab-candiru-2021
osesgy-unmissions.org	historical	secondary	citizenlab-candiru-2021
whoint.co	historical	secondary	citizenlab-candiru-2021
vesteldefnce.io	historical	secondary	citizenlab-candiru-2021
pochtarossiy.info	historical	secondary	citizenlab-candiru-2021
kupony-rohlik.cz	historical	secondary	citizenlab-candiru-2021
yeni-safak.com	historical	secondary	citizenlab-candiru-2021
cyprusnet.tk	historical	secondary	citizenlab-candiru-2021
lwaeh-iteham-alasra.com	historical	secondary	citizenlab-candiru-2021
mbsmetoo.com	historical	secondary	citizenlab-candiru-2021
indoprogress.co	historical	secondary	citizenlab-candiru-2021
#
# BRING-YOUR-OWN-VULNERABLE-DRIVER. This is HW.sys / HW64.sys, a LEGITIMATE kernel
# driver signed by Marvin Test Solutions, Inc. (port/memory/PCI access). Candiru
# loads it to disable protections (Avast, 'The Return of Candiru', CVE-2022-2294);
# it is catalogued as an abusable driver by LOLDrivers.
#
# IT IS NOT SPYWARE AND IT IS NOT THIS CAMPAIGN'S PAYLOAD. The same file is present
# on clean machines that legitimately use Marvin Test hardware software. It is tiered
# `vuln-driver`, NOT `sample`, so that a match is reported as something to look at
# rather than as proof of infection. Reporting it as a spyware sample would hand a
# false 'you are infected' to anyone running that hardware - the worst failure this
# tool can have.
6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5	vuln-driver	secondary	avast-2022

# Source: confiant-adint-2026; published 2026-10-15
# https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming
# Exact operational hosts only; the SDK endpoint is delivery-tier JavaScript
# control, not proof of an implant callback. Tracking/ad contact is not infection.
dtech.mtrtb.com	delivery	primary	confiant-adint-2026
tekma.adtimizer.co	delivery	primary	confiant-adint-2026
www.discover-tech.io	delivery	primary	confiant-adint-2026
d8lmy5wyiokrq.cloudfront.net	delivery	primary	confiant-adint-2026
d23625plpxg1yn.cloudfront.net	delivery	primary	confiant-adint-2026
d39619tdxn6mhj.cloudfront.net	delivery	primary	confiant-adint-2026
d2f4zpg1mgzwov.cloudfront.net	delivery	primary	confiant-adint-2026
d1fzw0miu1r9rc.cloudfront.net	delivery	primary	confiant-adint-2026
d19oo8r6k9oumb.cloudfront.net	delivery	primary	confiant-adint-2026
d147nolwbekx2b.cloudfront.net	delivery	primary	confiant-adint-2026
dcv2rnj2ograe.cloudfront.net	delivery	primary	confiant-adint-2026
d1x4e580sn23dn.cloudfront.net	delivery	primary	confiant-adint-2026
d2epnp0vokbtl7.cloudfront.net	delivery	primary	confiant-adint-2026
pagead.trustlayersdk.com	delivery	primary	confiant-adint-2026

# Source: microsoft-devilstongue-2021; published 2021-07-15
# https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/
# Older Candiru campaign evidence. Historical attribution does not establish
# current ownership or activity; interpret dated artifacts in source context.
noc-service-streamer.com	historical	secondary	microsoft-devilstongue-2021
fbcdnads.live	historical	secondary	microsoft-devilstongue-2021
hilocake.info	historical	secondary	microsoft-devilstongue-2021
backxercise.com	historical	secondary	microsoft-devilstongue-2021
winmslaf.xyz	historical	secondary	microsoft-devilstongue-2021
service-deamon.com	historical	secondary	microsoft-devilstongue-2021
online-affiliate-mon.com	historical	secondary	microsoft-devilstongue-2021
codeingasmylife.com	historical	secondary	microsoft-devilstongue-2021
kenoratravels.com	historical	secondary	microsoft-devilstongue-2021
weathercheck.digital	historical	secondary	microsoft-devilstongue-2021
colorpallatess.com	historical	secondary	microsoft-devilstongue-2021
library-update.com	historical	secondary	microsoft-devilstongue-2021
online-source-validate.com	historical	secondary	microsoft-devilstongue-2021
grayhornet.com	historical	secondary	microsoft-devilstongue-2021
johnshopkin.net	historical	secondary	microsoft-devilstongue-2021
eulenformacion.com	historical	secondary	microsoft-devilstongue-2021

# Source: avast-2022; published 2022-07-21
# https://github.com/gendigitalinc/ioc/blob/95f8e5920fa5b518801904099e603ec86fde95ba/Candiru/README.md
# Older Candiru campaign evidence. Historical attribution does not establish
# current ownership or activity; interpret dated artifacts in source context.
bad-shop.net	historical	secondary	avast-2022
bestcarent.org	historical	secondary	avast-2022
core-update.com	historical	secondary	avast-2022
datanalytic.org	historical	secondary	avast-2022
expertglobal.org	historical	secondary	avast-2022
only-music.net	historical	secondary	avast-2022
popsonglist.com	historical	secondary	avast-2022
querylight.net	historical	secondary	avast-2022
smartstand.org	historical	secondary	avast-2022
webs-update.com	historical	secondary	avast-2022

# Source: citizenlab-candiru-2021; published 2021-07-15
# https://citizenlab.ca/research/hooking-candiru-another-mercenary-spyware-vendor-comes-into-focus/
# Older Candiru campaign evidence. Historical attribution does not establish
# current ownership or activity; interpret dated artifacts in source context.
refugeeinternational.org	historical	secondary	citizenlab-candiru-2021
genderconference.org	historical	secondary	citizenlab-candiru-2021
un-asia.co	historical	secondary	citizenlab-candiru-2021
armenpress.net	historical	secondary	citizenlab-candiru-2021
tehrantimes.org	historical	secondary	citizenlab-candiru-2021
total-slovenia-news.net	historical	secondary	citizenlab-candiru-2021

# Source: citizenlab-catalangate-2022; published 2022-04-18
# https://citizenlab.ca/research/catalangate-extensive-mercenary-spyware-operation-against-catalans-using-pegasus-candiru/
# Older Candiru campaign evidence. Historical attribution does not establish
# current ownership or activity; interpret dated artifacts in source context.
stat.email	historical	secondary	citizenlab-catalangate-2022
adtrack.link	historical	secondary	citizenlab-catalangate-2022
cortana.cloud	historical	secondary	citizenlab-catalangate-2022
rbtlnk.net	historical	secondary	citizenlab-catalangate-2022

# Source: google-tag-candiru-2021; published 2021-07-14
# https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks/
# Older Candiru campaign evidence. Historical attribution does not establish
# current ownership or activity; interpret dated artifacts in source context.
lragir.org	historical	secondary	google-tag-candiru-2021
armradio.org	historical	secondary	google-tag-candiru-2021
asbares.com	historical	secondary	google-tag-candiru-2021
armtimes.net	historical	secondary	google-tag-candiru-2021
armlur.org	historical	secondary	google-tag-candiru-2021
armenpress.org	historical	secondary	google-tag-candiru-2021
hraparak.org	historical	secondary	google-tag-candiru-2021
armtimes.org	historical	secondary	google-tag-candiru-2021
hetq.org	historical	secondary	google-tag-candiru-2021
lioiamcount.com	historical	secondary	google-tag-candiru-2021
db-control-uplink.com	historical	secondary	google-tag-candiru-2021
kidone.xyz	historical	secondary	google-tag-candiru-2021
workaj.com	historical	secondary	google-tag-candiru-2021
wordzmncount.com	historical	secondary	google-tag-candiru-2021

# Source: amnesty-candiru-indonesia-2024; published 2024-05-01
# https://securitylab.amnesty.org/latest/2024/05/a-web-of-surveillance/
# Older Candiru campaign evidence. Historical attribution does not establish
# current ownership or activity; interpret dated artifacts in source context.
aqaf.net	historical	secondary	amnesty-candiru-indonesia-2024
gelora.org	historical	secondary	amnesty-candiru-indonesia-2024
nusantaraqurban.com	historical	secondary	amnesty-candiru-indonesia-2024

'''

# --- result ------------------------------------------------------------------
"""Shared result types — the contract every scan module implements.

Doctrine baked into these types (SPEC-scanner.md):

  D3  Measured, never inferred. A module reports CLEAN only for checks that
      actually ran and found nothing. A check that could not run is UNKNOWN,
      which is a DISTINCT outcome from CLEAN. Never collapse the two.

Status values
  CLEAN    every check this module was meant to run, ran, and found no hit
  HITS     at least one indicator matched
  UNKNOWN  no check in this module could run (nothing was actually observed)
  PARTIAL  some checks ran clean, at least one could not run (gaps remain)
"""


import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List

CLEAN = "CLEAN"
HITS = "HITS"
UNKNOWN = "UNKNOWN"
PARTIAL = "PARTIAL"

# Evidence grades, strongest first. See Hit.evidence for what each one means.
EV_ON_DISK = "on-disk"          # a known sample's fingerprint matched a file
EV_FILE_PATTERN = "file-pattern"  # a research rule matched; needs verification
EV_PERSISTENCE = "persistence"  # named in an auto-start registration
EV_CONTACTED = "contacted"      # the device demonstrably talked to the host
EV_DNS = "dns-record"           # a resolver record; endpoint contact unverified
EV_ATTEMPTED = "attempted"      # a lookup happened but a filter blocked it
EV_CONFIGURED = "configured"    # named in local config, NOT as a block
EV_REFERENCED = "referenced"    # the string appeared in saved content

EVIDENCE_ORDER = [EV_ON_DISK, EV_FILE_PATTERN, EV_PERSISTENCE, EV_CONTACTED, EV_DNS, EV_ATTEMPTED,
                  EV_CONFIGURED, EV_REFERENCED]

# Everything except `referenced` is a finding that needs a person to look at it.
# This is deliberately a DENY-list of the one benign grade rather than an
# allow-list of serious ones: a hit whose grade is missing or misspelled is then
# treated as serious, never as harmless. The opposite default is how a known
# sample on disk once came to be reported as "probably not a sign of compromise".
BENIGN_EVIDENCE = {EV_REFERENCED}


def is_serious(evidence: str) -> bool:
    return evidence not in BENIGN_EVIDENCE


@dataclass
class Hit:
    """A single indicator match. `indicator` is the IOC string that matched
    (domain, IP or hash); the tier/confidence come from the IOC set so every
    hit carries its own provenance, never a bare 'found something'."""

    indicator: str
    location: str
    detail: str
    tier: str = ""
    confidence: str = ""
    # Which published report this indicator came from. The file now carries more
    # than one source, so the citation has to travel with the hit.
    source: str = ""
    # How strong this hit is as evidence. The single most important field for
    # anyone triaging a result, because the artifact decides the meaning:
    #
    #   on-disk    - a file on this machine has the fingerprint of a published
    #                sample. Conclusive.
    #   persistence- the name appears in an auto-start/COM registration. Serious.
    #   contacted  - the browser or OS demonstrably talked to this host. A cookie
    #                it set, an HSTS header it sent, or a connection record.
    #   dns-record - the name or address appears in a DNS cache or event log.
    #                A lookup may fail, be prefetched, or never lead to a
    #                connection. Endpoint contact is unverified.
    #   attempted  - something on the device looked the name up, but a DNS filter
    #                answered with a block address, so no connection was made.
    #   configured - the name appears in local configuration (e.g. the hosts
    #                file) pointing somewhere REAL. A block entry (0.0.0.0) is
    #                protective and is not reported as a hit at all.
    #   referenced - the string appeared in cached page content or history text.
    #                That is often just a page ABOUT the indicator - a news
    #                article, a report, a blocklist. Usually NOT contact.
    #
    # Collapsing these would be the tool's most harmful bug in either direction:
    # over-grading sends people who merely read about this campaign to a
    # human-rights helpline; under-grading tells a real victim it is nothing.
    # Use the EV_* constants. An empty or unknown grade is treated as SERIOUS.
    evidence: str = ""
    # When the artifact says the contact happened, if it records that at all.
    observed: str = ""

    # Which browser profile / account this came from, by its DISPLAY name (e.g.
    # "Bubbles"), not just the folder name ("Profile 1"). On a machine with
    # several profiles the folder number tells the reader nothing, and whoever
    # triages a finding needs to know whose browser it was.
    #
    # The signed-in email address is deliberately NOT collected: the display
    # name already answers "which account", and reports get forwarded.
    profile: str = ""

    @property
    def is_contact(self) -> bool:
        return self.evidence == EV_CONTACTED

    @property
    def is_serious(self) -> bool:
        return is_serious(self.evidence)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Check:
    """One named sub-check inside a module (e.g. 'dns-cache'). `ran` records
    whether it actually executed; `reason` explains why it did not. This is how
    D3 (CLEAN != UNKNOWN) is enforced at the finest granularity."""

    name: str
    ran: bool
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ModuleResult:
    name: str
    checked: int = 0
    skipped: int = 0
    hits: List[Hit] = field(default_factory=list)
    checks: List[Check] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    submetrics: Dict[str, int] = field(default_factory=dict)
    # Wall-clock seconds this module took. Shown to the user because a scan that
    # prints nothing for ten minutes looks hung, and because it tells anyone
    # tuning the tool where the time actually goes.
    duration_s: float = 0.0
    # How far back in time this module's evidence actually reaches. A clean result
    # is only as meaningful as the window it covers: browser caches are recycled
    # within weeks, and the DNS log does not exist unless somebody turned it on.
    # Each entry is {label: {"earliest": ISO date or None, "basis": str,
    # "note": str}}. Reported to the user verbatim, because "we found nothing"
    # and "we could only look back 11 weeks" are the same sentence.
    reach: Dict[str, Any] = field(default_factory=dict)

    # --- builder helpers used by modules ------------------------------------

    def add_hit(self, hit: Hit) -> None:
        self.hits.append(hit)

    def ran(self, name: str) -> None:
        self.checks.append(Check(name, True))

    def could_not_run(self, name: str, reason: str) -> None:
        self.checks.append(Check(name, False, reason))
        self.notes.append("{}: could not run ({})".format(name, reason))

    def note(self, text: str) -> None:
        self.notes.append(text)

    # --- status rollup ------------------------------------------------------

    @property
    def status(self) -> str:
        if self.hits:
            return HITS
        if not self.checks:
            return UNKNOWN
        ran = [c for c in self.checks if c.ran]
        if not ran:
            return UNKNOWN
        if len(ran) == len(self.checks):
            return CLEAN
        return PARTIAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "checked": self.checked,
            "skipped": self.skipped,
            "hits": [h.to_dict() for h in self.hits],
            "checks": [c.to_dict() for c in self.checks],
            "notes": list(self.notes),
            "submetrics": dict(self.submetrics),
            "reach": dict(self.reach),
            "duration_s": round(self.duration_s, 1),
        }


# --- iocs --------------------------------------------------------------------
"""IOC loading, type inference and freshness.

Data contract (SPEC-scanner.md, matching iocs/adfection_iocs.txt):

    indicator <TAB> tier <TAB> confidence

  tier       = cc | validator | delivery | historical | sample
  confidence = primary | secondary

`#` lines are comments. The schema deliberately carries more than AdFection: the
threat is the ADINT *technique*, so the same file holds other vendors (NSO,
Intellexa/Predator, Paragon, Cytrox) and sample hashes as they are added. A hit
without a citation is unusable, so the provenance (confidence) column is required.

Indicator *type* is inferred from shape, not stored, so the file stays 3 columns:
  - 64 hex chars            -> sha256 sample hash
  - looks like an IPv4/IPv6 -> ip
  - otherwise               -> domain
"""


import io
import os
import ipaddress
import re
import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

VALID_TIERS = {
    "cc",           # Candiru command-and-control (Citizen Lab, named in body)
    "validator",    # Candiru validator / target-selection servers
    "delivery",     # Discover-Tech / Controlium ad infrastructure
    "historical",   # older, separate Candiru campaigns
    "sample",       # file hashes of the spyware itself
    # A legitimate, signed third-party driver or utility that this actor abuses
    # (bring-your-own-vulnerable-driver). The file is NOT spyware: it ships with
    # real products and is present on clean machines for innocent reasons. It is
    # tiered apart from `sample` precisely so a match can never be reported as
    # proof of infection - presence is a lead to investigate, nothing more.
    "vuln-driver",
    # Candiru-attributed server infrastructure whose individual ROLE is not stated
    # by the source. Recorded Future's Aug 2025 DevilsTongue report lists 8
    # clusters mixing victim-facing C2 and higher-tier operator infrastructure,
    # without saying which domain is which. Treating these as `cc` would claim
    # precision the source does not give, so they get their own tier.
    "candiru",
    # Same, but IP addresses. Separate because an IP indicator decays in a way a
    # domain does not: almost all of these are Vultr / DigitalOcean addresses
    # that are very likely reassigned to innocent tenants by now. A hit is only
    # meaningful if it is DATED (a DNS log entry from the period), which is why
    # the tier is distinguishable rather than mixed in with the domains.
    "candiru-ip",
}
VALID_CONFIDENCE = {"primary", "secondary"}

# Characters that may not sit immediately beside a match. Without this the
# matching is plain substring, so 52.174.65.77 matches inside 152.174.65.771 and
# controlium.net matches inside notcontrolium.net or controlium.network. With 100+
# IP indicators that stops being theoretical.
#
# A dot on the RIGHT is the subtle case. "controlium.net." (the fully-qualified
# form, or the end of a sentence) is the indicator; "controlium.net.evil.example"
# is a different domain that merely starts with it. So a trailing dot is allowed
# only when what follows it does not continue the name (the `cont` sets below).
_LABEL = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_LEFT_BAD = _LABEL | {"_"}
_RIGHT_BAD = _LABEL | {"_"}
_DIGIT = set("0123456789")
_DIGIT_DOT = _DIGIT | {"."}
_HEX = set("0123456789abcdef")
_HEX_COLON = _HEX | {":"}

TYPE_DOMAIN = "domain"
TYPE_IP = "ip"
TYPE_SHA256 = "sha256"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ASOF_RE = re.compile(r"^#\s*as-of:\s*(\d{4}-\d{2}-\d{2})\s*$")


def infer_type(indicator: str) -> str:
    s = indicator.strip().lower()
    if _SHA256_RE.match(s):
        return TYPE_SHA256
    if _IPV4_RE.match(s) or (":" in s and all(c in "0123456789abcdef:" for c in s)):
        return TYPE_IP
    return TYPE_DOMAIN


@dataclass(frozen=True)
class Indicator:
    value: str          # normalised: lower-case for domains/ips/hashes
    tier: str
    confidence: str
    type: str
    # Which published report this came from. Optional 4th column. With more than
    # one source in the file, "a hit without a citation is unusable" means the
    # citation has to travel per indicator, not per file.
    source: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "indicator": self.value,
            "tier": self.tier,
            "confidence": self.confidence,
            "type": self.type,
            "source": self.source,
        }


def _char_at(hay, pos):
    """One character of a str or bytes haystack, as a str, or None if out of range."""
    if pos < 0 or pos >= len(hay):
        return None
    c = hay[pos]
    return c if isinstance(c, str) else chr(c)


def _char_at16(hay: bytes, pos: int):
    """One UTF-16LE code unit of a bytes haystack starting at byte `pos`.

    Only ASCII matters for boundary decisions, so anything else comes back as a
    placeholder that is in none of the boundary sets.
    """
    if pos < 0 or pos + 1 >= len(hay):
        return None
    lo, hi = hay[pos], hay[pos + 1]
    return chr(lo) if hi == 0 and lo < 0x80 else "￿"


def _bad_sets(needle: str, ind_type: str):
    """(left_bad, right_bad, continues) for one indicator. `continues` is what
    may not follow a trailing dot - see the comment on _LABEL."""
    if ind_type == TYPE_IP:
        if ":" in needle:                      # IPv6
            return _HEX_COLON | {"."}, _HEX_COLON, _HEX
        return _DIGIT_DOT, _DIGIT, _DIGIT      # IPv4
    return _LEFT_BAD, _RIGHT_BAD, _LABEL


def _positions(hay, needle, ind_type: str, display: str, wide: bool = False):
    """Every offset at which `needle` occurs in `hay` as a whole indicator rather
    than as part of a longer name or number.

    Domains: the character before must not continue a label (so notcontrolium.net
    does not match controlium.net) and the character after must not either (so
    controlium.network does not match).
    IPs: neither side may continue the number, so 152.174.65.771 does not match
    52.174.65.77, and an IPv6 address may not sit inside a longer one.

    `display` is the indicator as text (for choosing boundary sets); `needle` is
    what is searched for, which differs when `wide` (UTF-16LE bytes).
    """
    left_bad, right_bad, cont = _bad_sets(display, ind_type)
    at = _char_at16 if wide else _char_at
    unit = 2 if wide else 1
    out = []
    start = 0
    while True:
        idx = hay.find(needle, start)
        if idx == -1:
            return out
        before = at(hay, idx - unit)
        after = at(hay, idx + len(needle))
        ok = before is None or before not in left_bad
        if ok and after is not None:
            if after in right_bad:
                ok = False
            elif after == ".":
                nxt = at(hay, idx + len(needle) + unit)
                ok = nxt is None or nxt not in cont
        if ok:
            out.append(idx)
        start = idx + 1


def _boundaries_ok(hay, needle, ind_type: str) -> bool:
    """True if `needle` occurs in `hay` at least once as a whole indicator."""
    display = needle if isinstance(needle, str) else needle.decode("ascii", "replace")
    return bool(_positions(hay, needle, ind_type, display))


def _prune_parents(found, hay) -> list:
    """Drop a parent domain whose every occurrence is just the tail of a matched
    child. "noas.powerium.net" in a cookie also contains "powerium.net", and both
    are indicators - but it is ONE contact, and reporting it as two servers that
    reached the device doubles the alarm for no reason. A parent that also occurs
    on its own somewhere in the same artifact is kept."""
    by_value = {ind.value: (ind, occ) for ind, occ in found}
    keep = []
    for ind, occ in found:
        children = [c for c in by_value
                    if c != ind.value and c.endswith("." + ind.value)]
        if ind.type != TYPE_DOMAIN or not children:
            keep.append(ind)
            continue
        standalone = False
        for enc, pos in occ:
            tail_of_child = False
            for child in children:
                extra = len(child) - len(ind.value)
                if enc == "wide":
                    start = pos - 2 * extra
                    seg = hay[start:pos + 2 * len(ind.value)] if start >= 0 else b""
                    tail_of_child = seg == child.encode("utf-16-le")
                else:
                    start = pos - extra
                    seg = hay[start:pos + len(ind.value)] if start >= 0 else ""
                    want = child if isinstance(hay, str) else child.encode("ascii")
                    tail_of_child = seg == want
                if tail_of_child:
                    break
            if not tail_of_child:
                standalone = True
                break
        if standalone:
            keep.append(ind)
    return keep


class IocSet:
    def __init__(self, indicators: List[Indicator], source_path: str,
                 source_mtime: Optional[float]):
        self.indicators = indicators
        self.source_path = source_path
        self.source_mtime = source_mtime
        self.asof = None  # "YYYY-MM-DD" from the header, set by load()
        self._by_value = {i.value: i for i in indicators}
        self._net_cache = None
        self._needle_cache = {}
        self._gate_text_re = None
        self._gate_bytes_re = None

    # --- views used by modules ---------------------------------------------

    @property
    def domains(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_DOMAIN]

    @property
    def ips(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_IP]

    @property
    def hashes(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_SHA256]

    @property
    def network_strings(self) -> List[str]:
        """Lower-case domain + IP strings, for substring matching in artifacts.
        Sorted for deterministic output. Never used to RESOLVE anything."""
        return sorted({i.value for i in self.indicators
                       if i.type in (TYPE_DOMAIN, TYPE_IP)})

    def lookup(self, value: str) -> Optional[Indicator]:
        return self._by_value.get(value.strip().lower())

    # --- matching -----------------------------------------------------------
    #
    # All matching goes through here so the boundary rules exist in exactly one
    # place. Both methods take an ALREADY LOWER-CASED haystack, and neither ever
    # resolves or contacts anything: this is text comparison only.

    @property
    def _net_indicators(self) -> List[Indicator]:
        if self._net_cache is None:
            self._net_cache = [i for i in self.indicators
                               if i.type in (TYPE_DOMAIN, TYPE_IP)]
        return self._net_cache

    # MEASURED, do not "optimise" this back into a regex.
    #
    # The obvious speedup is to compile one alternation of all 263 literals and
    # make a single pass per file instead of one pass per indicator. It was tried
    # and it is 4x SLOWER (10.7s vs 2.5s over 300 x 125 KB buffers): `in` on
    # bytes/str dispatches to an optimised C substring search, while Python's
    # `re` has to walk a large alternation itself. A genuine single-pass win
    # would need an Aho-Corasick implementation, which is not in the standard
    # library, and the tool has a hard no-dependencies rule.
    #
    # The boundary check runs only on candidates that already matched, so it
    # costs nothing on the overwhelming majority of files.

    def search(self, haystack_lower: str) -> List[Indicator]:
        """Indicators genuinely present in the text, with type-aware boundaries."""
        found = []
        for ind in self._net_indicators:
            if ind.value in haystack_lower:
                pos = _positions(haystack_lower, ind.value, ind.type, ind.value)
                if pos:
                    found.append((ind, [("str", p) for p in pos]))
        return _prune_parents(found, haystack_lower)

    def search_bytes(self, haystack_lower: bytes) -> List[Indicator]:
        """As search(), for raw binary artifacts (HTTP cache, LevelDB).

        Searches both single-byte text and UTF-16LE, because Chromium's storage
        and many Windows artifacts keep strings as UTF-16 - "c\\0o\\0n\\0..." -
        which a plain byte search walks straight past. bytes.lower() lower-cases
        the ASCII letters in both encodings, so the caller's lower-casing holds.
        """
        found = []
        for ind in self._net_indicators:
            occ = []
            narrow, wide = self._needles(ind)
            if narrow in haystack_lower:
                occ += [("narrow", p) for p in
                        _positions(haystack_lower, narrow, ind.type, ind.value)]
            if wide in haystack_lower:
                occ += [("wide", p) for p in
                        _positions(haystack_lower, wide, ind.type, ind.value,
                                   wide=True)]
            if occ:
                found.append((ind, occ))
        return _prune_parents(found, haystack_lower)

    def _needles(self, ind: Indicator):
        cache = self._needle_cache
        if ind.value not in cache:
            # Indicator values are ASCII by construction (load() converts IDN
            # domains to punycode), so this encode is exact, never lossy.
            cache[ind.value] = (ind.value.encode("ascii"),
                                ind.value.encode("utf-16-le"))
        return cache[ind.value]

    def most_specific(self, matched: List[Indicator]) -> List[Indicator]:
        """For ONE record (a cookie, an HSTS entry, a URL) that matched several
        indicators: keep only the most specific. A cookie for noas.powerium.net
        matches both noas.powerium.net and powerium.net, but it is one contact."""
        values = {i.value for i in matched}
        return [i for i in matched
                if not (i.type == TYPE_DOMAIN and
                        any(v != i.value and v.endswith("." + i.value)
                            for v in values))]

    def __len__(self) -> int:
        return len(self.indicators)

    # --- freshness ----------------------------------------------------------

    def _curated_at(self) -> Optional[datetime.datetime]:
        """When this set was last curated, as a datetime, or None if unknowable.

        The '# as-of:' date is preferred over the file's modification time
        because mtime is a property of the COPY, not of the data: a fresh clone,
        an unzip or a plain file copy resets it to now, so a set curated a year
        ago would report itself as zero days old and never trip the staleness
        warning. The header date is content, so it survives being copied.
        """
        if self.asof:
            try:
                return datetime.datetime.strptime(self.asof, "%Y-%m-%d")
            except ValueError:
                # A malformed header must degrade to the mtime, never raise in
                # the middle of a scan.
                pass
        if self.source_mtime is None:
            return None
        return datetime.datetime.fromtimestamp(self.source_mtime)

    def age_days(self, now: Optional[datetime.datetime] = None) -> Optional[int]:
        curated = self._curated_at()
        if curated is None:
            return None
        now = now or datetime.datetime.now()
        delta = now - curated
        return max(0, delta.days)

    def is_stale(self, threshold_days: int = 30) -> bool:
        age = self.age_days()
        return age is not None and age > threshold_days


class IocError(Exception):
    pass


# Indicator values drive substring searches over every artifact and are printed
# into reports people forward, but only the file's schema was checked. A hostile
# or corrupted feed could pass: a lone "." normalises to the empty string, which
# matches between every pair of bytes (measured at ~31 MB of RAM per MB scanned);
# a lone ":" parses as an IP that matches every URL; "0.0.0.0" would match every
# BLOCKED lookup; and a value carrying control characters went straight into the
# report. Real indicators are hostnames, IP addresses and hex digests. Anything
# else is refused, loudly, rather than scanned for.
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_MAX_INDICATORS = 20000


def _value_problem(value, kind):
    """Why an indicator value is unsafe to scan for, or an empty string."""
    if kind == TYPE_IP:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return "not a valid IP address"
        if addr.is_unspecified or len(value) < 7:
            return "would match far more than the intended host"
        return ""
    if kind == TYPE_DOMAIN:
        if not 4 <= len(value) <= 253:
            return "not the length of a hostname"
        labels = value.split(".")
        if len(labels) < 2:
            return "a hostname needs at least one dot"
        for label in labels:
            if not 1 <= len(label) <= 63 or not _DOMAIN_LABEL_RE.match(label):
                return "label {!r} is not a valid hostname label".format(label[:70])
        return ""
    return ""   # hashes are already pinned to 64 hex digits by infer_type


def load(path: str) -> IocSet:
    if not os.path.exists(path):
        raise IocError("IOC file not found: {}".format(path))
    seen: Dict[str, Indicator] = {}
    asof: Optional[str] = None
    # utf-8-sig, not utf-8: Windows editors save a byte-order mark, and U+FEFF is
    # not whitespace to str.strip(). With plain utf-8 the first indicator in a
    # user's own list silently became "﻿controlium.net", matched nothing,
    # and the scan then reported finding nothing without ever having looked.
    with io.open(path, encoding="utf-8-sig") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                # The '# as-of: YYYY-MM-DD' header is the set's curated date. It
                # is the deterministic timestamp every generated artifact uses,
                # so the whole build is reproducible from committed content.
                m = _ASOF_RE.match(line)
                if m:
                    asof = m.group(1)
                continue
            parts = [p.strip() for p in line.split("\t") if p.strip() != ""]
            if len(parts) < 3:
                raise IocError(
                    "line {}: expected 3 or 4 tab-separated columns, got {!r}"
                    .format(lineno, line))
            value, tier, confidence = parts[0].lower(), parts[1], parts[2]
            # 4th column is an optional source tag; files written before it
            # existed stay valid.
            source = parts[3] if len(parts) > 3 else ""
            if tier not in VALID_TIERS:
                raise IocError("line {}: unknown tier {!r}".format(lineno, tier))
            if confidence not in VALID_CONFIDENCE:
                raise IocError(
                    "line {}: unknown confidence {!r}".format(lineno, confidence))
            if value.startswith("﻿") or any(
                    c in value for c in "​‌‍⁠"):
                raise IocError("line {}: invisible character in {!r} - the "
                               "file was probably re-saved by an editor".format(
                                   lineno, value))
            kind = infer_type(value)
            if kind == TYPE_DOMAIN:
                value = value.rstrip(".")
                if not value.isascii():
                    # Store internationalised names in the punycode form that
                    # browsers and DNS actually record, so matching is exact.
                    try:
                        value = value.encode("idna").decode("ascii")
                    except UnicodeError:
                        raise IocError("line {}: {!r} is not a valid domain "
                                       "name".format(lineno, value))
            problem = _value_problem(value, kind)
            if problem:
                raise IocError("line {}: {!r}: {}".format(
                    lineno, value[:80], problem))
            seen[value] = Indicator(value, tier, confidence, kind, source)
            if len(seen) > _MAX_INDICATORS:
                raise IocError("more than {:,} indicators - refusing what looks "
                               "like a corrupted or hostile feed".format(
                                   _MAX_INDICATORS))
    if not seen:
        # An empty list must never produce a report. A truncated download or an
        # emptied file would otherwise run a full scan, search for nothing, and
        # print a result that reads as reassurance.
        raise IocError("indicator file contains no indicators: {}".format(path))
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    s = IocSet(sorted(seen.values(), key=lambda i: i.value),
               os.path.abspath(path), mtime)
    s.asof = asof
    return s


# --- netguard ----------------------------------------------------------------
"""Runtime enforcement of doctrine D2: never contact an indicator.

D2 is the most important rule in the project. Resolving a C&C domain, or opening
any connection, would announce a possible victim to the people running the
infrastructure. The tool is a local string-matching tool; it has no reason to
touch the network at all.

We do not merely *intend* not to resolve anything — we make it impossible. While a
scan runs inside `no_network()`, every name-resolution and outbound-connection
entry point in the `socket` module raises `NetworkContactAttempt`. A bug that tried
to resolve an IOC would crash loudly instead of leaking a signal.

This does NOT block `subprocess` (OS pipes, not Python sockets), so the host
module can still read the LOCAL DNS resolver cache via PowerShell — reading an
already-cached entry resolves nothing.

The IOC-update path (not implemented here) is the one explicitly-invoked network
operation the spec allows; it must run OUTSIDE this guard and verify a signature.
"""


import contextlib
import socket
from typing import List


class NetworkContactAttempt(RuntimeError):
    """Raised when scan code tries to resolve a name or open a connection."""


# Functions on the socket module that perform resolution or egress.
_BLOCKED = (
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
    "create_connection",
)


class _Recorder:
    def __init__(self) -> None:
        self.attempts: List[str] = []

    def trip(self, what: str) -> None:
        self.attempts.append(what)
        raise NetworkContactAttempt(
            "D2 violation: scan code attempted network contact via {}. "
            "The scanner must never resolve or connect to an indicator.".format(what))


@contextlib.contextmanager
def no_network():
    """Context manager that disables all socket-level resolution and egress."""
    recorder = _Recorder()
    saved = {}

    for name in _BLOCKED:
        if hasattr(socket, name):
            saved[name] = getattr(socket, name)

            def make(fn_name):
                def blocked(*_a, **_k):
                    recorder.trip("socket." + fn_name)
                return blocked
            setattr(socket, name, make(name))

    # Methods on the socket OBJECT that open a connection or send egress. sendto
    # and sendmsg matter because a UDP datagram needs no prior connect(): without
    # them a bug could still push bytes to a resolver or a C&C over UDP.
    _SOCK_METHODS = ("connect", "connect_ex", "sendto", "sendmsg", "sendall",
                     "send")
    saved_methods = {}
    for mname in _SOCK_METHODS:
        if hasattr(socket.socket, mname):
            saved_methods[mname] = getattr(socket.socket, mname)

            def make_method(m):
                def blocked(self, *_a, **_k):
                    recorder.trip("socket.socket." + m)
                return blocked
            setattr(socket.socket, mname, make_method(mname))

    try:
        yield recorder
    finally:
        for name, fn in saved.items():
            setattr(socket, name, fn)
        for mname, fn in saved_methods.items():
            setattr(socket.socket, mname, fn)


# --- localpaths --------------------------------------------------------------
"""Refuse Windows remote drives and filesystem redirections before reads.

Checks are conservative and use lstat so a reparse point is inspected rather
than followed. POSIX network mounts cannot always be distinguished from local
paths here. This is not a sandbox against concurrent filesystem changes.
"""

import os
import stat
import sys


def local_temp_dir():
    """Select a local temp directory without tempfile's write-probing fallback."""
    candidates = [os.environ.get(key, "") for key in ("TMPDIR", "TEMP", "TMP")]
    if sys.platform == "win32":
        candidates.extend(os.path.join(base, "Temp") for base in
                          (os.environ.get("LOCALAPPDATA", ""),
                           os.environ.get("SystemRoot", "")) if base)
    else:
        candidates.extend(("/tmp", "/var/tmp", "/private/tmp"))
    for candidate in candidates:
        if candidate and not path_problem(candidate) and os.path.isdir(candidate):
            return candidate
    raise PermissionError("no safe local temporary directory is available")


def path_problem(path):
    """Return why a path cannot safely be inspected, or an empty string."""
    path = os.fspath(path)
    if not os.path.isabs(path):
        return "relative path cannot be classified as local"
    if ".." in path.replace("\\", "/").split("/"):
        return "parent-directory traversal cannot be classified as local"
    if sys.platform == "win32":
        s = path.replace("/", "\\")
        if s.startswith("\\\\"):
            return "UNC or device path was not opened"
        drive, _tail = os.path.splitdrive(s)
        if len(drive) != 2 or drive[1] != ":":
            return "path does not name an absolute local drive"
        try:
            import ctypes
            kind = ctypes.windll.kernel32.GetDriveTypeW(drive + "\\")
        except (AttributeError, OSError):
            return "drive locality could not be established"
        if kind not in (2, 3, 5, 6):  # removable, fixed, CD-ROM, RAM disk
            return "drive is remote or its locality is unknown"

    drive, tail = os.path.splitdrive(path)
    current = drive + os.sep
    parts = [p for p in tail.replace("\\", os.sep).split(os.sep) if p]
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return ""  # caller handles a genuinely absent artifact
        except OSError as exc:
            return "cannot safely inspect {}: {}".format(current, exc)
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            # macOS exposes its standard /var, /tmp and /etc directories through
            # root-owned aliases into /private. These exact system aliases are
            # safe to validate lexically; arbitrary user links remain refused.
            # readlink reads the link itself and does not traverse its target.
            aliases = {"/var": "/private/var", "/tmp": "/private/tmp",
                       "/etc": "/private/etc"}
            target = aliases.get(current) if sys.platform == "darwin" else None
            if (target and stat.S_ISLNK(info.st_mode)
                    and getattr(info, "st_uid", None) == 0):
                try:
                    link = os.readlink(current)
                except OSError as exc:
                    return "cannot inspect system alias {}: {}".format(current, exc)
                # Apple's links commonly use 'private/var', relative to '/'.
                # Accept only these two exact spellings of the expected target.
                if link in (target, target.lstrip("/")):
                    canonical = os.path.join(target, *parts[index + 1:])
                    return path_problem(canonical)
            return "symlink or reparse point was not followed: {}".format(current)
    return ""


def walk_local(root, onerror=None):
    """Top-down os.walk equivalent that never classifies a link by following it.

    The caller can prune the yielded dirs list in place, as with os.walk.
    Refused entries are delivered to onerror as PermissionError instances.
    """
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            problem = path_problem(current)
            if problem:
                raise PermissionError(13, problem, current)
            dirs, files = [], []
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if (stat.S_ISLNK(info.st_mode)
                                or getattr(info, "st_file_attributes", 0) & 0x400):
                            raise PermissionError(13, "symlink or reparse point "
                                                  "was not followed", entry.path)
                        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                            raise PermissionError(13, "special filesystem entry "
                                                  "was not opened", entry.path)
                        (dirs if stat.S_ISDIR(info.st_mode) else files).append(entry.name)
                    except OSError as exc:
                        if onerror:
                            onerror(exc)
        except OSError as exc:
            if onerror:
                onerror(exc)
            continue
        yield current, dirs, files
        pending.extend(os.path.join(current, d) for d in reversed(dirs))


# --- context -----------------------------------------------------------------
"""ScanContext — what every module receives. Keeps modules decoupled from the CLI."""


import sys
from dataclasses import dataclass, field
from typing import Callable



@dataclass
class ScanContext:
    iocs: IocSet
    deep: bool = False
    # Skip the file-fingerprinting check, which is the slowest part of the scan
    # by far and the weakest signal in it. See cli.py for why.
    quick: bool = False
    verbose: bool = True
    # progress sink; defaults to stderr so stdout stays the clean human report
    emit: Callable[[str], None] = field(
        default=lambda msg: print(msg, file=sys.stderr))
    # The result the running module is filling in, published here as soon as it
    # exists. A module that dies half way through has usually already found
    # something - a matching cookie read before a later, malformed artifact
    # raised - and that evidence must survive the crash. Without this the CLI
    # could only build a fresh empty result and the hits were thrown away.
    # Modules set it; nothing else should read it except the CLI's recovery path.
    partial: object = None
    # Optional research feature. Never installs a dependency or fetches rules.
    patterns: bool = False
    pattern_paths: tuple = ()
    # Local, per-user COM server files discovered by the host check. Only the
    # optional pattern module consumes these; explicit --pattern-path wins.
    pattern_candidate_paths: tuple = ()
    pattern_candidate_omitted: int = 0


# --- candiru_rules -----------------------------------------------------------
"""Pinned public Candiru research rules, embedded for offline standalone builds.

The two rule strings retain their own third-party licenses and authorship.
See third_party/candiru/PROVENANCE.json and the corresponding license texts.
Do not replace these with downloaded rules at scan time.
"""

CANDIRU_ENGINE_VERSION = "1.21.0"

CANDIRU_RULE_SOURCES = ('import "pe"\n\nrule MAL_DevilsTongue_HijackDll {\n   meta:\n      description = "Detects SOURGUM\'s DevilsTongue hijack DLL"\n      author = "Microsoft Threat Intelligence Center (MSTIC)"\n      date = "2021-07-15"\n      reference = "https://www.microsoft.com/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"\n      score = 80\n      id = "390b8b73-6740-513d-8c70-c9002be0ce69"\n   strings:\n      $str1 = "windows.old\\\\windows" wide\n      $str2 = "NtQueryInformationThread"\n      $str3 = "dbgHelp.dll" wide\n      $str4 = "StackWalk64"\n      $str5 = "ConvertSidToStringSidW"\n      $str6 = "S-1-5-18" wide\n      $str7 = "SMNew.dll" // DLL original name\n      // Call check in stack manipulation\n      // B8 FF 15 00 00   mov     eax, 15FFh\n      // 66 39 41 FA      cmp     [rcx-6], ax\n      // 74 06            jz      short loc_1800042B9\n      // 80 79 FB E8      cmp     byte ptr [rcx-5], 0E8h ;\n      $code1 = { B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8 }\n      // PRNG to generate number of times to sleep 1s before exiting\n      // 44 8B C0 mov r8d, eax\n      // B8 B5 81 4E 1B mov eax, 1B4E81B5h\n      // 41 F7 E8 imul r8d\n      // C1 FA 05 sar edx, 5\n      // 8B CA    mov ecx, edx\n      // C1 E9 1F shr ecx, 1Fh\n      // 03 D1    add edx, ecx\n      // 69 CA 2C 01 00 00 imul ecx, edx, 12Ch\n      // 44 2B C1 sub r8d, ecx\n      // 45 85 C0 test r8d, r8d\n      // 7E 19    jle  short loc_1800014D0\n      $code2 = { 44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19 }\n   condition:\n      filesize < 800KB and\n      uint16(0) == 0x5A4D and\n      ( pe.characteristics & pe.DLL ) and\n      (\n         4 of them or\n         ( $code1 and $code2 ) or\n         pe.imphash() == "9a964e810949704ff7b4a393d9adda60"\n      )\n}\n', 'rule win_devilstongue_auto {\n\n    meta:\n        author = "Felix Bilstein - yara-signator at cocacoding dot com"\n        date = "2026-09-17"\n        version = "1"\n        description = "Detects win.devilstongue."\n        info = "autogenerated rule brought to you by yara-signator"\n        tool = "yara-signator v0.6.0"\n        signator_config = "callsandjumps;datarefs;binvalue"\n        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.devilstongue"\n        malpedia_rule_date = "20260916"\n        malpedia_hash = "53a643781c18e08f4a50949af60172d837a0b6f6"\n        malpedia_version = "20260917"\n        malpedia_license = "CC BY-SA 4.0"\n        malpedia_sharing = "TLP:WHITE"\n\n    /* DISCLAIMER\n     * The strings used in this rule have been automatically selected from the\n     * disassembly of memory dumps and unpacked files, using YARA-Signator.\n     * The code and documentation is published here:\n     * https://github.com/fxb-cocacoding/yara-signator\n     * As Malpedia is used as data source, please note that for a given\n     * number of families, only single samples are documented.\n     * This likely impacts the degree of generalization these rules will offer.\n     * Take the described generation method also into consideration when you\n     * apply the rules in your use cases and assign them confidence levels.\n     */\n\n\n    strings:\n        $sequence_0 = { 4d85c0 0f94442402 bba2984e80 ebc5 81fb97ab74c9 0f8f97000000 81fba2984e80 }\n            // n = 7, score = 100\n            //   4d85c0               | dec                 esp\n            //   0f94442402           | mov                 esi, ecx\n            //   bba2984e80           | dec                 ecx\n            //   ebc5                 | mov                 edi, edx\n            //   81fb97ab74c9         | dec                 eax\n            //   0f8f97000000         | cmp                 dword ptr [ecx], 0\n            //   81fba2984e80         | je                  0xb24\n\n        $sequence_1 = { 4883ec28 4889d1 e8???????? b801000000 4883c428 c3 56 }\n            // n = 7, score = 100\n            //   4883ec28             | push                ebx\n            //   4889d1               | dec                 eax\n            //   e8????????           |                     \n            //   b801000000           | sub                 esp, 0x28\n            //   4883c428             | dec                 eax\n            //   c3                   | lea                 ebp, [edx + 0x60]\n            //   56                   | dec                 eax\n\n        $sequence_2 = { 4829d7 48bdffffffffffffff7f 4889e9 4829f9 4839cb 0f879b010000 4d89fe }\n            // n = 7, score = 100\n            //   4829d7               | inc                 esp\n            //   48bdffffffffffffff7f     | jne    0xfffffff6\n            //   4889e9               | jmp                 0xd\n            //   4829f9               | mov                 eax, 0x445c91b1\n            //   4839cb               | jmp                 0xfffffff6\n            //   0f879b010000         | dec                 eax\n            //   4d89fe               | mov                 dword ptr [esp + 8], ecx\n\n        $sequence_3 = { 4c89e1 e8???????? 4829d8 4839e8 0f82dc010000 4801dd 4c8b6f18 }\n            // n = 7, score = 100\n            //   4c89e1               | dec                 eax\n            //   e8????????           |                     \n            //   4829d8               | lea                 ecx, [esi + 0x10]\n            //   4839e8               | inc                 ebp\n            //   0f82dc010000         | mov                 eax, dword ptr [eax]\n            //   4801dd               | dec                 eax\n            //   4c8b6f18             | mov                 eax, esi\n\n        $sequence_4 = { 85c0 0f8492010000 e9???????? 488b442448 49894608 8b442450 41894618 }\n            // n = 7, score = 100\n            //   85c0                 | mov                 ecx, dword ptr [esp]\n            //   0f8492010000         | mov                 ecx, 0x50ecbd49\n            //   e9????????           |                     \n            //   488b442448           | dec                 ecx\n            //   49894608             | mov                 ecx, edx\n            //   8b442450             | jmp                 0x688\n            //   41894618             | dec                 esp\n\n        $sequence_5 = { 48895818 48897020 488b05???????? 4833c4 488985f0010000 418bf0 4c8bf2 }\n            // n = 7, score = 100\n            //   48895818             | mov                 ecx, dword ptr [esp + 0x20]\n            //   48897020             | dec                 eax\n            //   488b05????????       |                     \n            //   4833c4               | mov                 edx, edi\n            //   488985f0010000       | dec                 ecx\n            //   418bf0               | mov                 eax, ebx\n            //   4c8bf2               | dec                 eax\n\n        $sequence_6 = { 57 4883ec30 488d6c2430 48c745f8feffffff 4889d6 4889cf 4c89c2 }\n            // n = 7, score = 100\n            //   57                   | dec                 ecx\n            //   4883ec30             | sub                 ebp, esi\n            //   488d6c2430           | mov                 eax, 0xcde3b609\n            //   48c745f8feffffff     | dec                 esp\n            //   4889d6               | lea                 esp, [ebp - 0x38]\n            //   4889cf               | cmp                 eax, 0xaaa31545\n            //   4c89c2               | je                  0xeee\n\n        $sequence_7 = { 488d4d08 41b80c000000 e8???????? 488d4d08 e8???????? 488d4dc8 4889c2 }\n            // n = 7, score = 100\n            //   488d4d08             | jmp                 0x1435\n            //   41b80c000000         | dec                 eax\n            //   e8????????           |                     \n            //   488d4d08             | mov                 dword ptr [esp + 0x20], edi\n            //   e8????????           |                     \n            //   488d4dc8             | dec                 eax\n            //   4889c2               | mov                 ecx, dword ptr [esp + 0x20]\n\n        $sequence_8 = { 488b442428 488b442420 488b442438 b800554687 e9???????? 488b4c2470 4831e1 }\n            // n = 7, score = 100\n            //   488b442428           | inc                 ecx\n            //   488b442420           | mov                 ecx, ebp\n            //   488b442438           | dec                 eax\n            //   b800554687           | mov                 dword ptr [esp + 0x38], eax\n            //   e9????????           |                     \n            //   488b4c2470           | mov                 eax, 0x886bf338\n            //   4831e1               | jmp                 0x9b7\n\n        $sequence_9 = { 81fa15b7785c 75f0 488b542410 48c7411000000000 ba251f32f5 ebdc }\n            // n = 6, score = 100\n            //   81fa15b7785c         | jne                 0x1a7\n            //   75f0                 | dec                 esp\n            //   488b542410           | mov                 ecx, edi\n            //   48c7411000000000     | jg                  0x136\n            //   ba251f32f5           | cmp                 eax, 0x45b54eab\n            //   ebdc                 | je                  0x19e\n\n    condition:\n        7 of them and filesize < 990208\n}')

CANDIRU_RULE_METADATA = {'MAL_DevilsTongue_HijackDll': {'identifier': 'MAL_DevilsTongue_HijackDll', 'author': 'Microsoft Threat Intelligence Center (MSTIC)', 'license': 'DRL 1.1', 'license_url': 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/LICENSE', 'source': 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_candiru.yar', 'filename': 'apt_candiru.yar'}, 'win_devilstongue_auto': {'identifier': 'win_devilstongue_auto', 'author': 'Felix Bilstein - yara-signator at cocacoding dot com', 'license': 'CC BY-SA 4.0', 'license_url': 'https://creativecommons.org/licenses/by-sa/4.0/', 'source': 'https://malpedia.caad.fkie.fraunhofer.de/details/win.devilstongue', 'filename': 'win_devilstongue_auto.yar'}}


# --- report ------------------------------------------------------------------
"""Human-readable + machine-readable reporting, and the overall verdict.

Doctrine enforced here:
  D1  Every run that finds nothing prints, verbatim, the mandatory closing line.
  D3  A module that could not run is UNKNOWN, never CLEAN; gaps are stated out
      loud in the interface, not buried.
  The verdict for a hit is "investigate", never "you are compromised" — an ad
  impression is not proof of infection (README / the IOC file header).
"""


import datetime
import copy
import json
import platform as _platform
import re
from typing import Any, Dict, List


# The exact text required by D1. Do not reword.
D1_LINE = ("No known indicators were found in the places that can be checked. "
           "This is not a clean bill of health.")

V_HITS = "INDICATORS_FOUND"
V_NONE_WITH_GAPS = "NO_KNOWN_INDICATORS_WITH_GAPS"
V_NONE = "NO_KNOWN_INDICATORS"


def _windows_release(release: str, version: str) -> str:
    """Correct Python's release string on Windows 11.

    platform.release() reports "10" on Windows 11, because the underlying
    GetVersionEx still reports major version 10 for compatibility. Windows 11 is
    build 22000 and up, so the build number in platform.version() is what
    actually distinguishes them. This matters because the JSON report is meant to
    be evidence: a report that names the wrong OS is a report someone has to
    double-check by hand.
    """
    if release != "10":
        return release
    try:
        build = int(version.split(".")[2])
    except (IndexError, ValueError):
        return release
    return "11" if build >= 22000 else release


def _platform_info() -> Dict[str, str]:
    system = _platform.system()
    release = _platform.release()
    version = _platform.version()
    if system == "Windows":
        release = _windows_release(release, version)
    return {
        "system": system,
        "release": release,
        "version": version,
        "machine": _platform.machine(),
        "python": _platform.python_version(),
    }


def build_document(iocs: IocSet, modules: List[ModuleResult],
                   started: datetime.datetime) -> Dict[str, Any]:
    hits_total = sum(len(m.hits) for m in modules)
    gaps: List[str] = []
    for m in modules:
        for c in m.checks:
            if not c.ran:
                gaps.append("{}/{}: {}".format(m.name, c.name, c.reason))
        # A module that produced NO checks at all is UNKNOWN - it observed
        # nothing - but has no failed Check to turn into a gap, so without this it
        # is invisible to the verdict and a "nothing found" reads as clean. The
        # common cause is a browser module on a machine where no supported browser
        # is installed, or on macOS/Linux before the platform paths existed.
        if m.status == UNKNOWN and not m.checks:
            gaps.append("{}: nothing in this check could run, so it cleared "
                        "nothing".format(m.name))

    if hits_total > 0:
        status = V_HITS
    elif gaps:
        status = V_NONE_WITH_GAPS
    else:
        status = V_NONE

    age = iocs.age_days()
    return {
        "tool": {"name": "adint-scan", "version": __version__},
        "timestamp": started.replace(microsecond=0).isoformat(),
        "platform": _platform_info(),
        "ioc_set": {
            "path": iocs.source_path,
            "count": len(iocs),
            "age_days": age,
            "stale": iocs.is_stale(),
        },
        "modules": {m.name: m.to_dict() for m in modules},
        "verdict": {
            "status": status,
            "hits_total": hits_total,
            "gaps": gaps,
        },
        # D1 line is present whenever nothing was found (CLEAN or with gaps).
        "doctrine_line": None if hits_total > 0 else D1_LINE,
        # Whether a "HOW TO TURN ON DNS HISTORY" block will actually be rendered,
        # so the summary's pointer to it does not dangle on a host where no reach
        # entry carried how_to_enable (e.g. a non-Windows machine).
        "_dns_howto": any(
            info.get("how_to_enable")
            for m in modules for info in (m.reach or {}).values()),
        "_indicators": iocs.network_strings,
    }


def write_json(document: Dict[str, Any], path: str) -> None:
    # The internal rendering flag is not part of the evidence record.
    doc = {k: v for k, v in document.items() if not k.startswith("_")}
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# --- human-readable rendering ----------------------------------------------

_RULE = "=" * 72


def _fmt_count(n: int) -> str:
    return "{:,}".format(n)


# Raw metric keys are developer shorthand. Say what each number is, in words,
# because "com_registrations=37" tells a reader nothing about whether 37 is bad.
_METRIC_LABELS = {
    "sqlite": "browser databases read",
    "blob": "cache / stored-data files searched",
    "hsts_entries": "HSTS security records checked (proof of past connections)",
    "connection_records": "saved connection records checked",
    "files_hashed": "files fingerprinted",
    "files_pattern_scanned": "files checked against Candiru patterns",
    "bytes_pattern_scanned": "bytes checked against Candiru patterns",
    "com_registrations": "auto-start COM registrations reviewed",
    "com_user_writable": "   of those, in a folder you can write to",
    "dns_cache_entries": "names in the DNS cache since last reboot",
    "dns_log_records": "DNS history records available",
    "dns_log_events_scanned": "DNS history events searched",
    "hosts_entries": "entries in the hosts file",
    "hosts_blocked_indicators": "   of those, indicators you are BLOCKING (good)",
    "known_paths_checked": "known malware file-paths checked",
    "known_paths_present": "   of those, a file is present at (see notes)",
}


def _describe_metrics(metrics: Dict[str, int]) -> List[str]:
    out = []
    for key, value in metrics.items():
        if key == "bytes_hashed":
            out.append("{:,.1f} GB of files read".format(value / 1e9))
            continue
        if key == "dns_log_enabled":
            out.append("Windows DNS history logging: {}".format(
                "ON" if value else "OFF (the Windows default)"))
            continue
        label = _METRIC_LABELS.get(key)
        if label is None:
            out.append("{}: {}".format(key, _fmt_count(value)))
        else:
            out.append("{}: {}".format(label, _fmt_count(value)))
    return out


def render_human(document: Dict[str, Any]) -> str:
    document = _human_document(document)
    out: List[str] = []
    w = out.append

    w(_RULE)
    w("  Zero Breach {}  —  AdFection / Candiru indicator check".format(
        document["tool"]["version"]))
    # The name must not be read as a promise. The tagline carries the tool's one
    # non-negotiable caveat right next to it, so a screenshot of the top of the
    # report cannot imply "you are safe".
    w("  Checks for TRACES of ad-delivered spyware. A clean result is NOT a")
    w("  clean bill of health - see what could not be checked, below.")
    w("  {}   {} {}".format(document["timestamp"],
                            document["platform"]["system"],
                            document["platform"]["release"]))
    w(_RULE)
    w("")

    # The answer first. Everything after it is the supporting evidence.
    out.extend(render_summary(document).split("\n"))

    ioc = document["ioc_set"]
    age = ioc["age_days"]
    age_txt = "unknown age" if age is None else "{} day(s) old".format(age)
    w("Indicator set : {} indicators, {}".format(ioc["count"], age_txt))
    if ioc["stale"]:
        w("  ** WARNING: this indicator set is more than 30 days old. Update it "
          "before trusting a clean result. **")
    w("")

    # Put the full indicator evidence after the coverage/DNS-history instructions.
    # The concise result and urgent next steps remain visible in the summary.
    _render_reach(w, document)

    w("DETAIL  —  what was examined, and the evidence behind the summary")
    w("")
    for name, m in document["modules"].items():
        took = (" in {:.0f}s".format(m["duration_s"])
                if m.get("duration_s") else "")
        w("--- {} check  [{}]{} ---".format(name, m["status"], took))
        w("    examined: {}    could not read: {}".format(
            _fmt_count(m["checked"]), _fmt_count(m["skipped"])))
        if m["submetrics"]:
            for line in _describe_metrics(m["submetrics"]):
                w("    {}".format(line))
        for note in m["notes"]:
            w("    note   : {}".format(note))
        if m["hits"]:
            # Strongest evidence first: someone reading this should see a sample
            # on disk or a proven contact before a string that merely appeared in
            # cached page text.
            order = {EV_ON_DISK: 0, EV_FILE_PATTERN: 0.5, EV_PERSISTENCE: 1, EV_CONTACTED: 2,
                     EV_DNS: 3, EV_ATTEMPTED: 4, EV_CONFIGURED: 5,
                     EV_REFERENCED: 6, "": 0}
            for h in sorted(m["hits"], key=lambda x: order.get(x.get("evidence", ""), 0)):
                prov = "{}/{}".format(h["tier"], h["confidence"]) if h["tier"] else "?"
                ev = h.get("evidence") or "unclassified"
                w("    !! HIT  {}  [{}]  evidence: {}".format(
                    _defang(h["indicator"]), prov, ev.upper()))
                gloss = _evidence_gloss(h)
                if gloss:
                    w("            meaning: {}".format(gloss))
                if h.get("profile"):
                    w("            account: {}".format(h["profile"]))
                w("            at     : {}".format(
                    _defang_text(h["location"], h["indicator"])))
                w("            detail : {}".format(
                    _defang_text(h["detail"], h["indicator"])))
                if h.get("observed"):
                    w("            when   : {}".format(
                        _defang_text(h["observed"], h["indicator"])))
                if h.get("source"):
                    w("            source : {}".format(h["source"]))
        w("")

    v = document["verdict"]
    w(_RULE)
    if v["status"] == V_HITS:
        w("VERDICT: {} indicator(s) matched.".format(v["hits_total"]))
        w("")
        counts = {}
        for m in document["modules"].values():
            for h in m["hits"]:
                key = h.get("evidence") or "unclassified"
                counts[key] = counts.get(key, 0) + 1
        w("  By evidence strength: " + ", ".join(
            "{} {}".format(n, k) for k, n in sorted(counts.items())))
        w("")
        w("  Follow the next steps in the summary. The indicator's role and the")
        w("  evidence type determine those steps; the number of matches does not.")
        w("  A match means INVESTIGATE, not 'you are compromised'.")
        w("  A match does not by itself establish that spyware ran on this device.")
    else:
        if v["gaps"]:
            w("VERDICT: no known indicators found IN WHAT COULD BE CHECKED.")
            w("")
            w("Checks that could NOT run (a gap is not a clean result):")
            for g in v["gaps"]:
                w("  - {}".format(g))
            w("")
        else:
            w("VERDICT: no known indicators found in any check that ran.")
            w("")
        # D1: the mandatory closing line, verbatim.
        w(document["doctrine_line"])
        w("")
    w("")
    _support_options(w)
    w(_RULE)
    return _defang_report("\n".join(out), document)


# The window the AdFection campaign was actually active, from the Citizen Lab
# report: at least 45 targeted devices at Al Jazeera during 2024-2025. If the
# evidence on this machine does not reach back that far, the honest thing is to say
# the check could not have covered it, rather than let a clean result imply it did.
CAMPAIGN_FROM = datetime.date(2024, 1, 1)
CAMPAIGN_TO = datetime.date(2025, 12, 31)
CAMPAIGN_LABEL = "2024-2025 (the documented campaign period)"


def overlap_statement(earliest: datetime.date, source: str) -> List[str]:
    """Compare the dates reported by this scan with the campaign window.

    Unread or out-of-scope records may be older; an oldest date does not prove
    that records cover every day since then or that missing evidence is gone.
    """
    if earliest > CAMPAIGN_TO:
        return [
            "** The oldest dated evidence reported by this scan is {} ({}).".format(
                source,
                earliest.isoformat()),
            "   The campaign this tool searches for was active in {}.".format(
                CAMPAIGN_LABEL),
            "   Those dates DO NOT OVERLAP. The dates reported here do not reach",
            "   the campaign period. Older or unread records may still exist;",
            "   this scan cannot rule out past contact during that period. **",
        ]
    if earliest > CAMPAIGN_FROM:
        return [
            "** The oldest dated evidence reported by this scan is {} ({}).".format(
                source, earliest.isoformat()),
            "   That reaches PART of the campaign period ({}),".format(CAMPAIGN_LABEL),
            "   from {} onwards, and only through that one kind of record.".format(
                earliest.isoformat()),
            "   This does not establish continuous coverage from that date.",
            "   Older or unread records may still exist. A clean result cannot",
            "   rule out past contact during the campaign period. **",
        ]
    return [
        "** The oldest dated evidence reported by this scan is {} ({}), which predates".format(
            source, earliest.isoformat()),
        "   the campaign period. This does not establish continuous coverage",
        "   through that period. Surviving records are never everything, and a",
        "   clean result cannot rule out past contact during that period. **",
    ]


def _render_reach(w, document: Dict[str, Any]) -> None:
    """Say how far back the evidence reaches. A clean result over 11 weeks and a
    clean result over 3 years are different findings, and the reader cannot tell
    them apart unless the tool says which one it just produced."""
    entries = []
    for mod_name, m in document["modules"].items():
        for label, info in (m.get("reach") or {}).items():
            entries.append((mod_name, label, info))
    if not entries:
        return

    w(_RULE)
    w("HOW FAR BACK THIS SCAN COULD SEE")
    w("")
    w("  These dates come from the records examined by this scan. They do not")
    w("  establish a complete history; older or unread records may still exist:")
    w("")

    earliest_overall = None
    earliest_source = ""
    for mod_name, label, info in entries:
        earliest = info.get("earliest")
        days = info.get("days")
        when = "unknown (no date established)" if not earliest else earliest[:10]
        age = ""
        if isinstance(days, int) and earliest:
            age = "  ({} days ago)".format(days)
        w("  {}/{}".format(mod_name, label))
        w("      reaches back to : {}{}".format(when, age))
        w("      basis           : {}".format(info.get("basis", "")))
        if info.get("note"):
            w("      {}".format(info["note"]))
        w("")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if earliest_overall is None or d < earliest_overall:
                    earliest_overall = d
                    earliest_source = "{}/{}".format(mod_name, label)
            except ValueError:
                pass

    # How many artifacts actually date from inside the campaign window. This is
    # the number that answers "could this scan have seen it?", where the oldest
    # surviving file only answers "how far back does anything reach?".
    in_window = 0
    total_dated = 0
    for _mod_name, _label, info in entries:
        by_year = info.get("by_year") or {}
        for year, count in by_year.items():
            year = int(year)
            total_dated += count
            if CAMPAIGN_FROM.year <= year <= CAMPAIGN_TO.year:
                in_window += count

    if earliest_overall is not None:
        for line in overlap_statement(earliest_overall, earliest_source):
            w("  " + line)
        w("")

    # Does ANY reach record - cookie ages, DNS, not just the cache files that
    # carry by_year - reach into the campaign window? This decides whether the
    # absolute "nothing dates from the campaign period" sentence is even true.
    something_in_window = False
    for _mod_name, _label, info in entries:
        earliest = info.get("earliest")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if d <= CAMPAIGN_TO:
                    something_in_window = True
            except ValueError:
                pass

    if total_dated:
        merged = {}
        for _mod_name, _label, info in entries:
            for year, count in (info.get("by_year") or {}).items():
                year = int(year)
                merged[year] = merged.get(year, 0) + count

        w("  Age of the browser cache files searched, by year (cache files only,")
        w("  not cookies or DNS - those are summarised above):")
        w("      " + "   ".join("{}: {:,}".format(y, merged[y])
                                for y in sorted(merged)))
        w("")
        pct = 100.0 * in_window / total_dated
        w("  Of those cache files, dating from the campaign period ({}-{}): "
          "{:,} of {:,} ({:.1f}%).".format(
              CAMPAIGN_FROM.year, CAMPAIGN_TO.year, in_window, total_dated, pct))

        # A per-year floor matters more than the total: the campaign ran across
        # several years, and a year with almost nothing left is a year this scan
        # cannot speak about, however healthy the overall percentage looks.
        sparse = [y for y in range(CAMPAIGN_FROM.year, CAMPAIGN_TO.year + 1)
                  if merged.get(y, 0) < 100]
        if in_window == 0 and not something_in_window:
            w("  No dated evidence summarised here reaches the campaign period.")
            w("  Older or unread records may still exist. A clean result cannot")
            w("  rule out past contact during that period.")
        elif in_window == 0 and something_in_window:
            w("  No browser CACHE file examined dates from the campaign period, though some")
            w("  older evidence (shown above) does. Cache is the thinnest record;")
            w("  the window above is the one to read.")
        elif sparse:
            w("  BUT cache coverage is uneven. These campaign years have almost no")
            w("  surviving cache, so a clean result says little about them:")
            for y in sparse:
                w("      {}: {:,} cache file(s)".format(y, merged.get(y, 0)))
        w("")

    # The actionable part, rendered as its own ruled-off section so the one thing
    # a reader can act on does not get lost at the tail of the reach block.
    howto = []
    for _mod_name, _label, info in entries:
        howto.extend(info.get("how_to_enable") or [])
    if howto:
        w("")
        w(_RULE)
        for line in howto:
            w(line)
        w(_RULE)
    w("")


# What a hit in each tier actually MEANS, in plain language. The tier is the
# whole point of curating the indicator set: contact with an ad tracker and
# contact with a command-and-control server are different events, and a report
# that renders them identically has failed the person reading it.
TIER_MEANING = {
    "delivery": ("Advertising/tracking infrastructure belonging to this network. "
                 "The evidence grade says what was observed; a DNS record or "
                 "saved reference does not prove an ad reached this device. "
                 "An ad impression is NOT evidence of infection."),
    "cc": ("A Candiru command-and-control server. This is the most serious "
           "class of indicator - it is the address an active implant talks to."),
    "validator": ("A Candiru validator server. These profiled a device and "
                  "decided, per device, whether to deliver an exploit. Contact "
                  "suggests this device was being assessed as a target."),
    "candiru": ("A server attributed to Candiru by Recorded Future. Its exact "
                "role is not published, so treat it as serious but unspecified."),
    "candiru-ip": ("An IP address attributed to Candiru infrastructure in 2025. "
                   "Weak on its own: cloud IP addresses are reassigned to "
                   "unrelated, innocent customers within months."),
    "historical": ("Infrastructure from separate, older Candiru campaigns. "
                   "Interpret dated evidence in the cited report's context; "
                   "current ownership and activity are not established."),
    "sample": ("The file fingerprint of a published Candiru sample. A match "
               "here is conclusive, not circumstantial."),
    "candiru-pattern": ("A published Candiru detection rule matched patterns "
                        "inside a file. This needs expert verification; it is "
                        "not an exact sample identification or proof that "
                        "spyware ran."),
    "vuln-driver": ("A LEGITIMATE, signed third-party driver that this actor "
                    "abuses to disable protections (bring-your-own-vulnerable-"
                    "driver). The file itself is not spyware and is present on "
                    "clean machines that genuinely use that hardware or "
                    "software. This is a lead worth checking - who installed "
                    "it, and when - NOT evidence that spyware is on this "
                    "machine."),
}

# Tiers whose file hashes identify legitimate software this actor abuses, rather
# than the spyware itself. A match must never be reported as proof of infection:
# the same file sits on clean machines for honest reasons (see `vuln-driver`).
NOT_MALWARE_TIERS = {"vuln-driver"}

EVIDENCE_MEANING = {
    EV_FILE_PATTERN: ("patterns inside a file matched a published detection "
                      "rule. This is a lead for investigation, not a confirmed "
                      "infection or an exact known-file match"),
    EV_ON_DISK: ("a file on this machine has the fingerprint of a published "
                 "spyware sample - this is conclusive, not circumstantial"),
    # Same grade, different claim: see _on_disk_gloss(). A legitimate-but-abused
    # driver sits on disk too, and saying "conclusive" about it would be false.
    EV_PERSISTENCE: ("the name is registered to run automatically on this "
                     "machine - a hallmark of installed spyware"),
    EV_CONTACTED: "this device demonstrably communicated with it",
    EV_DNS: ("the name or address appears in local DNS data; this does not "
             "establish communication with the indicated server, and a logged "
             "lookup may have failed"),
    EV_ATTEMPTED: ("something on this device looked the name up, but a filter "
                   "blocked the connection"),
    EV_CONFIGURED: ("the name is in local configuration pointing at a real "
                    "address (a protective block entry is not reported at all)"),
    EV_REFERENCED: ("the name appeared in saved page content - most often a page "
                    "ABOUT this campaign, not contact with it"),
}

# A short imperative headline per grade, used in the summary. The ones that are
# not EV_REFERENCED are serious and each gets its own, so a sample on disk and a
# persistence entry can never be rendered as "probably nothing".
EVIDENCE_HEADLINE = {
    EV_FILE_PATTERN: "A FILE MATCHED A CANDIRU DETECTION RULE - NEEDS REVIEW",
    EV_ON_DISK: "A KNOWN SPYWARE FILE IS ON THIS MACHINE",
    EV_PERSISTENCE: "SOMETHING IS SET TO RUN AUTOMATICALLY FROM THIS INFRASTRUCTURE",
    EV_CONTACTED: "THIS DEVICE CONTACTED THIS INFRASTRUCTURE",
    EV_DNS: "THIS INDICATOR APPEARS IN LOCAL DNS RECORDS",
    EV_ATTEMPTED: "THIS DEVICE TRIED TO REACH THIS INFRASTRUCTURE (a filter blocked it)",
    EV_CONFIGURED: "THIS INFRASTRUCTURE IS CONFIGURED ON THIS MACHINE",
}


# A file-on-disk hit means two very different things depending on what the file
# IS. The grade (EV_ON_DISK) is the same either way, so the claim has to be
# chosen from the tier, not from the grade alone.
ON_DISK_NOT_MALWARE_HEADLINE = (
    "A LEGITIMATE FILE THIS ATTACKER IS KNOWN TO ABUSE IS ON THIS MACHINE")
ON_DISK_NOT_MALWARE_GLOSS = (
    "this file is NOT spyware - it is signed, legitimate software that this "
    "actor loads to disable protections. It is also installed for honest "
    "reasons. Worth establishing how it got here; not proof of anything")


def _headline_for(hit) -> str:
    """The summary headline for one serious hit, chosen by grade AND tier."""
    if hit.get("tier") in NOT_MALWARE_TIERS and hit.get("evidence") == EV_ON_DISK:
        return ON_DISK_NOT_MALWARE_HEADLINE
    if hit.get("evidence") == EV_ON_DISK and hit.get("tier") != "sample":
        return "A FILE FINGERPRINT MATCHED; ITS CLASSIFICATION NEEDS REVIEW"
    if hit.get("tier") == "candiru-ip" and hit.get("evidence") == EV_CONTACTED:
        return "THIS DEVICE CONTACTED A HISTORICALLY ATTRIBUTED IP ADDRESS"
    return EVIDENCE_HEADLINE.get(hit.get("evidence"), "A SERIOUS INDICATOR MATCHED")


def _evidence_gloss(hit) -> str:
    """What this grade establishes for this hit (tier-aware, same reason)."""
    if hit.get("tier") in NOT_MALWARE_TIERS and hit.get("evidence") == EV_ON_DISK:
        return ON_DISK_NOT_MALWARE_GLOSS
    if hit.get("evidence") == EV_ON_DISK and hit.get("tier") != "sample":
        return ("a file fingerprint matched an indicator, but its classification "
                "does not identify it as a known spyware sample; expert review "
                "is needed")
    if hit.get("tier") == "candiru-ip" and hit.get("evidence") == EV_CONTACTED:
        return ("a connection record names this IP address; who controlled it "
                "at the time is not established by this match")
    return EVIDENCE_MEANING.get(hit.get("evidence") or "", "")


def _defang(indicator: str) -> str:
    """Make an indicator safe to paste into an email or chat without a client,
    gateway or link scanner auto-fetching it. The report is designed to be
    forwarded to Access Now / Amnesty, and the tool's own rule is never to
    contact an indicator - so it must not ship them in a fetchable form. The JSON
    report keeps the raw value; only the human text is defanged."""
    out = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Neuter the last dot (domains) or wrap every dot (IPs) so nothing resolves.
    if any(c.isalpha() for c in indicator) and "." in out:
        head, _, tail = out.rpartition(".")
        return "{}[.]{}".format(head, tail)
    return out.replace(".", "[.]")


# A URL scheme is all a mail gateway, link preview or security scanner needs in
# order to fetch the thing. ftp:// is covered too, because a detail line quotes
# whatever was in the saved page.
_SCHEMES = {"https://": "hxxps://", "http://": "hxxp://", "ftp://": "fxp://"}
_SCHEME_RE = re.compile("|".join(_SCHEMES), re.IGNORECASE)


def _defang_text(text: str, indicator: str) -> str:
    """Defang the indicator traces inside a free-text field - a detail line, a
    path - and change nothing else about it.

    Two passes, and only two. Schemes are neutered wherever they appear, because
    a detail line quotes saved page content and a live https:// in there is
    fetchable straight out of the report. Then the indicator's own value is
    swapped for whatever _defang() renders it as, so the two places a reader
    sees the same name agree. That match is case-insensitive: the browser module
    lowercases the text it quotes, while the indicator need not be lowercase.

    Deliberately NOT a general "wrap every dot" pass. A location is usually a
    Windows path - "C:\\Users\\x\\AppData\\...\\Network\\Cookies" - and blanket
    dot-wrapping would mangle real file and folder names into something the
    person acting on this report can no longer find on their own disk.
    """
    out = _SCHEME_RE.sub(lambda m: _SCHEMES[m.group(0).lower()], str(text))
    defanged = _defang(indicator) if indicator else indicator
    if indicator and defanged != indicator:
        out = re.sub(re.escape(indicator), lambda _m: defanged, out,
                     flags=re.IGNORECASE)
    return out


# Artifact-derived text is attacker-influenced: a browser profile's display name,
# a registry value, a page title. Rendered raw, a newline or a terminal escape
# inside one can forge whole report lines - a fake "VERDICT: no known indicators
# found" printed under a real hit, which survives being pasted into an email to a
# helpline. Control characters, Unicode line separators and bidirectional
# overrides (which can visually reverse a line without any newline) are
# replaced, and newlines collapse to spaces so a field can never begin a line of
# its own. The JSON report keeps the raw evidence.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _safe_text(value, limit=2000):
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = _UNSAFE_CHARS.sub("�", text)
    return text if len(text) <= limit else text[:limit] + "…"


# Tighter limits for the single-line fields an attacker can fill most freely.
_HIT_FIELD_LIMITS = {"profile": 120, "observed": 64, "location": 500,
                     "detail": 500}


def _human_document(document):
    """Sanitize artifact-derived fields without changing the JSON evidence.

    Notes and gaps can quote remote paths just as hits can. Published source
    citations and the fixed help links remain usable.
    """
    doc = copy.deepcopy(document)

    def scrub(value, limit=2000):
        if isinstance(value, str):
            return _defang_text(_safe_text(value, limit), "")
        if isinstance(value, list):
            return [scrub(item, limit) for item in value]
        if isinstance(value, dict):
            return {key: scrub(item, limit) for key, item in value.items()}
        return value

    for module in doc["modules"].values():
        for key in ("notes", "checks", "reach"):
            if key in module:
                module[key] = scrub(module[key])
        for hit in module["hits"]:
            for key in ("location", "detail", "observed", "profile"):
                if key in hit:
                    hit[key] = scrub(hit[key], _HIT_FIELD_LIMITS[key])
    doc["verdict"]["gaps"] = scrub(doc["verdict"].get("gaps", []))
    return doc


def _defang_report(text, document):
    """Cover every occurrence, including notes and another hit's details."""
    indicators = set(document.get("_indicators", []))
    indicators.update(hit["indicator"] for module in document["modules"].values()
                      for hit in module["hits"])
    for indicator in sorted(indicators, key=len, reverse=True):
        if indicator and _defang(indicator) != indicator:
            text = re.sub(re.escape(indicator), lambda m: _defang(m.group(0)),
                          text, flags=re.IGNORECASE)
    return text


def _recommended_action(hit) -> int:
    """Human next steps, separate from evidence grades and the JSON verdict.

    0: saved context; 1: self-review; 2: qualified interpretation;
    3: prompt expert help. Unknown metadata never becomes reassurance.
    """
    evidence, tier = hit.get("evidence"), hit.get("tier")
    if evidence == EV_REFERENCED:
        return 0
    if evidence == EV_ON_DISK and tier == "vuln-driver":
        return 1
    if evidence in (EV_ON_DISK, EV_PERSISTENCE):
        return 3
    if (tier in ("delivery", "candiru-ip") and
            evidence in (EV_CONTACTED, EV_DNS, EV_ATTEMPTED, EV_CONFIGURED)):
        return 1
    return 2


def _advice_paragraph(w, text):
    for line in _wrap(text, 66):
        w("    " + line)


def _next_steps(w, hits):
    action = max(_recommended_action(h) for h in hits)
    w("  WHAT TO DO")
    if any(h.get("evidence") == EV_FILE_PATTERN for h in hits):
        _advice_paragraph(w, "A file matched a Candiru pattern rule. Ask a "
                         "qualified incident responder to verify the named file "
                         "and rule. Preserve the file and this report; do not "
                         "open, run or delete the file. A pattern match alone "
                         "does not prove infection or that the file executed.")
        w("")
        if all(h.get("evidence") in (EV_FILE_PATTERN, EV_REFERENCED) for h in hits):
            return
    if action == 3:
        _advice_paragraph(w, "Seek expert help promptly. Preserve this report and "
                         "the named files or registrations. Do NOT delete, move, "
                         "run or try to clean them. A file match establishes "
                         "presence; a registration establishes configuration. "
                         "Neither alone establishes that spyware executed.")
        w("")
        _advice_paragraph(w, "Contact a qualified incident responder or your "
                         "organisation's security team. You do not need to "
                         "finish investigating first. Support options are at "
                         "the end of this report.")
    elif action == 2:
        _advice_paragraph(w, "Qualified interpretation is recommended. Review "
                         "the evidence type, saved date and location below. "
                         "A DNS record may be a failed lookup; it does not "
                         "establish a connection. Missing or unrecognised "
                         "evidence labels also need review, not reassurance.")
        w("")
        _advice_paragraph(w, "A connection record for command-and-control, "
                         "validator or other attributed spyware infrastructure "
                         "warrants specialist review. For a DNS-only or "
                         "configuration finding, seek qualified help if the "
                         "local context does not explain it, or if you have "
                         "a credible reason to believe you are being targeted. "
                         "These records do not by themselves establish infection.")
        w("")
        _advice_paragraph(w, "Keep the report and original records. Do NOT delete "
                         "or clean them while arranging review. Your organisation's "
                         "security team or a qualified incident responder can help.")
    else:
        _advice_paragraph(w, "Start with the saved evidence below. Check the "
                         "indicator's role, evidence type, browser/profile, "
                         "date (if available), and file or record that matched. "
                         "Use the report and existing records; do not visit "
                         "the indicator to investigate it.")
        if any(h.get("tier") == "delivery" and h.get("evidence") in
               (EV_CONTACTED, EV_DNS, EV_ATTEMPTED) for h in hits):
            w("")
            _advice_paragraph(w, "Advertising-network records alone do not show "
                             "that you were selected for an exploit or infected. "
                             "A connection can result from an ordinary ad; a "
                             "DNS record does not even establish that connection. "
                             "This finding alone does not call for a spyware "
                             "helpline referral.")
        if any(h.get("tier") == "vuln-driver" and
               h.get("evidence") == EV_ON_DISK for h in hits):
            w("")
            _advice_paragraph(w, "For the legitimate driver, check whether its "
                             "location and installation history match hardware "
                             "or software you use. Your IT support or the "
                             "software vendor can help identify it. Do not "
                             "delete it solely because of this match.")
        if any(h.get("tier") == "candiru-ip" for h in hits):
            w("")
            _advice_paragraph(w, "For a historical IP address, ownership can change. "
                             "The tool has not established who controlled it "
                             "at the time of this record. Check the saved date "
                             "against the cited research; an absent date leaves "
                             "that question unresolved.")
        if any(h.get("evidence") == EV_CONFIGURED for h in hits):
            w("")
            _advice_paragraph(w, "For a configuration entry, check who or what "
                             "created it and why. An ordinary ad impression "
                             "does not explain a local hosts-file entry. "
                             "Do not edit it merely to make this finding disappear.")
        w("")
        _advice_paragraph(w, "Keep the report. If you cannot explain a finding, "
                         "ask trusted IT support for help interpreting it. "
                         "Stronger findings or a credible targeting concern "
                         "warrant qualified security help directly; you do not "
                         "have to complete these steps first.")
    w("")
    _advice_paragraph(w, "Do NOT open, visit or look up indicator addresses. Keep "
                     "the [.] spelling when sharing them.")


def _support_options(w):
    w("WHEN TO SEEK SUPPORT")
    w("A credible targeting concern or a genuine security notification warrants")
    w("qualified help regardless of this scan's result. You do not need to")
    w("complete self-checks first. Contact your organisation's security team")
    w("or a qualified incident responder.")
    w("")
    w("For journalists, activists, human-rights defenders and other civil")
    w("society members, Access Now offers a Digital Security Helpline:")
    w("  https://www.accessnow.org/help/")
    w("  Eligibility and support: https://www.accessnow.org/help/helpline-faq/")
    w("Check its intake instructions before sending private evidence.")
    w("")
    w("Research and further guidance:")
    w("  Amnesty International Security Lab  https://securitylab.amnesty.org/")
    w("  The Citizen Lab                     https://citizenlab.ca/")
    w("")
    w("A saved reference or advertising-network trace alone is not a reason")
    w("to assume spyware infection. No result from this tool rules it out.")


def render_summary(document: Dict[str, Any]) -> str:
    """The part a person actually reads. Answers, in order: what was found, what
    it means, what to do, and what this scan could not check.

    Everything below this in the report is the evidence for these few lines."""
    document = _human_document(document)
    out: List[str] = []
    w = out.append
    v = document["verdict"]

    all_hits = [h for _m, m in document["modules"].items() for h in m["hits"]]
    serious = [h for h in all_hits if is_serious(h.get("evidence", ""))]
    benign = [h for h in all_hits if not is_serious(h.get("evidence", ""))]

    w(_RULE)
    w("  SUMMARY  —  read this part")
    w(_RULE)

    if not all_hits:
        w("  RESULT: no known indicator was found in anything that could be")
        w("          checked.")
        w("")
        w("  This is NOT a clean bill of health. See the two sections below for")
        w("  what was searched and, more importantly, what could not be.")
    elif serious:
        n = len(serious)
        action = max(_recommended_action(h) for h in serious)
        if action == 3:
            w("  RESULT: SERIOUS FINDING - seek expert help promptly.")
        elif action == 2:
            w("  RESULT: potentially SERIOUS finding - qualified review recommended.")
        else:
            w("  RESULT: {} finding{} to review; start with the saved context.".format(
                n, "" if n == 1 else "s"))
        if benign:
            nb = len(benign)
            w("          ({} further match{} {} only {} in saved page "
              "content.)".format(
                  nb, "" if nb == 1 else "es", "is" if nb == 1 else "are",
                  "a reference" if nb == 1 else "references"))
        w("")
        w("  WHAT WAS FOUND")
        # Strongest grade first; collapse repeats of the same indicator+grade so
        # one domain in three cache files is not three lines.
        for h in sorted(_dedup_serious(serious),
                        key=_recommended_action, reverse=True):
            headline = _headline_for(h)
            w("    >> {}".format(headline))
            w("       {}  [{}]".format(_defang(h["indicator"]), h["tier"]))
            meaning = TIER_MEANING.get(h["tier"])
            if meaning:
                for line in _wrap(meaning, 64):
                    w("          " + line)
            if h.get("profile"):
                w("          Account: {}".format(h["profile"]))
            if h.get("observed"):
                w("          When: {}".format(h["observed"][:19].replace("T", " ")))
            w("          Where: {}".format(
                _defang_text(h["location"], h["indicator"])))
            w("")
        _next_steps(w, serious)
        if benign:
            n_b = len(benign)
            w("")
            w("    The {} reference-only match{} {} listed in DETAIL. Saved text".format(
                  n_b, "" if n_b == 1 else "es", "is" if n_b == 1 else "are"))
            w("    can mention an indicator without a connection to it.")
    else:
        n = len(benign)
        w("  RESULT: {} match{} found, all of them reference-only.".format(
            n, "" if n == 1 else "es"))
        w("")
        w("  WHAT THIS PROBABLY IS")
        for line in _wrap(
                "These matches are names found in saved content, such as page "
                "text, an unvisited bookmark or browser storage. A reference "
                "does not establish a connection, execution or infection. "
                "Check the saved title, location and date in DETAIL without "
                "opening the indicator address. A reference alone is probably "
                "not a sign of compromise; it does not clear the device either.", 68):
            w("    " + line)
        w("")
        _advice_paragraph(w, "A reference alone does not call for a helpline "
                         "referral. If you have a credible targeting concern "
                         "or a genuine security notification, seek qualified "
                         "help directly regardless of this result.")

    gaps = v.get("gaps") or []
    if gaps:
        w("")
        w("  WHAT COULD NOT BE CHECKED  ({} gap{})".format(
            len(gaps), "" if len(gaps) == 1 else "s"))
        shown = gaps[:4]
        for g in shown:
            for i, line in enumerate(_wrap(g, 66)):
                w("    " + ("- " if i == 0 else "  ") + line)
        if len(gaps) > len(shown):
            w("    ... and {} more, listed in full at the end of this report."
              .format(len(gaps) - len(shown)))
        # The DNS gap is the one a reader can actually close - but only point at
        # the instructions if they were actually rendered (they are not on a
        # non-Windows host), or the pointer dangles.
        if document.get("_dns_howto") and any("dns" in g.lower() for g in gaps):
            w("")
            w("    -> You can fix the DNS gap for next time, in one command.")
            w("       See \"HOW TO TURN ON DNS HISTORY\" further down. It tells you")
            w("       nothing about the past, but it means a future check can")
            w("       actually answer the question.")
    # Every report, not only one with findings. A clean or reference-only result
    # is the one people are most relaxed about posting publicly to say "I'm
    # fine" - and it carries the same usernames, profile names and paths.
    w("")
    for line in _wrap(_PRIVACY_NOTE, 68):
        w("  " + line)
    w(_RULE)
    w("")
    return _defang_report("\n".join(out), document)


_PRIVACY_NOTE = ("Before you share this report: it can contain your Windows "
                 "username, browser profile names, file paths and browsing "
                 "details. Ask a responder how to share evidence securely; "
                 "do not post the full report publicly.")


def _dedup_serious(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeats of the same indicator at the same grade, strongest grade
    first, so one domain found in three cache files is one line, not three."""
    order = {g: i for i, g in enumerate(
        [EV_ON_DISK, EV_PERSISTENCE, EV_CONTACTED, EV_DNS, EV_ATTEMPTED, EV_CONFIGURED])}
    seen = {}
    for h in hits:
        key = (h["indicator"], h.get("evidence", ""))
        if key not in seen:
            seen[key] = h
    return sorted(seen.values(),
                  key=lambda h: order.get(h.get("evidence", ""), 99))


def _wrap(text: str, width: int) -> List[str]:
    words, lines, cur = text.split(), [], ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        lines.append(cur)
    return lines


def _referrals(w) -> None:
    w("  - Access Now Digital Security Helpline  https://www.accessnow.org/help/")
    w("  - Amnesty International Security Lab     https://securitylab.amnesty.org/")
    w("  - The Citizen Lab                        https://citizenlab.ca/")


# --- modules/browser ---------------------------------------------------------
"""Search this machine's browser artifacts for AdFection / Candiru IOC domains.

Why several artifact types and not just history: browser HISTORY only records
top-level navigations, and an ad is a subresource inside an iframe. A real
AdFection impression would almost certainly never appear in history. The HTTP
cache, the cookie stores and the local-storage LevelDB files do record
subresource origins, so they are where a retrospective trace would actually
survive.

Read-only. Databases are copied before being opened, because a running browser
holds a write lock on them; the copy is opened and the temp dir is always
cleaned up. No network, ever (CONTRACT D2) - needles are matched as plain
substrings and never resolved.

Honest gaps (CONTRACT D3). A browser's databases are often locked because the
browser is running. That is NOT a clean result, it is a gap: there was somewhere
to look and we could not look there. So this module tracks, per (browser label,
artifact kind), whether at least one profile could actually be read. A kind that
was present somewhere but could never be read is reported with
`r.could_not_run(...)`, which the verdict reads as a gap - rather than being
silently swallowed into a clean roll-up. A kind that is simply ABSENT (the
browser never created that artifact) is not a gap and is recorded as nothing at
all. A browser whose every database was locked therefore rolls up to
PARTIAL/UNKNOWN with those gaps named, never to CLEAN.
"""


import base64
import datetime
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from urllib.parse import urlsplit


NAME_BROWSER = "browser"

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")


def _chromium_roots():
    """Chromium user-data roots as (label, path), chosen by platform.

    The label names the browser in each per-artifact sub-check, so an
    installed-but-clean browser is recorded distinctly from an absent one, and a
    locked artifact names the browser it belongs to. Tests override the roots by
    patching CHROMIUM_ROOTS / FIREFOX_ROOTS directly (not by patching LOCAL /
    ROAMING), so the suite is hermetic on every platform, never the tester's own
    browser.
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return [
            ("chrome", os.path.join(LOCAL, "Google", "Chrome", "User Data")),
            ("edge", os.path.join(LOCAL, "Microsoft", "Edge", "User Data")),
            ("brave", os.path.join(LOCAL, "BraveSoftware", "Brave-Browser",
                                   "User Data")),
            ("chromium", os.path.join(LOCAL, "Chromium", "User Data")),
            ("vivaldi", os.path.join(LOCAL, "Vivaldi", "User Data")),
        ]
    if sys.platform == "darwin":
        asup = os.path.join(home, "Library", "Application Support")
        return [
            ("chrome", os.path.join(asup, "Google", "Chrome")),
            ("edge", os.path.join(asup, "Microsoft Edge")),
            ("brave", os.path.join(asup, "BraveSoftware", "Brave-Browser")),
            ("chromium", os.path.join(asup, "Chromium")),
            ("vivaldi", os.path.join(asup, "Vivaldi")),
        ]
    if sys.platform.startswith("linux"):
        cfg = os.path.join(home, ".config")
        var = os.path.join(home, ".var", "app")
        snap = os.path.join(home, "snap")
        return [
            ("chrome", os.path.join(cfg, "google-chrome")),
            ("chromium", os.path.join(cfg, "chromium")),
            ("brave", os.path.join(cfg, "BraveSoftware", "Brave-Browser")),
            ("edge", os.path.join(cfg, "microsoft-edge")),
            ("vivaldi", os.path.join(cfg, "vivaldi")),
            ("vivaldi-snapshot", os.path.join(cfg, "vivaldi-snapshot")),
            # snap packaging
            ("chromium-snap", os.path.join(snap, "chromium", "common", "chromium")),
            # flatpak packaging
            ("chrome-flatpak", os.path.join(var, "com.google.Chrome", "config",
                                            "google-chrome")),
            ("brave-flatpak", os.path.join(var, "com.brave.Browser", "config",
                                           "BraveSoftware", "Brave-Browser")),
            ("chromium-flatpak", os.path.join(var, "org.chromium.Chromium",
                                              "config", "chromium")),
            ("vivaldi-flatpak", os.path.join(var, "com.vivaldi.Vivaldi",
                                             "config", "vivaldi")),
        ]
    return []


# Computed at import so the test-suite can monkeypatch this attribute directly.
CHROMIUM_ROOTS = _chromium_roots()

# Firefox (profiles_dir, cache_dir) pairs. None means "derive from the platform
# at run() time"; tests set an explicit list so the suite never reads the real
# profile on any OS (the Windows branch of _firefox_roots used to be the only one
# the tests could neutralise, which let the suite read the tester's real Firefox
# on macOS/Linux).
FIREFOX_ROOTS = None


def _firefox_roots():
    """Firefox (profiles_dir, cache_dir) pairs by platform.

    Evaluated at run() time so the Windows pair reflects the current LOCAL /
    ROAMING globals (which the tests override to neutralise it). Returns [] on a
    platform with no known Firefox location.
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return [(os.path.join(ROAMING, "Mozilla", "Firefox", "Profiles"),
                 os.path.join(LOCAL, "Mozilla", "Firefox", "Profiles"))]
    if sys.platform == "darwin":
        return [(os.path.join(home, "Library", "Application Support", "Firefox",
                              "Profiles"),
                 os.path.join(home, "Library", "Caches", "Firefox", "Profiles"))]
    if sys.platform.startswith("linux"):
        return [
            (os.path.join(home, ".mozilla", "firefox"),
             os.path.join(home, ".cache", "mozilla", "firefox")),
            # snap packaging
            (os.path.join(home, "snap", "firefox", "common", ".mozilla",
                          "firefox"),
             os.path.join(home, "snap", "firefox", "common", ".cache", "mozilla",
                          "firefox")),
            # flatpak packaging
            (os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla",
                          "firefox"),
             os.path.join(home, ".var", "app", "org.mozilla.firefox", ".cache",
                          "mozilla", "firefox")),
        ]
    return []


# Largest browser database we will snapshot, siblings included. Real History /
# Cookies files are tens of MB; 1 GiB leaves generous headroom.
_MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024


def copy_locked(path):
    """Copy a possibly-locked SQLite db (plus -wal/-shm/-journal) to a temp dir.

    A running browser holds a write lock on the live file, so we snapshot it and
    its write-ahead-log / journal siblings into the system temp dir and open the
    copy read-only. The caller removes the temp dir in a finally once it has the
    returned path; if the snapshot itself fails the caller never receives a path,
    so this function removes its own temp dir before re-raising (no leak).

    Returns (path_to_copy, incomplete) where `incomplete` lists the sibling
    suffixes that existed but could not be copied. A non-empty list means the
    snapshot is missing data the live database has."""
    problem = path_problem(path)
    if problem:
        raise PermissionError(13, problem, path)
    # Refuse an implausibly large database before copying anything. A profile
    # database the attacker can write could otherwise fill the temp drive - an
    # unbounded write by a tool that promises it only reads - and then exhaust
    # memory when its rows are read. Checked before mkdtemp so a refusal never
    # leaves a temp directory behind; the caller records it as a gap.
    try:
        total = os.path.getsize(path) + sum(
            os.path.getsize(path + sfx) for sfx in ("-wal", "-shm", "-journal")
            if os.path.exists(path + sfx))
    except OSError:
        total = 0   # let the copy below surface the real error
    if total > _MAX_SNAPSHOT_BYTES:
        raise OSError(27, "database is {:,} bytes, over the {:,}-byte snapshot "
                      "limit, so it was not copied".format(
                          total, _MAX_SNAPSHOT_BYTES), path)
    tmpdir = tempfile.mkdtemp(prefix="bscan_", dir=local_temp_dir())
    try:
        base = os.path.join(tmpdir, os.path.basename(path))
        shutil.copy2(path, base)
        # A failed sibling copy is NOT cosmetic. A write-ahead log holds rows
        # that are committed but not yet folded into the main file, so losing it
        # silently drops the MOST RECENT evidence - exactly the rows that matter
        # for a campaign someone is checking for right now. Report which ones
        # failed so the caller can record a gap instead of reading a short file
        # and calling it clean (D3).
        incomplete = []
        for suffix in ("-wal", "-shm", "-journal"):
            if path_problem(path + suffix):
                incomplete.append(suffix)
                continue
            if os.path.exists(path + suffix):
                try:
                    shutil.copy2(path + suffix, base + suffix)
                except OSError:
                    incomplete.append(suffix)
        return base, incomplete
    except BaseException as exc:
        # The one place that makes the temp dir is also the one place that
        # removes it when it never hands it over. A failed copy may already
        # contain cookie values, so deletion failure must reach the report.
        if not _discard_snapshot(tmpdir):
            exc.snapshot_leftover = tmpdir
        raise


def _discard_snapshot(tmpdir, con=None):
    """Close the open handle, then delete the snapshot - and check it is gone.

    These temp copies are byte-for-byte duplicates of browser databases, cookie
    VALUES included, even though the queries only read metadata. Windows refuses
    to delete a file that an open SQLite connection still holds, and
    shutil.rmtree(ignore_errors=True) swallows that refusal without a word - so
    the copies survived in %TEMP% after every scan. A tool that leaves copies of
    your cookies behind is worse than no tool, so the handle is closed first and
    the removal is verified rather than assumed. Returns True if the directory
    is gone."""
    if con is not None:
        try:
            con.close()
        except Exception:
            pass
    shutil.rmtree(tmpdir, ignore_errors=True)
    if os.path.exists(tmpdir):
        # One retry: on Windows an antivirus or indexer can hold a file open for
        # a moment after the handle closes.
        shutil.rmtree(tmpdir, ignore_errors=True)
    return not os.path.exists(tmpdir)


def _chromium_profile_names(user_data):
    """Map profile folder -> display name, from the browser's own Local State.

    Chromium calls profile folders "Default", "Profile 1", "Profile 7"..., which
    is meaningless to a person with several accounts. Local State holds the name
    they actually see in the browser, which is what makes a finding
    actionable: "the cookie is in Bubbles" rather than "the cookie is in
    Profile 1".

    Only the display name is read. The signed-in email address is in the same
    structure and is deliberately left alone - the name is enough to identify
    the account, and a report may be forwarded to other people.
    """
    out = {}
    path = os.path.join(user_data, "Local State")
    if path_problem(path):
        return out
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    # RecursionError is not a ValueError. A Local State file of 200,000 nested
    # brackets - about 400 KB, writable without admin - made json.load raise it
    # before a single profile was read, and the whole browser module was lost.
    # Malformed is malformed: fall back to folder names, keep scanning.
    except (OSError, ValueError, RecursionError, MemoryError):
        return out
    profile = data.get("profile", {}) if isinstance(data, dict) else {}
    if not isinstance(profile, dict):
        return out
    cache = profile.get("info_cache", {})
    if not isinstance(cache, dict):
        return out
    for folder, info in cache.items():
        if isinstance(info, dict) and info.get("name"):
            out[folder] = str(info["name"])
    return out


# Files that mark a directory as a real Firefox profile (as opposed to a sibling
# folder like Crash Reports / Pending Pings / Profile Groups that lives in the
# same root on Linux). Any one is enough.
_FF_PROFILE_MARKERS = ("prefs.js", "places.sqlite", "cookies.sqlite",
                       "favicons.sqlite", "SiteSecurityServiceState.txt",
                       "cert9.db", "key4.db", "logins.json")


def _firefox_ini(profiles_dir):
    """Parse Firefox's profiles.ini. Returns ({folder_basename: display_name},
    {folder basenames that profiles.ini lists as profiles}).

    profiles.ini sits INSIDE profiles_dir on Linux (~/.mozilla/firefox) but one
    level ABOVE it on Windows/macOS (...\\Firefox\\Profiles). Try both, so names
    resolve on every platform; the first readable one wins.
    """
    names, known = {}, set()

    def flush(sec):
        path = sec.get("Path")
        if path:
            base = os.path.basename(path.replace("/", os.sep).rstrip(os.sep))
            known.add(base)
            if sec.get("Name"):
                names[base] = sec["Name"]

    for ini in (os.path.join(profiles_dir, "profiles.ini"),
                os.path.join(os.path.dirname(profiles_dir), "profiles.ini")):
        if path_problem(ini):
            continue
        section = {}
        try:
            with io.open(ini, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.strip()
                    if line.startswith("["):
                        flush(section)
                        section = {}
                    elif "=" in line:
                        key, value = line.split("=", 1)
                        section[key.strip()] = value.strip()
            flush(section)
            break
        except OSError:
            continue
    return names, known


def _is_ff_profile_dir(path):
    """True if `path` looks like a real Firefox profile (holds a marker file)."""
    for marker in _FF_PROFILE_MARKERS:
        full = os.path.join(path, marker)
        problem = path_problem(full)
        if problem:
            raise PermissionError(13, problem, full)
        try:
            os.lstat(full)
            return True
        except FileNotFoundError:
            continue
    return False


def _fmt_time(conv, raw):
    """Render an artifact timestamp, or "" if it is missing or unreadable."""
    if not raw:
        return ""
    try:
        return conv(int(raw)).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _locked_note(path, exc):
    """A locked database is the most common non-error a user will see, so say
    what it means and what to do rather than printing a raw errno.

    A running browser causes this two ways: the OS refuses the snapshot with a
    sharing violation (PermissionError / errno 13 on Windows), or SQLite reports
    "database is locked" when the copy is opened. Both mean the same thing to the
    person reading the report: close the browser and run again."""
    leftover = getattr(exc, "snapshot_leftover", "")
    cleanup_warning = (
        " WARNING: temporary snapshot cleanup failed; a copy of browser data "
        "may remain at {}. Remove this temporary directory when its files can "
        "be released.".format(leftover) if leftover else "")
    browser_name = "the browser"
    lowered = path.lower()
    for marker, label in (("bravesoftware", "Brave"), ("vivaldi", "Vivaldi"),
                          ("google", "Chrome"), ("microsoft", "Edge"),
                          ("mozilla", "Firefox")):
        if marker in lowered:
            browser_name = label
            break
    if (isinstance(exc, PermissionError) or getattr(exc, "errno", None) == 13
            or "locked" in str(exc).lower()):
        return ("{} was running, so one of its databases was locked and could "
                "not be checked ({}). Close {} and run again to cover it."
                .format(browser_name, os.path.basename(path), browser_name)
                + cleanup_warning)
    return "could not read {}: {}".format(path, exc) + cleanup_warning


def _is_schema_drift(exc):
    """True for the benign "this browser version lacks that table/column" error,
    as opposed to real corruption or a lock. Only the former is safe to skip."""
    msg = str(exc).lower()
    return "no such table" in msg or "no such column" in msg


def _hsts_fingerprint(host):
    """Chromium stores HSTS hostnames as base64(sha256(DNS wire form)).

    The wire form is each label prefixed by its length, terminated by a zero
    byte: "a.example" -> b"\\x01a\\x07example\\x00". Hashing our indicators the
    same way lets us match an EXACT hostname without ever learning any other
    host the person visited - the file is deliberately a one-way set, and this
    respects that. It also means zero substring false positives.

    The length byte must count the BYTES that are hashed, not the str length.
    Indicator domains are ASCII (punycode) at load time, so ascii-encoding each
    label is exact; a stray non-ASCII label is idna-encoded instead, so the
    prefix and the payload always agree.
    """
    wire = b""
    for label in host.strip(".").lower().split("."):
        try:
            payload = label.encode("ascii")
        except UnicodeEncodeError:
            payload = label.encode("idna")
        wire += bytes([len(payload)]) + payload
    wire += b"\x00"
    return base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii")


def _host_of(origin):
    """Host part of an origin like "https://example.org:443"."""
    s = str(origin).strip()
    try:
        # urlsplit is a lexical parser; it never resolves or opens a URL.
        parsed = urlsplit(s if "://" in s or s.startswith("//") else "//" + s)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def _host_matches(host, ioc_set):
    """Exact host match, or a subdomain of an indicator. Not a substring test:
    these artifacts give us a real hostname, so we can compare properly."""
    host = host.lower().strip(".")
    ind = ioc_set.lookup(host)
    if ind is not None:
        return ind
    # MOST specific wins, not first-found. The indicator set holds both parents
    # and children (powerium.net and qa-noas.powerium.net), and iteration order
    # is the file's order, so returning the first match could hand back the
    # parent while most_specific() - which callers use to pick the hit - keeps
    # the child. The two then disagree, the "is this the host?" comparison
    # fails, and a genuine contact is downgraded to a mere reference.
    best = None
    for candidate in ioc_set.indicators:
        if candidate.type == "domain" and host.endswith("." + candidate.value):
            if best is None or len(candidate.value) > len(best.value):
                best = candidate
    return best


def chromium_profiles(user_data):
    """Every Default / Guest / Profile* directory under a Chromium user-data root.

    Raises OSError if the root exists but cannot be enumerated (a bad ACL); the
    caller turns that into a gap for this one root rather than aborting the whole
    module."""
    problem = path_problem(user_data)
    if problem:
        raise PermissionError(13, problem, user_data)
    if not os.path.isdir(user_data):
        return []
    out = []
    for name in os.listdir(user_data):
        p = os.path.join(user_data, name)
        if name == "Default" or name == "Guest Profile" or name.startswith("Profile"):
            out.append(p)
    return out


def run_browser(ctx) -> ModuleResult:
    r = ModuleResult(NAME_BROWSER)
    r.submetrics["sqlite"] = 0
    r.submetrics["blob"] = 0
    # Publish the result straight away so that if anything below raises,
    # the CLI can still recover whatever was found before the failure
    # instead of discarding it (see ScanContext.partial).
    ctx.partial = r

    # Matching itself lives in IocSet.search / search_bytes, so the boundary
    # rules (a domain must not match inside a longer name, an IP must not match
    # inside a longer number) exist in exactly one place for every module.

    # Modification times of every cache/LevelDB file searched, used at the end to
    # report the actual age of the oldest surviving artifact.
    seen_mtimes = []
    # Creation times of the oldest cookie in each cookie store. Cookies outlive the
    # cache by a long way, so leaving them out would understate the window.
    cookie_times = []
    # How many cookie STORES were actually read. The reach "basis" count must be
    # the number of stores, not len(cookie_times) (which is inflated by one entry
    # per matching cookie plus one per store).
    cookie_stores = [0]
    # Whether any history query actually returned rows. reach["history"] is only
    # populated when it did, so an empty result never advertises a window the
    # scan did not actually observe.
    history_rows = [False]

    # Which profile is currently being scanned, so every hit can name the
    # account it came from. Updated as the walk moves between profiles.
    current = {"name": ""}

    # --- per (browser label, artifact kind) outcome ------------------------
    #
    # Each (label, kind) records whether ANY profile could read that artifact.
    #   ok     - at least one profile read this artifact successfully (a lock in
    #            a different profile is a note, not a whole-kind gap)
    #   fail   - present but unreadable, and no profile has read it yet
    #   absent - never recorded; the browser never created it (not a gap)
    # Insertion order is preserved so the checks list is stable.
    kinds = {}

    def _touch(label, kind):
        key = (label, kind)
        if key not in kinds:
            kinds[key] = {"ok": False, "reason": "", "failures": []}
        return kinds[key]

    def mark_ok(label, kind):
        _touch(label, kind)["ok"] = True

    def mark_fail(label, kind, reason):
        # Every failure is kept, with the profile it happened in. Keeping only a
        # single flag let one readable profile mask another profile's locked
        # database: the kind was reported as a check that ran, and the scan came
        # out CLEAN with no gap at all. That is precisely the collapse of UNKNOWN
        # into CLEAN that D3 forbids, so the failures are now carried through to
        # the rollup individually.
        entry = _touch(label, kind)
        if not entry["reason"]:
            entry["reason"] = reason
        entry["failures"].append((current["name"], reason))

    def chrome_time(us):
        # Chromium stores microseconds since 1601-01-01 (the Windows epoch).
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)

    def unix_us_time(us):
        # Firefox stores microseconds since 1970-01-01.
        return datetime.datetime.fromtimestamp(us / 1e6)

    def record_hit(path, ind, detail, evidence=EV_REFERENCED, observed=""):
        # Attach tier/confidence/source provenance from the IOC set to every hit,
        # plus how strong the artifact makes it (see Hit.evidence).
        r.add_hit(Hit(indicator=ind.value, location=path, detail=detail,
                      tier=ind.tier, confidence=ind.confidence,
                      source=ind.source, evidence=evidence, observed=observed,
                      profile=current["name"]))

    def open_db(path, label, kind):
        """Snapshot and open a possibly-locked SQLite db read-only.

        Returns (con, tmp) on success, or None. A truly absent file (artifact not
        present for this profile) is NOT a gap and returns None silently; every
        other failure records a could-not-read for this (label, kind) - which is
        promoted to a gap only if no profile ever reads it. The db is not counted
        as checked here; that happens only once rows are actually read."""
        problem = path_problem(path)
        if problem:
            r.skipped += 1
            mark_fail(label, kind, "{}: {}".format(path, problem))
            return None
        try:
            os.stat(path)
        except FileNotFoundError:
            return None  # artifact simply absent for this profile
        except OSError as exc:
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        try:
            tmp, incomplete = copy_locked(path)
        except OSError as exc:
            # A locked db we could not even snapshot is a gap, not a clean item.
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        try:
            con = sqlite3.connect(tmp)
        except sqlite3.Error as exc:
            if not _discard_snapshot(os.path.dirname(tmp)):
                exc.snapshot_leftover = os.path.dirname(tmp)
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        if incomplete:
            # The main file opened, but a write-ahead log or journal that the
            # live database HAS could not be copied. Whatever was committed
            # there is missing from this snapshot - and that is the newest
            # evidence, not the oldest. Reading the short file and calling it
            # clean would be a false negative, so this is a gap.
            note = ("{}: snapshot is incomplete - could not copy {} alongside "
                    "it, so recently written rows may be missing from this "
                    "read".format(os.path.basename(path), ", ".join(incomplete)))
            r.note(note)
            mark_fail(label, kind, note)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        return con, tmp

    def _count_db():
        r.submetrics["sqlite"] += 1
        r.checked += 1

    def scan_history(label, path, flavour):
        """History / moz_places, host-graded.

        A history row whose URL HOST is the indicator means the browser actually
        went there, so it grades as contacted and carries the row's own visit
        date as the observed time (when the schema records it). A match only in
        the query string or page title is a reference - often a search for the
        name - so it stays referenced. Chromium's download records live in the
        same db and stay referenced (a saved path/URL, not proof of contact)."""
        kind = "history"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        read_ok = False
        failed = False
        try:
            if flavour == "chromium":
                table, visit_col, conv = "urls", "last_visit_time", chrome_time
            else:
                table, visit_col, conv = ("moz_places", "last_visit_date",
                                          unix_us_time)
            try:
                present = {row[1] for row in
                           con.execute("PRAGMA table_info({})".format(table))}
            except sqlite3.Error as exc:
                present = set()
                if not _is_schema_drift(exc):
                    mark_fail(label, kind, _locked_note(path, exc))
                    failed = True

            if not failed and "url" not in present:
                mark_fail(label, kind, "the history store has no supported URL "
                          "column, so navigation history could not be searched")
                failed = True
            if not failed and "url" in present:
                cols = ["url"]
                if "title" in present:
                    cols.append("title")
                if visit_col in present:
                    cols.append(visit_col)
                if flavour == "firefox" and "visit_count" in present:
                    cols.append("visit_count")
                try:
                    rows = con.execute("SELECT {} FROM {}".format(
                        ", ".join(cols), table)).fetchall()
                except sqlite3.Error as exc:
                    rows = None
                    if not _is_schema_drift(exc):
                        mark_fail(label, kind, _locked_note(path, exc))
                        failed = True
                if rows is not None:
                    read_ok = True
                    if rows:
                        history_rows[0] = True
                    for row in rows:
                        rec = dict(zip(cols, row))
                        url = str(rec.get("url") or "")
                        title = str(rec.get("title") or "")
                        blob = (url + " " + title).lower()
                        observed = _fmt_time(conv, rec.get(visit_col))
                        # Firefox's places database also stores never-visited
                        # bookmarks. A URL row alone does not establish a visit.
                        has_visit = flavour != "firefox"
                        if flavour == "firefox":
                            for raw in (rec.get(visit_col), rec.get("visit_count")):
                                try:
                                    has_visit = has_visit or int(raw or 0) > 0
                                except (TypeError, ValueError, OverflowError):
                                    pass
                        host_ind = _host_matches(_host_of(url), ctx.iocs)
                        for ind in ctx.iocs.most_specific(ctx.iocs.search(blob)):
                            if (has_visit and host_ind is not None
                                    and host_ind.value == ind.value):
                                record_hit(path, ind, "history: " + blob[:160],
                                           EV_CONTACTED, observed)
                            else:
                                record_hit(path, ind, "history: " + blob[:160],
                                           EV_REFERENCED)

            if flavour == "chromium" and not failed:
                try:
                    rows = con.execute(
                        "SELECT current_path, tab_url, referrer "
                        "FROM downloads").fetchall()
                except sqlite3.Error as exc:
                    rows = None
                    if not _is_schema_drift(exc):
                        mark_fail(label, kind, _locked_note(path, exc))
                        failed = True
                if rows is not None:
                    read_ok = True
                    for row in rows:
                        blob = " ".join(str(c) for c in row
                                        if c is not None).lower()
                        for ind in ctx.iocs.most_specific(ctx.iocs.search(blob)):
                            record_hit(path, ind, "download: " + blob[:160],
                                       EV_REFERENCED)

            if not failed:
                # Opened and queried without corruption: this artifact was read.
                mark_ok(label, kind)
                if read_ok:
                    _count_db()
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_favicons(label, path, flavour):
        """Favicons. For Chromium, a favicon URL whose stored bitmap is present
        and non-empty means the browser actually fetched the icon from that host
        (contacted); a row with no image is only a reference. For Firefox the
        presence of a moz_icons entry already means the icon was fetched, so it
        grades as contacted."""
        kind = "favicons"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        try:
            if flavour == "chromium":
                sql = ("SELECT favicons.url, "
                       "CASE WHEN favicon_bitmaps.image_data IS NOT NULL "
                       "AND length(favicon_bitmaps.image_data) > 0 "
                       "THEN 1 ELSE 0 END "
                       "FROM favicons "
                       "LEFT JOIN favicon_bitmaps "
                       "ON favicons.id = favicon_bitmaps.icon_id")
                graded = True
            else:
                sql = "SELECT icon_url FROM moz_icons"
                graded = False
            try:
                rows = con.execute(sql).fetchall()
            except sqlite3.Error as exc:
                mark_fail(label, kind, _locked_note(path, exc))
                return
            mark_ok(label, kind)
            _count_db()
            for row in rows:
                if graded:
                    url, has_bitmap = row[0], row[1]
                    ev = EV_CONTACTED if has_bitmap else EV_REFERENCED
                else:
                    url, ev = row[0], EV_CONTACTED
                blob = str(url or "").lower()
                # Anchor to the HOST, the same way history does. A stored bitmap
                # proves the browser fetched that icon - from the icon URL's own
                # host. An indicator sitting in the query string of an otherwise
                # innocent favicon URL proves contact with the innocent host, not
                # with the indicator, so it must not be graded as contact.
                host_ind = _host_matches(_host_of(blob), ctx.iocs)
                for ind in ctx.iocs.most_specific(ctx.iocs.search(blob)):
                    anchored = (host_ind is not None
                                and host_ind.value == ind.value)
                    record_hit(path, ind, "favicon: " + blob[:160],
                               ev if anchored else EV_REFERENCED)
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_cookies(label, path, flavour):
        """Cookies get their own reader because they are the richest artifact
        here, and the generic row-to-string match throws away the two things a
        person actually needs: WHEN the cookie was set, and WHICH page they were
        on when it happened.

        Chromium partitions third-party cookies by top-level site, so
        `top_frame_site_key` names the site that was being visited when an ad
        tracker set its cookie. For an ad-delivered indicator that is the single
        most useful field in the whole scan - it turns "something was contacted"
        into "this happened on that site, on that date".

        The store is not counted as checked until rows are in hand: every early
        exit (unreadable schema, no usable columns, a failed SELECT) is a gap, so
        a locked cookie store - the common case, because the browser is open -
        shows up as such rather than as a clean, empty result.
        """
        kind = "cookies"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        try:
            # Only ask for columns this database actually has. Cookie schemas
            # differ across browser versions and forks, and a single missing
            # column would otherwise fail the whole query and silently lose the
            # richest artifact in the scan.
            table = "cookies" if flavour == "chromium" else "moz_cookies"
            try:
                present = {row[1] for row in
                           con.execute("PRAGMA table_info({})".format(table))}
            except sqlite3.Error as exc:
                r.skipped += 1
                mark_fail(label, kind, _locked_note(path, exc))
                return
            if flavour == "chromium":
                candidates = ["host_key", "name", "creation_utc",
                              "last_access_utc", "top_frame_site_key"]
                conv = chrome_time
            else:
                candidates = ["host", "name", "creationTime", "lastAccessed"]
                conv = unix_us_time
            wanted = [c for c in candidates if c in present]
            host_column = "host_key" if flavour == "chromium" else "host"
            if host_column not in wanted:
                r.skipped += 1
                mark_fail(label, kind,
                          "the cookie store {} had no supported host column, "
                          "so its cookie origins could not be searched"
                          .format(os.path.basename(path)))
                return
            sql = "SELECT {} FROM {}".format(", ".join(wanted), table)
            try:
                rows = con.execute(sql).fetchall()
            except sqlite3.Error as exc:
                r.skipped += 1
                mark_fail(label, kind, _locked_note(path, exc))
                return

            # Rows are in hand: now the store genuinely counts as read.
            mark_ok(label, kind)
            _count_db()
            cookie_stores[0] += 1

            for row in rows:
                record = dict(zip(wanted, row))
                host = str(record.get("host_key") or record.get("host") or "")
                for ind in ctx.iocs.most_specific(ctx.iocs.search(host.lower())):
                    created = _fmt_time(conv, record.get("creation_utc")
                                        or record.get("creationTime"))
                    seen = _fmt_time(conv, record.get("last_access_utc")
                                     or record.get("lastAccessed"))
                    partition = str(record.get("top_frame_site_key") or "").strip()
                    bits = ["cookie set by {}".format(host),
                            "name {}".format(record.get("name") or "?")]
                    if partition:
                        bits.append("set while visiting {}".format(partition))
                    if created:
                        bits.append("first set {}".format(created))
                    if seen and seen != created:
                        bits.append("last used {}".format(seen))
                    elif seen:
                        bits.append("never used again after that")
                    record_hit(path, ind, "; ".join(bits), EV_CONTACTED,
                               created or seen)
                    if created:
                        cookie_times.append(conv(int(
                            record.get("creation_utc")
                            or record.get("creationTime"))))
            # Oldest cookie overall, for the time-coverage section.
            col = "creation_utc" if flavour == "chromium" else "creationTime"
            if col in present:
                try:
                    raw = con.execute(
                        "SELECT MIN({0}) FROM {1} WHERE {0} > 0".format(
                            col, table)).fetchone()
                    if raw and raw[0]:
                        cookie_times.append(conv(int(raw[0])))
                except (sqlite3.Error, ValueError, OverflowError, OSError):
                    pass
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_blobs(label, root, evidence):
        """Substring-search binary files (HTTP cache, LevelDB) for the needles.

        Raw bytes do not distinguish origin keys from saved page content. Every
        match here is referenced, even when it looks like a complete origin URL.

        A directory that exists and can be walked is a successful check of the
        "blobs" kind, even if it holds no files (a present-but-empty cache is a
        legitimately clean cache). A subtree that could not be walked at all, or a
        file too large to hold in memory, is a gap - never dropped silently."""
        kind = "blobs"
        problem = path_problem(root)
        if problem:
            r.skipped += 1
            mark_fail(label, kind, "{}: {}".format(root, problem))
            return
        try:
            os.stat(root)
        except FileNotFoundError:
            return  # artifact absent for this profile — not a gap
        except OSError as exc:
            r.skipped += 1
            r.note(_locked_note(root, exc))
            mark_fail(label, kind, _locked_note(root, exc))
            return

        failures = []

        def onerror(exc):
            # os.walk swallows directory errors unless we catch them here.
            failures.append("could not enumerate {}: {}".format(
                getattr(exc, "filename", root), exc))
            r.skipped += 1
            r.note("could not enumerate {}: {}".format(
                getattr(exc, "filename", root), exc))

        read_any = False
        for dirpath, _dirs, files in walk_local(root, onerror=onerror):
            for fn in files:
                full = os.path.join(dirpath, fn)
                try:
                    problem = path_problem(full)
                    if problem:
                        raise PermissionError(13, problem, full)
                    st = os.stat(full)
                except OSError as exc:
                    r.skipped += 1
                    r.note("could not read {}: {}".format(full, exc))
                    failures.append("could not stat {}: {}".format(full, exc))
                    continue
                if st.st_size > 400 * 1024 * 1024:
                    r.skipped += 1  # too large to search — a gap, not clean
                    r.note("{} is larger than 400 MB and was not searched"
                           .format(full))
                    failures.append("{} exceeds the 400 MB search limit".format(full))
                    continue
                try:
                    with io.open(full, "rb") as fh:
                        data = fh.read()
                    lowered = data.lower()
                except MemoryError:
                    # read() then .lower() needs two copies; a file that will not
                    # fit is recorded as a gap, not pretended to be searched.
                    r.skipped += 1
                    failures.append("{} could not fit in memory".format(full))
                    continue
                except OSError as exc:
                    r.skipped += 1  # unreadable file — a gap, not clean
                    r.note("could not read {}: {}".format(full, exc))
                    failures.append("could not read {}: {}".format(full, exc))
                    continue
                # Oldest cache artifact = how far back this check can possibly see.
                # Browsers recycle the cache continuously, so this is a measured
                # window, not a guess, and it is usually far shorter than people
                # assume.
                seen_mtimes.append(st.st_mtime)
                r.submetrics["blob"] += 1
                r.checked += 1
                read_any = True
                for ind in ctx.iocs.search_bytes(lowered):
                    # Local Storage / Session Storage / Service Worker entries
                    # are KEYED BY ORIGIN, which is why a match there was graded
                    # as contact. But this is a raw byte search over the whole
                    # file, and these stores also hold page CONTENT - a saved
                    # article, a quoted report. An indicator inside a stored
                    # value proves someone read about this campaign, not that
                    # the device talked to it, and telling a journalist who read
                    # the Citizen Lab report that their device "demonstrably
                    # communicated with" spyware infrastructure is the worst
                    # kind of false alarm. A URL-looking string is not enough
                    # to identify a structured origin key, so retain a reference.
                    record_hit(full, ind,
                               "binary match in cache/leveldb; raw bytes do not "
                               "establish whether this is an origin or saved content",
                               EV_REFERENCED)

        if read_any or not failures:
            mark_ok(label, kind)
        if failures:
            mark_fail(label, kind,
                      "{} item(s) under {} were not searched: {}"
                      .format(len(failures), root, "; ".join(failures[:3])))

    def scan_connection_records(label, prof):
        """The two long-lived records of hosts the browser actually CONNECTED to.

        Why these matter more than the cache: the HTTP cache is recycled within
        weeks and a byte match in it may only be page content mentioning a name.
        These two files instead record that a connection happened, they survive
        far longer, and HSTS even carries the date it was observed.

        TransportSecurity - HSTS state. An entry exists because that host served
        an HSTS header over HTTPS. Hostnames are stored hashed, so we hash our
        indicators and compare; we never learn anything about other hosts.

        Network Persistent State - plaintext origins of servers the browser has
        connected to, plus hosts with broken alternative services.
        """
        net_dir = os.path.join(prof, "Network")

        ts_path = os.path.join(net_dir, "TransportSecurity")
        ts_present = True
        try:
            problem = path_problem(ts_path)
            if problem:
                raise PermissionError(13, problem, ts_path)
            os.stat(ts_path)
        except FileNotFoundError:
            ts_present = False
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(ts_path, exc))
            ts_present = False
        if ts_present:
            try:
                with io.open(ts_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                if not isinstance(data, dict):
                    raise ValueError("HSTS state must be an object")
                entries = data.get("sts", [])
                # Shape-check rather than trust: a file whose "sts" is a number
                # rather than a list made len() raise TypeError, which escaped
                # the (OSError, ValueError) handler below, propagated out of the
                # module and cost every hit already collected. A malformed
                # artifact is a gap for THIS artifact, never a crash.
                if not isinstance(entries, list):
                    raise ValueError(
                        "unexpected shape: 'sts' is {}, expected a list"
                        .format(type(entries).__name__))
                r.submetrics["hsts_entries"] = (
                    r.submetrics.get("hsts_entries", 0) + len(entries))
                r.checked += len(entries)
                mark_ok(label, "hsts")
                if entries:
                    held = {}
                    for e in entries:
                        if not isinstance(e, dict) or not isinstance(e.get("host"), str):
                            raise ValueError("HSTS entry must contain a host string")
                        held[e["host"]] = e
                    for ind in ctx.iocs.indicators:
                        if ind.type != "domain":
                            continue
                        e = held.get(_hsts_fingerprint(ind.value))
                        if e is None:
                            continue
                        when = ""
                        try:
                            when = datetime.datetime.fromtimestamp(
                                float(e.get("sts_observed"))).isoformat(
                                    timespec="seconds")
                        except (TypeError, ValueError, OverflowError, OSError):
                            pass
                        record_hit(
                            ts_path, ind,
                            "HSTS state recorded for this exact host - the "
                            "browser received an HSTS header from it over HTTPS"
                            + (" (observed {})".format(when[:10]) if when else ""),
                            EV_CONTACTED, when)
            except (OSError, ValueError, RecursionError, MemoryError) as exc:
                r.skipped += 1
                mark_fail(label, "hsts", _locked_note(ts_path, exc))

        nps_path = os.path.join(net_dir, "Network Persistent State")
        nps_present = True
        try:
            problem = path_problem(nps_path)
            if problem:
                raise PermissionError(13, problem, nps_path)
            os.stat(nps_path)
        except FileNotFoundError:
            nps_present = False
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "connection-records", _locked_note(nps_path, exc))
            nps_present = False
        if nps_present:
            try:
                with io.open(nps_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                if not isinstance(data, dict):
                    raise ValueError("network state must be an object")
                net = data.get("net", {})
                if not isinstance(net, dict):
                    raise ValueError("network state 'net' must be an object")
                hsp = net.get("http_server_properties", {})
                if not isinstance(hsp, dict):
                    raise ValueError("http_server_properties must be an object")
                for field, host_field in (("servers", "server"),
                                          ("broken_alternative_services", "host")):
                    entries = hsp.get(field, [])
                    if not isinstance(entries, list):
                        raise ValueError("{} must be a list".format(field))
                    for row in entries:
                        if not isinstance(row, dict) or not isinstance(
                                row.get(host_field), str):
                            raise ValueError("{} contains an invalid host record"
                                             .format(field))
                origins = []
                for row in hsp.get("servers") or []:
                    if isinstance(row, dict) and row.get("server"):
                        origins.append((_host_of(row["server"]), "connected server"))
                for row in hsp.get("broken_alternative_services") or []:
                    if isinstance(row, dict) and row.get("host"):
                        origins.append((_host_of(row["host"]),
                                        "broken alternative service"))
                r.submetrics["connection_records"] = (
                    r.submetrics.get("connection_records", 0) + len(origins))
                r.checked += len(origins)
                mark_ok(label, "connection-records")
                for host, kind in origins:
                    ind = _host_matches(host, ctx.iocs)
                    if ind is not None:
                        record_hit(
                            nps_path, ind,
                            "{}: the browser has a connection record for {}"
                            .format(kind, host), EV_CONTACTED)
            except (OSError, ValueError, RecursionError, MemoryError) as exc:
                r.skipped += 1
                mark_fail(label, "connection-records",
                          _locked_note(nps_path, exc))

    def scan_firefox_hsts(label, path):
        """Firefox's HSTS store, SiteSecurityServiceState.txt.

        Like Chromium's TransportSecurity, every hostname here is one the browser
        connected to over HTTPS and received an HSTS header from, so a match is
        proof of contact. Unlike Chromium's, Firefox keeps the hostnames in
        PLAINTEXT, so we read the file as text and run the shared matcher over it;
        only our indicators are searched for, so no other host from the file ever
        reaches the output.
        """
        try:
            problem = path_problem(path)
            if problem:
                raise PermissionError(13, problem, path)
            os.stat(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(path, exc))
            return
        try:
            with io.open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(path, exc))
            return
        entries = text.count(":HSTS")
        r.submetrics["hsts_entries"] = (
            r.submetrics.get("hsts_entries", 0) + entries)
        r.checked += entries
        mark_ok(label, "hsts")
        for ind in ctx.iocs.search(text.lower()):
            record_hit(
                path, ind,
                "Firefox HSTS state recorded for this host - the browser "
                "received an HSTS header from it over HTTPS", EV_CONTACTED)

    # No browser profile location is known for this platform at all: say so as a
    # gap rather than returning an empty, falsely-clean result.
    ff_roots = FIREFOX_ROOTS if FIREFOX_ROOTS is not None else _firefox_roots()
    if not CHROMIUM_ROOTS and not ff_roots:
        r.could_not_run("browser", "no browser profile locations are known for "
                        "{}".format(sys.platform))
        return r

    # --- Chromium family: Chrome, Edge, Brave, Vivaldi, Chromium ---------------------
    for label, root in CHROMIUM_ROOTS:
        problem = path_problem(root)
        if problem:
            r.could_not_run(label + ":profiles", "{}: {}".format(root, problem))
            continue
        if not os.path.isdir(root):
            continue  # browser not installed — absent, so no sub-check for it
        try:
            profs = chromium_profiles(root)
        except OSError as exc:
            # One bad ACL on the user-data root must not abort the whole module.
            r.could_not_run(label + ":profiles", _locked_note(root, exc))
            continue
        names = _chromium_profile_names(root)
        ctx.emit("[*] {} ({} profile(s))".format(root, len(profs)))
        for prof in profs:
            problem = path_problem(prof)
            if problem:
                r.could_not_run(label + ":profile:" + os.path.basename(prof), problem)
                continue
            if not os.path.isdir(prof):
                continue
            folder = os.path.basename(prof)
            display = names.get(folder, "")
            # Name the account in the hit, falling back to the folder when the
            # browser has no display name recorded for it.
            current["name"] = ("{} ({})".format(display, folder) if display
                               else folder)
            ctx.emit("[*]   profile: {}".format(current["name"]))
            scan_history(label, os.path.join(prof, "History"), "chromium")
            scan_cookies(label, os.path.join(prof, "Network", "Cookies"),
                         "chromium")
            scan_cookies(label, os.path.join(prof, "Cookies"), "chromium")
            scan_favicons(label, os.path.join(prof, "Favicons"), "chromium")
            scan_connection_records(label, prof)
            for sub, evidence in (
                    (("Cache", "Cache_Data"), EV_REFERENCED),
                    (("Code Cache", "js"), EV_REFERENCED),
                    (("Local Storage", "leveldb"), EV_CONTACTED),
                    (("Session Storage",), EV_CONTACTED),
                    (("Service Worker", "CacheStorage"), EV_CONTACTED)):
                scan_blobs(label, os.path.join(prof, *sub), evidence)

    # --- Firefox: roaming profiles for the dbs, local cache for the cache ---
    # A stray cross-profile hit must never be stamped with the last Chrome
    # profile, so reset attribution before the Firefox walk and keep it
    # per-profile inside the loop (the cache lives in a sibling tree whose
    # profile folders share the same names - the old code swept it ONCE, outside
    # the loop, stamping every Firefox cache hit with the last Chrome profile).
    current["name"] = ""
    for profiles_dir, cache_dir in ff_roots:
        refused = [(p, path_problem(p)) for p in (profiles_dir, cache_dir)]
        if any(reason for _p, reason in refused):
            for p, reason in refused:
                if reason:
                    r.could_not_run("firefox:profiles:" + p, reason)
            continue
        prof_is_dir = os.path.isdir(profiles_dir)
        cache_is_dir = os.path.isdir(cache_dir)
        if not prof_is_dir and not cache_is_dir:
            continue
        ff_names, ff_known = _firefox_ini(profiles_dir) if prof_is_dir else ({}, set())
        ctx.emit("[*] {}".format(profiles_dir if prof_is_dir else cache_dir))

        folders = set()
        if prof_is_dir:
            try:
                folders.update(os.listdir(profiles_dir))
            except OSError as exc:
                r.could_not_run("firefox:profiles",
                                _locked_note(profiles_dir, exc))
        if cache_is_dir:
            try:
                folders.update(os.listdir(cache_dir))
            except OSError as exc:
                r.could_not_run("firefox:cache-dir", _locked_note(cache_dir, exc))

        for name in sorted(folders):
            prof = os.path.join(profiles_dir, name)
            cprof = os.path.join(cache_dir, name)
            refused = [(p, path_problem(p)) for p in (prof, cprof)]
            if any(reason for _p, reason in refused):
                for p, reason in refused:
                    if reason:
                        r.could_not_run("firefox:profile:" + p, reason)
                continue
            if not os.path.isdir(prof) and not os.path.isdir(cprof):
                continue
            # On Linux the profiles root also holds non-profile folders (Crash
            # Reports, Pending Pings, Profile Groups). Only treat a folder as a
            # profile if profiles.ini lists it or it holds a profile marker file,
            # so those are not scanned and mislabelled as profiles.
            if name not in ff_known:
                try:
                    if not _is_ff_profile_dir(prof):
                        continue
                except OSError as exc:
                    r.could_not_run("firefox:profile:" + name, str(exc))
                    continue
            display = ff_names.get(name, "")
            current["name"] = ("{} ({})".format(display, name) if display
                               else name)
            ctx.emit("[*]   profile: {}".format(current["name"]))
            if os.path.isdir(prof):
                scan_history("firefox", os.path.join(prof, "places.sqlite"),
                             "firefox")
                scan_cookies("firefox", os.path.join(prof, "cookies.sqlite"),
                             "firefox")
                scan_favicons("firefox", os.path.join(prof, "favicons.sqlite"),
                              "firefox")
                scan_firefox_hsts(
                    "firefox",
                    os.path.join(prof, "SiteSecurityServiceState.txt"))
            if os.path.isdir(cprof):
                scan_blobs("firefox", cprof, EV_REFERENCED)

    # Nothing written after this point should inherit a stale profile name.
    current["name"] = ""

    # --- roll each (browser, kind) up into a check the verdict can read -----
    #
    # A kind that at least one profile read is a check that ran (and, with no hit,
    # is clean). A kind that was present but could never be read is a check that
    # could_not_run, which the verdict surfaces as a gap - never folded into a
    # clean result.
    for (label, kind), state in kinds.items():
        check_name = "{}:{}".format(label, kind)
        if state["ok"]:
            r.ran(check_name)
            # A profile that could not be read is still a gap when a DIFFERENT
            # profile of the same browser read fine: the unread profile was
            # never searched, so nothing has been cleared for it. Previously the
            # successful profile set a single flag and these vanished, so a
            # locked second profile came out CLEAN with no gap - the collapse of
            # UNKNOWN into CLEAN that D3 exists to prevent. Each is named with
            # its account so the report can say WHICH one was not covered.
            for profile_name, reason in state["failures"]:
                r.could_not_run(
                    "{} [{}]".format(check_name, profile_name or "profile"),
                    reason)
        else:
            # Nothing anywhere read this kind: the kind itself is the gap.
            r.could_not_run(check_name, state["reason"] or "could not be read")

    # Report the measured window. Without this, "browser: CLEAN" invites the reader
    # to assume it means "clean for as long as I have owned this computer", which is
    # never true — and for a campaign that ran in 2024-2025, the gap between the two
    # readings is the whole answer.
    if seen_mtimes:
        earliest = min(seen_mtimes)
        # The oldest surviving file is survivorship, not coverage: ONE artifact
        # from 2023 does not mean a usable record of 2023. So report the
        # distribution by year as well, and let the report say how much evidence
        # actually falls inside the period being asked about.
        by_year = {}
        for m in seen_mtimes:
            y = datetime.datetime.fromtimestamp(m).year
            by_year[y] = by_year.get(y, 0) + 1
        r.reach["cache"] = {
            "earliest": datetime.datetime.fromtimestamp(earliest).isoformat(
                timespec="seconds"),
            "days": max(0, (datetime.datetime.now()
                            - datetime.datetime.fromtimestamp(earliest)).days),
            "basis": "oldest of {:,} cache/LevelDB/Service-Worker files "
                     "searched".format(len(seen_mtimes)),
            "note": "The HTTP cache is recycled within weeks, but Local Storage, "
                    "LevelDB and Service Worker files can persist for years - "
                    "which is why this date is often much older than the cache "
                    "alone. It is the oldest SURVIVOR, not proof of a continuous "
                    "record since then.",
            "by_year": by_year,
        }
    if cookie_times:
        oldest = min(cookie_times)
        r.reach["cookies"] = {
            "earliest": oldest.isoformat(timespec="seconds"),
            "days": max(0, (datetime.datetime.now() - oldest).days),
            "basis": "oldest surviving cookie across {} cookie store(s)".format(
                cookie_stores[0]),
            "note": "Cookies are the strongest evidence the browser keeps: one "
                    "exists only if the browser actually got a response from that "
                    "site. But this is the oldest SURVIVOR, not a full record back "
                    "to that date. Cookies expire (Chrome caps them at 400 days) "
                    "or get cleared, so most cookies from that time are gone.",
        }
    if history_rows[0]:
        r.reach["history"] = {
            "earliest": None,
            "days": None,
            "basis": "browser history was searched, but records only top-level "
                     "navigations",
            "note": "History reaches back further than the cache but CANNOT record "
                    "an ad: ads load as a sub-resource inside a page, and only the "
                    "page itself is recorded. The long record cannot see ads; the "
                    "record that sees ads is not long.",
        }
    return r


# --- modules/hashscan --------------------------------------------------------
"""Hunt known sample hashes across the user-writable parts of this machine.

Citizen Lab (and others) publish SHA-256 hashes for the Windows payloads this
infrastructure delivers. Hashing every file on C: would take hours, so this
scans the locations an implant DLL actually lands in, plus anything the user
downloaded, and compares each file's digest against the sample hashes carried in
the IOC set.

A clean result means "none of these exact files are in these locations" - nothing
more. Each sample is one build; another victim's payload would hash differently,
which is why a clean hash scan is never a clean bill of health (D1/D3).

Contract: defines NAME_HASH and run(ctx) -> ModuleResult. Read-only, stdlib only, no
network (D2) - hashing a local file resolves nothing.
"""


import hashlib
import io
import os


NAME_HASH = "hash"

# Only file types a payload plausibly ships as. Keeps the walk cheap and avoids
# hashing the user's documents and media for no reason.
EXTS = (".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr", ".tmp", ".dat", ".bin", ".ax")

# Files larger than this are almost certainly not the implant; skipping them
# (counted as skipped, never as clean) keeps the scan from stalling on big blobs.
MAX_BYTES = 120 * 1024 * 1024

# Directory names pruned from the walk: browser/code caches, dependency trees and
# the Windows component store - huge, noisy, and not where an implant DLL lands.
PRUNE_DIRS = (
    "cache", "cache_data", "gpucache", "code cache", "node_modules",
    ".git", "servicepackfiles", "winsxs",
)


def _roots():
    """The user-writable locations an implant actually drops into, filtered to
    those that exist on this host. Matches the proof-of-concept exactly."""
    user = os.path.expanduser("~")
    roots = [
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("PROGRAMDATA", ""),
        os.environ.get("TEMP", ""),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "Documents"),
        r"C:\Users\Public",
    ]
    # De-duplicate by resolved, case-normalised path, then drop any root that is
    # nested inside another. %TEMP% is %LOCALAPPDATA%\Temp on a default install,
    # so without this every file under Temp is hashed twice - inflating the
    # coverage counts and reporting one real sample as two separate hits.
    resolved = []
    for raw in roots:
        if not raw:
            continue
        # Do not resolve links or test existence before the locality guard.
        norm = os.path.normcase(os.path.normpath(raw))
        if norm not in resolved:
            resolved.append(norm)
    kept = []
    for r1 in resolved:
        if any(r1 != r2 and r1.startswith(r2 + os.sep) for r2 in resolved):
            continue  # r1 lives inside another root; walking that one covers it
        kept.append(r1)
    return kept


def _sha256(full):
    """SHA-256 of a file, read in 1 MiB chunks so a large file never loads whole
    into memory. Returns (hex_digest, size) or raises OSError for the caller to
    count as skipped."""
    problem = path_problem(full)
    if problem:
        raise PermissionError(13, problem, full)
    size = os.path.getsize(full)
    h = hashlib.sha256()
    with io.open(full, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest(), size


def run_hash(ctx) -> ModuleResult:
    r = ModuleResult(NAME_HASH)
    # Publish the result straight away so that if anything below raises,
    # the CLI can still recover whatever was found before the failure
    # instead of discarding it (see ScanContext.partial).
    ctx.partial = r

    # Build the hex-digest -> Indicator map once so each file is a single dict
    # lookup. The hashes come from the IOC set, never hardcoded (ctx.iocs.hashes).
    targets = {ind.value: ind for ind in ctx.iocs.hashes}

    # D3: with nothing to compare against we cannot claim CLEAN. State the gap
    # and stop - an empty target set is UNKNOWN for this check, not clean.
    if not targets:
        r.could_not_run("hash-compare", "no sample hashes in the indicator set")
        return r

    ctx.emit("[hash] looking for {} known sample hash(es)".format(len(targets)))

    for root in _roots():
        problem = path_problem(root)
        if problem:
            r.could_not_run("root:" + root, problem)
            continue
        if not os.path.isdir(root):
            continue
        # The full path, not the basename: %TEMP% and %SystemRoot%\Temp both end
        # in "Temp", and two roots collapsing to one name would make the check
        # list lie about what was actually covered.
        #
        # The verdict for this root is decided AFTER the walk, not before it.
        # Marking it as a check that ran up front meant a root where every
        # candidate file failed to open still counted as a clean, completed
        # check: nothing was fingerprinted, nothing was reported, and the scan
        # said CLEAN with no gap. A file that could not be read has not been
        # cleared of anything (D3).
        ctx.emit("[hash] scanning {} ...".format(root))
        tally = {"hashed": 0, "candidates": 0, "unreadable": 0}

        def _walk_err(exc, _r=r, _t=tally):
            # An unreadable subtree would otherwise vanish silently from os.walk.
            _r.skipped += 1
            _t["unreadable"] += 1

        for dirpath, dirs, files in walk_local(root, onerror=_walk_err):
            # Prune noisy / huge subtrees in place so os.walk never descends them.
            dirs[:] = [d for d in dirs if d.lower() not in PRUNE_DIRS]
            for fn in files:
                if not fn.lower().endswith(EXTS):
                    continue
                full = os.path.join(dirpath, fn)
                tally["candidates"] += 1
                try:
                    problem = path_problem(full)
                    if problem:
                        raise PermissionError(13, problem, full)
                    size = os.path.getsize(full)
                    # Over the size cap: skipped, not clean (D-never-crash).
                    if size > MAX_BYTES:
                        r.skipped += 1
                        tally["unreadable"] += 1
                        continue
                    digest, size = _sha256(full)
                except OSError:
                    # Locked / permission-denied / unreadable: skip and continue.
                    r.skipped += 1
                    tally["unreadable"] += 1
                    continue

                tally["hashed"] += 1
                r.checked += 1
                r.submetrics["files_hashed"] = r.submetrics.get("files_hashed", 0) + 1
                r.submetrics["bytes_hashed"] = r.submetrics.get("bytes_hashed", 0) + size

                ind = targets.get(digest)
                if ind is not None:
                    # EV_ON_DISK is the whole point: a file whose fingerprint
                    # matches a published sample is conclusive. Without an
                    # evidence grade the report defaulted it to "referenced" and
                    # told the reader it was "probably not a sign of compromise" -
                    # over a known spyware binary sitting on their disk.
                    r.add_hit(Hit(
                        indicator=digest,
                        location=full,
                        detail="this file's SHA-256 matches a published sample: "
                               + ind.value,
                        tier=ind.tier,
                        confidence=ind.confidence,
                        source=ind.source,
                        evidence=EV_ON_DISK,
                    ))
                    ctx.emit("[hash] !! MATCH {} ({})".format(full, ind.value))

        # Now say honestly what this root amounted to.
        name = "root:" + root
        if tally["hashed"]:
            r.ran(name)
            if tally["unreadable"]:
                r.could_not_run(
                    name + " (partial)",
                    "{} of {} candidate file(s) under this root could not be "
                    "read or were too large to fingerprint, so they were not "
                    "compared against the known hashes".format(
                        tally["unreadable"], tally["candidates"]))
        elif tally["candidates"] or tally["unreadable"]:
            # Candidates existed but not one could be fingerprinted: this root
            # was not searched at all, however many files it holds.
            r.could_not_run(
                name,
                "no file under this root could be fingerprinted ({} candidate "
                "file(s) unreadable)".format(tally["unreadable"]))
        else:
            # Walked cleanly, held nothing to fingerprint. Genuinely covered.
            r.ran(name)

    return r


# --- modules/host ------------------------------------------------------------
"""Host module — per-user COM persistence, DNS cache, DNS history, hosts file.

Ported from scripts/scan_host.ps1. Four checks, and the reason each one exists:

  1. com-persistence. Citizen Lab's write-up of this Candiru chain says it
     persists via a COM hijack. The technique registers a CLSID under HKCU,
     and Windows resolves HKCU\\Software\\Classes before the machine-wide HKLM
     registration — so a *per-user* InprocServer32 pointing at a DLL in a
     user-writable directory gets loaded into every process that instantiates
     that class, with no admin rights and no service or Run key to find.
     That is the whole appeal of the technique, and it is why this check looks
     at HKCU and not HKLM.
     Legitimate per-user COM registrations absolutely do exist (the reference
     machine had 37 of them), so this check LISTS them for review; it does not
     call them malicious. Per D4 (precision over coverage) an unsigned DLL in
     %LOCALAPPDATA% is not a finding on its own — plenty of honest software
     ships exactly that — so a Hit is emitted only when a registered path
     contains an actual indicator string.

  2. dns-cache. The local resolver cache, which is a record of what this boot
     has already looked up. Reading it resolves nothing: the entries are
     answers the OS kept from queries that already happened (D2).

  3. dns-log. This is the check that matters most in the whole project, and it
     usually FAILS. Microsoft-Windows-DNS-Client/Operational is disabled by
     default on Windows, so on a typical machine there is no DNS history to
     query at all — meaning past contact with a C&C domain cannot be ruled out
     retrospectively, only *future* contact can. Reporting that gap out loud is
     the point; silently reporting "clean" here would be a lie (D3). The report
     prints the one manual command that turns the log on for next time.

  4. hosts-file. Cheap. An indicator pointed at a sink address is a deliberate
     *block* (protective, not reported as a hit); only a mapping to a real
     address is a finding.

Read-only throughout: this module never writes the registry, never enables the
log, and needs no administrator (D7).
"""


import io
import json
import os
import platform
import re
import subprocess


NAME_HOST = "host"

# winreg is Windows-only; a non-Windows import must not break the package.
try:
    import winreg  # type: ignore
except ImportError:  # pragma: no cover - non-Windows
    winreg = None  # type: ignore

# Resolve PowerShell by its absolute path, never the bare name. Invoked as
# "powershell", Windows resolves it through the executable search order - which
# includes the CURRENT DIRECTORY before System32. The tool tells users to run it
# from their Downloads folder, a user-writable location, so a planted
# powershell.exe there would be executed in its place (issue #7). An absolute
# path is never resolved through that search, so only the real interpreter at
# the System32 location can run; if it is not there, the call fails to a gap
# rather than ever executing a same-named file from elsewhere.
_PS_EXE = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows",
                       "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
# A directory the scanner does not control, used as the child's working
# directory so it cannot inherit a hostile CWD either.
_PS_CWD = os.environ.get("SystemRoot") or r"C:\Windows"
_PS = [_PS_EXE, "-NoProfile", "-NonInteractive",
       "-ExecutionPolicy", "Bypass", "-Command"]

_DNS_LOG = "Microsoft-Windows-DNS-Client/Operational"
_DNS_EVENT_CAP = 50000

# Addresses that mean "this name was deliberately pointed nowhere". Shared by the
# hosts-file check and the resolver-cache check, because the two have to make the
# SAME judgement about the same address: a name answered with one of these was
# blocked by a filter, not reached. This project publishes hosts-file blocklists
# that map these very indicators to 0.0.0.0, so anyone who took our own advice
# will have exactly these entries - and telling them their device "communicated
# with" israeli spyware infrastructure would be a false alarm aimed at precisely
# the people the tool is for.
_SINK_ADDRESSES = {"0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:1"}

# The sub-keys under a CLSID that name a server binary, in the order the PoC
# checks them. InprocHandler32 is included because it is loaded the same way
# and is the quieter of the three.
_SERVER_KINDS = ("InprocServer32", "LocalServer32", "InprocHandler32")
_COM_PATTERN_CANDIDATE_CAP = 128

# HKCU CLSID. Both the 64-bit and 32-bit registry views must be read, and the
# right way is explicit KEY_WOW64_*KEY flags on the ONE logical path - not two
# literal paths. Opening the literal "...\WOW6432Node\CLSID" works only from a
# 64-bit interpreter; from a 32-bit one the plain path is itself redirected into
# WOW6432Node and the literal WOW6432Node path becomes a doubly-nested key that
# does not exist, so the native view - where a hijack lives on a 64-bit box - goes
# unread. winreg may lack the flags on a 32-bit-only build, hence the getattr.
_CLSID_PATH = r"Software\Classes\CLSID"
_REG_VIEWS = [("native", getattr(winreg, "KEY_WOW64_64KEY", 0)),
              ("wow6432", getattr(winreg, "KEY_WOW64_32KEY", 0))]
# ERROR_NO_MORE_ITEMS: the only winerror that means "enumeration finished" rather
# than "enumeration failed". Anything else mid-walk is a truncation, not an end.
_ERROR_NO_MORE_ITEMS = 259

# Exact text required when there is no DNS history to query. Do not reword:
# this gap is the single most important finding the tool can report.
_DNS_LOG_GAP = (
    "DNS-Client/Operational log is disabled (the Windows default) — there is "
    "no queryable DNS history, so past activity cannot be checked "
    "retrospectively from this host")

_ARM_HINT = ("dns-log: Windows is not recording DNS history on this machine. See "
             "\"HOW TO TURN ON DNS HISTORY\" in this report to start a record a future scan "
             "can search. It cannot answer the question for the past.")

# Spelled out, because "enable DNS logging" is not an instruction most people can
# act on, and this is the single highest-value thing a reader can actually do.
# One manual command only: the tool deliberately does not write to the system in
# this release, so there is nothing here that could get the step wrong or need an
# undo. Turn it off again with the same command and /e:false.
_HOW_TO_ENABLE = [
    "HOW TO TURN ON DNS HISTORY (so a future scan can answer this):",
    "  One command, in an Administrator PowerShell:",
    "    1. Click Start, type \"PowerShell\", right-click it, \"Run as administrator\".",
    "    2. Paste this line and press Enter:",
    "         wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864",
    "  (/e:true turns the log on; /ms sets it to 64 MB so it holds months, not",
    "   hours. To turn it back off later, run the same line with /e:false.)",
    "  This does NOT protect you and tells you nothing about the past. It means that",
    "  next time, there is a record to search instead of an empty attic.",
]


# --- PowerShell plumbing ----------------------------------------------------

def _ps(cmd: str, timeout: int = 60):
    """Run one PowerShell command. Returns (returncode, stdout, stderr).
    Never raises for a non-zero exit; callers decide what a failure means.

    errors="replace" is load-bearing, not defensive dressing. PowerShell writes
    in the console's code page, not UTF-8, and a certificate subject with an
    accented character in it (Proton AG's, for one) emits a byte that is not
    valid UTF-8. With strict decoding that raises inside subprocess's own reader
    thread, the whole check degrades to could_not_run, and the tool reports a gap
    it does not actually have. A mangled character in a signer name is a far
    better outcome than a phantom gap.
    """
    # Ask PowerShell to actually write UTF-8, so the decode above usually has
    # nothing to repair in the first place.
    cmd = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    proc = subprocess.run(_PS + [cmd], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          cwd=_PS_CWD)
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def _ps_json(cmd: str, timeout: int = 60):
    """Run a PowerShell command whose output is ConvertTo-Json.

    Returns (rows, error). `rows` is always a list: ConvertTo-Json emits a bare
    object (not an array) for a single result and nothing at all for an empty
    one, so both shapes are normalised here. `error` is "" on success.
    """
    try:
        rc, out, err = _ps(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], "PowerShell timed out after {}s".format(timeout)
    except OSError as exc:
        return [], "PowerShell could not be launched: {}".format(exc)

    text = out.strip()
    if rc != 0:
        reason = err.strip().splitlines()
        return [], (reason[0] if reason else
                    "PowerShell exited {}".format(rc))
    if not text or text == "null":
        return [], ""
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], "unparseable JSON from PowerShell: {}".format(exc)
    if isinstance(data, dict):      # single object, not a list
        return [data], ""
    if isinstance(data, list):
        return data, ""
    return [], "unexpected JSON shape from PowerShell: {}".format(type(data))


def _str(row, *names) -> str:
    """Pull the first present, non-null field from a ConvertTo-Json row."""
    if not isinstance(row, dict):
        return "" if row is None else str(row)
    for name in names:
        val = row.get(name)
        if val not in (None, ""):
            return val if isinstance(val, str) else str(val)
    return ""


# --- shared matching --------------------------------------------------------

def _match(r: ModuleResult, ctx, haystack: str, location: str,
           detail_fmt: str, evidence: str = EV_REFERENCED,
           observed: str = "") -> int:
    """Case-insensitive substring match of every network IOC against one blob
    of local text. Each hit carries its own tier/confidence provenance.

    `detail_fmt` is substituted with a plain replace rather than str.format so
    that artifact text containing braces can never break the detail line."""
    found = 0
    low = (haystack or "").lower()
    if not low:
        return 0
    for ind in ctx.iocs.search(low):
        r.add_hit(Hit(indicator=ind.value, location=location,
                      detail=detail_fmt.replace("{ioc}", ind.value),
                      tier=ind.tier, confidence=ind.confidence,
                      source=ind.source, evidence=evidence, observed=observed))
        found += 1
    return found


# --- 1. per-user COM registrations -----------------------------------------

def _boot_time():
    """Last boot time, which is the entire window the DNS resolver cache covers.
    Returns (iso_string_or_None, error)."""
    rows, err = _ps_json(
        "Get-CimInstance Win32_OperatingSystem"
        " | Select-Object @{n='Boot';e={$_.LastBootUpTime.ToString('o')}}"
        " | ConvertTo-Json -Depth 2 -Compress", timeout=60)
    if err or not rows:
        return None, err or "no result"
    boot = _str(rows[0], "Boot")
    return (boot or None), ""


def _user_writable_dirs():
    """Directories a normal user can drop a DLL into without elevation. A COM
    server living under one of these is the shape the Candiru hijack takes."""
    home = os.path.expanduser("~")
    candidates = [
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("TEMP"),
        os.environ.get("PROGRAMDATA"),
        os.path.join(home, "Downloads") if home else None,
    ]
    return [d.rstrip("\\/").lower() for d in candidates if d]


def _enum_com_registrations(r: ModuleResult):
    """Walk HKCU CLSID (both views) and collect every registered server path.

    Uses winreg rather than PowerShell: this is thousands of key opens and
    spawning a shell for it would dominate the module's runtime.
    """
    entries = []
    partial = []  # views where the walk could not be completed
    for view_name, view_flag in _REG_VIEWS:
        access = winreg.KEY_READ | view_flag
        try:
            base = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _CLSID_PATH, 0, access)
        except FileNotFoundError:
            continue  # this view genuinely has no CLSID key - not a failure
        except OSError as exc:
            partial.append("{} view could not be opened ({})".format(
                view_name, exc))
            continue
        try:
            index = 0
            while True:
                try:
                    clsid = winreg.EnumKey(base, index)
                except OSError as exc:
                    if getattr(exc, "winerror", None) not in (None, _ERROR_NO_MORE_ITEMS):
                        # ACCESS_DENIED / KEY_DELETED / transient: the list was
                        # ABORTED, not exhausted. Record how far we got so the
                        # check cannot pass off a truncated walk as complete.
                        partial.append("{} view enumeration stopped after {} "
                                       "keys ({})".format(view_name, index, exc))
                    break
                index += 1
                for kind in _SERVER_KINDS:
                    sub = "{}\\{}".format(clsid, kind)
                    try:
                        with winreg.OpenKey(base, sub, 0, access) as key:
                            value, _type = winreg.QueryValueEx(key, "")
                    except FileNotFoundError:
                        continue  # no such sub-key, or no default value
                    except OSError as exc:
                        partial.append("{} {} could not be read ({})".format(
                            view_name, sub, exc))
                        continue
                    if not isinstance(value, str) or not value.strip():
                        continue
                    entries.append({
                        "clsid": clsid,
                        "kind": kind,
                        "raw": value,
                        "view": view_name,
                    })
        finally:
            base.Close()
    return entries, partial


def _server_path(raw: str, kind: str) -> str:
    """Turn a registered server value into the path of the binary it names.

    InprocServer32/InprocHandler32 hold a bare DLL path. LocalServer32 holds a
    COMMAND LINE: `"C:\\...\\App.exe" -Embedding`. The PoC only trimmed outer
    quotes, which leaves the switches attached and makes every such entry test
    as "not on disk" — three false review entries on the reference machine. The
    binary is extracted properly here so the on-disk and signature answers are
    about the real file.
    """
    s = os.path.expandvars(raw).strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return s[1:end].strip()
    s = s.strip('"').strip()
    if kind == "LocalServer32" and s:
        # Parse only text here. Even an existence check would contact a UNC
        # server before _check_com has had a chance to reject the path.
        # An extension inside a directory (tool.exe\payload.bat) or a
        # longer filename (tool.exe.backup\app.exe) is not the binary's end.
        # Match extensions in command order, not by extension preference:
        # arguments may themselves contain a later .exe path.
        end = re.search(r"\.(?:exe|com|bat|cmd)(?=\s|$)", s, re.IGNORECASE)
        if end is not None:
            return s[:end.end()].strip()
    return s


# --- "it never connects" enforced for FILESYSTEM paths ---------------------
#
# netguard.py makes network contact impossible through Python's socket module.
# A registered COM path escapes that guard completely: the value comes out of
# the registry, which is attacker-controllable on a compromised machine, and a
# UNC value such as \\attacker-host\share\payload.dll makes WINDOWS open an SMB
# session the instant anything stats the path. The connection is made by the OS,
# not by Python, so the socket guard never sees it and records nothing - and on
# Windows that handshake can hand the remote host this account's NetNTLM
# credentials. A drive letter mapped to a remote share does the same thing with
# none of the visual warning a UNC path gives.
#
# So the question "is this path local?" is answered from the STRING and from the
# OS's own mount table, before anything opens, stats or hashes it.
#
# Residual, stated rather than hidden: a reparse point or symlink sitting under a
# local drive letter can still redirect to a remote location, and there is no way
# to find that out without following it - which is the very act we are avoiding.
# That case needs an attacker who can already create reparse points locally.

# DRIVE_REMOTE from winbase.h: GetDriveTypeW's answer for a letter bound to a
# network share. The call reads the mount table the OS already holds and opens
# nothing itself, which is what makes it safe to ask first.
_DRIVE_REMOTE = 4


def _network_drive_letters():
    """Drive letters currently bound to a remote share.

    Returns (letters, known). `known` is False when the question could not be
    asked at all; per D3 that is reported as a gap, never assumed to mean
    "local".
    """
    letters = set()
    try:
        import ctypes
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW  # type: ignore
    except (ImportError, AttributeError, OSError):  # pragma: no cover - non-Windows
        return letters, False
    for code in range(ord("A"), ord("Z") + 1):
        letter = chr(code)
        try:
            if get_drive_type("{}:\\".format(letter)) == _DRIVE_REMOTE:
                letters.add(letter)
        except OSError:  # pragma: no cover - defensive
            return letters, False
    return letters, True


def _remote_path_reason(path: str, remote_letters, drives_known: bool) -> str:
    """Why this registered path must NOT be touched, or "" if it is local.

    Asked BEFORE os.path.exists(), because on a UNC path the existence test IS
    the connection; there is no safe way to ask afterwards.
    """
    if not path:
        return ""
    s = path.replace("/", "\\")
    low = s.lower()
    rest = s
    if low.startswith("\\\\?\\") or low.startswith("\\\\.\\"):
        # Extended-length prefix. "\\?\UNC\server\share" is the long spelling of
        # "\\server\share", while "\\?\C:\..." wearing the same prefix is an
        # ordinary local path - so the prefix alone settles nothing and the part
        # after it has to be read.
        if low[4:].startswith("unc\\"):
            return "it is a UNC path to a remote share (\\\\?\\UNC\\...)"
        rest = s[4:]
    elif s.startswith("\\\\"):
        return "it is a UNC path to a remote share (\\\\server\\share)"
    if len(rest) >= 2 and rest[0].isalpha() and rest[1] == ":":
        letter = rest[0].upper()
        if letter in remote_letters:
            return "drive {}: is mapped to a remote share".format(letter)
        if not drives_known:
            return ("drive {}: could not be classified as a local disk or a "
                    "network mapping on this host".format(letter))
    return ""


def _signature_status(paths, timeout: int = 180):
    """Leave signatures unverified: the OS verifier may retrieve network data.

    Signature inventory is optional context, never an indicator match. Until a
    strictly offline verifier is available, no verification subprocess is run.
    """
    if not paths:
        return {}, ""
    return ({p.lower(): ("NotChecked", "") for p in paths},
            "signature verification was not performed because the OS verifier "
            "may contact the network; signature status is unknown")


def _check_com(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] enumerating per-user COM registrations (HKCU CLSID)")
    entries, partial = _enum_com_registrations(r)

    # Expand, de-quote and test each registered path before asking about
    # signatures, so the batched call only covers files that exist on disk.
    writable = [os.path.normcase(os.path.normpath(d)).casefold()
                for d in _user_writable_dirs()]
    remote_letters, drives_known = _network_drive_letters()
    on_disk = []
    for e in entries:
        expanded = _server_path(e["raw"], e["kind"])
        e["path"] = expanded
        low = os.path.normcase(os.path.normpath(expanded)).casefold() if expanded else ""
        # Decided before the path is touched: os.path.exists() on a remote path
        # is itself the network contact this tool promises never to make, and it
        # happens inside Windows where netguard cannot see it.
        e["remote_reason"] = _remote_path_reason(expanded, remote_letters,
                                                 drives_known)
        if not e["remote_reason"] and expanded:
            e["remote_reason"] = path_problem(expanded)
        if e["remote_reason"]:
            e["exists"] = False
            e["user_writable"] = False
            continue
        try:
            e["exists"] = bool(expanded) and os.path.exists(expanded)
        except OSError:
            e["exists"] = False
        e["user_writable"] = any(low == d or low.startswith(d + os.sep)
                                 for d in writable)
        if e["exists"]:
            on_disk.append(expanded)

    sigs, sig_err = _signature_status(on_disk)
    if sig_err:
        r.could_not_run("com-signatures", sig_err)

    # The existing general file roots miss a registered server in an unusual
    # local directory. Pass only bounded, local, user-writable file paths to
    # the opt-in pattern module; the latter rechecks each path before reading.
    # A user's explicit --pattern-path retains its documented limited scope.
    if getattr(ctx, "patterns", False) and not getattr(ctx, "pattern_paths", ()):
        unique = {}
        for e in entries:
            if not (e.get("exists") and e.get("user_writable")) or e.get("remote_reason"):
                continue
            try:
                if not os.path.isfile(e["path"]):
                    continue
            except OSError:
                continue
            key = os.path.normcase(os.path.normpath(e["path"]))
            unique.setdefault(key, e["path"])
        candidates = [unique[key] for key in sorted(unique)]
        ctx.pattern_candidate_paths = tuple(candidates[:_COM_PATTERN_CANDIDATE_CAP])
        ctx.pattern_candidate_omitted = max(0, len(candidates) - _COM_PATTERN_CANDIDATE_CAP)

    user_writable = 0
    reviewable = []
    unreachable = []
    for e in entries:
        if e.get("remote_reason"):
            # NOT "not on disk": nobody looked. Rendering a refusal to look as a
            # measurement is exactly the collapse D3 forbids.
            status, signer = "not checked (path is not on a local disk)", ""
        elif e["exists"]:
            status, signer = sigs.get(e["path"].lower(), ("Unknown", ""))
        else:
            status, signer = "n/a (not on disk)", ""
        e["sig"] = status
        e["signer"] = signer
        if e["user_writable"]:
            user_writable += 1

        location = "HKCU\\{}\\{}\\{}".format(
            "Software\\Classes\\WOW6432Node\\CLSID" if e["view"] == "wow6432"
            else "Software\\Classes\\CLSID", e["clsid"], e["kind"])

        # D4: the only COM finding worth calling a Hit is a registered path
        # that actually contains an indicator. "Unsigned DLL in AppData" is a
        # description of a lot of legitimate software, not of this implant.
        _match(r, ctx, "{} {}".format(e["raw"], e["path"]), location,
               "per-user COM server registration references indicator "
               "{ioc} — a COM hijack is this chain's documented persistence; "
               "investigate the registration and the binary",
               EV_PERSISTENCE)

        # The string match above is pure text and costs nothing, so a remote
        # registration is still matched against the indicator set - it is only
        # the FILE behind it that is left alone. Collected here, where the
        # registry location has been formatted, so the report can name it.
        if e.get("remote_reason"):
            unreachable.append((location, e))

        # Reviewable inventory, deliberately narrowed: an entry is only worth a
        # human's attention if it is BOTH in a user-writable directory AND not
        # validly signed. Collected rather than noted inline, so the list can be
        # capped - 8 full-width "not validly signed" lines in the DETAIL channel
        # read as 8 alarms next to the real hits.
        if e["user_writable"] and status not in ("Valid", "Unknown", "NotChecked"):
            reviewable.append((location, e))

    if reviewable:
        r.note("com-persistence: {} per-user COM registration(s) are in a folder "
               "you can write to and are not validly signed. Legitimate software "
               "does this too - these are pointers for a reviewer, NOT findings, "
               "and none of them matched an indicator.".format(len(reviewable)))
        for location, e in reviewable[:3]:
            r.note("    - {} -> {} [on disk: {}; signature: {}{}]".format(
                location, e["path"] or "(empty)",
                "yes" if e["exists"] else "no", e["sig"],
                "; signer: " + e["signer"] if e["signer"] else ""))
        if len(reviewable) > 3:
            r.note("    - ... and {} more, listed in full in the JSON report."
                   .format(len(reviewable) - 3))

    if unreachable:
        # Refusing to touch the path is the right call, but a refusal is a GAP,
        # not a clean entry, and the user is owed both facts: what was skipped
        # and why skipping it was the safe thing to do.
        r.note("com-persistence: {} per-user COM registration(s) name a path "
               "that is not on a local disk. The scanner did NOT open them. "
               "Merely testing whether such a path exists makes Windows open a "
               "connection to the remote host - and can hand that host this "
               "account's network credentials - which is the one thing this "
               "tool promises never to do. These entries are UNVERIFIED: their "
               "file was not fingerprinted and its signature was not checked."
               .format(len(unreachable)))
        for location, e in unreachable[:3]:
            r.note("    - {} -> {} [not checked: {}]".format(
                location, e["path"] or "(empty)", e["remote_reason"]))
        if len(unreachable) > 3:
            r.note("    - ... and {} more, listed in full in the JSON report."
                   .format(len(unreachable) - 3))

    r.checked += len(entries)
    r.submetrics["com_registrations"] = len(entries)
    r.submetrics["com_user_writable"] = user_writable
    if unreachable:
        r.submetrics["com_remote_paths"] = len(unreachable)

    # A truncated enumeration must not pass as a complete one (D3). If a registry
    # view could not be fully walked, the COM surface was only partly checked.
    if partial:
        r.could_not_run("com-persistence",
                        "the registry could not be fully enumerated, so an "
                        "auto-start entry may have been missed: {}".format(
                            "; ".join(partial)))
    elif unreachable:
        # Same doctrine, different cause: the registry was read in full, but
        # some of what it named was deliberately not opened.
        r.could_not_run("com-persistence",
                        "{} registered path(s) are not on a local disk and were "
                        "deliberately not opened (contacting them is what this "
                        "tool promises not to do), so those entries were not "
                        "verified: {}".format(
                            len(unreachable),
                            "; ".join(sorted(set(
                                e["remote_reason"] for _loc, e in unreachable)))))
    else:
        r.ran("com-persistence")
    ctx.emit("[host] COM registrations: {} ({} in user-writable dirs)"
             .format(len(entries), user_writable))


# --- 2. DNS resolver cache --------------------------------------------------

def _check_dns_cache(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] reading local DNS resolver cache")
    # Reads the cache the OS already holds. It issues no query and resolves
    # nothing, which is exactly why D2 permits it.
    rows, err = _ps_json(
        "Get-DnsClientCache -ErrorAction Stop"
        " | Select-Object Entry,Name,Data,Type"
        " | ConvertTo-Json -Depth 3 -Compress", timeout=60)
    if err:
        r.could_not_run("dns-cache", "Get-DnsClientCache unavailable: {}".format(err))
        return

    hits = 0
    blocked = 0
    for row in rows:
        entry = _str(row, "Entry")
        name = _str(row, "Name")
        data = _str(row, "Data")
        # Windows preloads hosts-file mappings into the resolver cache when
        # the DNS Client starts, even if no application looked up that name.
        # A sink entry is therefore protective state, not proof of an attempted
        # connection. Installing our blocklist must not create findings.
        # https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups
        was_blocked = data.strip().lower() in _SINK_ADDRESSES
        haystack = " ".join((entry, name, data))
        if was_blocked:
            blocked += sum(1 for _ind in ctx.iocs.search(haystack.lower()))
            continue
        where = ("(Entry=" + (entry or "-") + " Name=" + (name or "-") +
                 " Data=" + (data or "-") + ")")
        detail = ("indicator {ioc} appears as a name or address in this "
                  "boot's DNS resolver cache " + where + " — this is a "
                  "resolver record; endpoint contact is unverified")
        found = _match(r, ctx, haystack, "DNS resolver cache", detail, EV_DNS)
        hits += found

    r.checked += len(rows)
    r.submetrics["dns_cache_entries"] = len(rows)
    if blocked:
        r.submetrics["dns_cache_blocked_indicators"] = blocked
        r.note("dns-cache: {} indicator entry/entries point to a sink address. "
               "This is protective state, not a finding. Windows can preload "
               "these entries from the hosts file without any lookup; no "
               "attempt or contact is established.".format(blocked))

    # The resolver cache is wiped by a reboot, so its whole window is "since last
    # boot". Stating that plainly stops a clean cache being read as a clean history.
    boot, boot_err = _boot_time()
    r.reach["dns-cache"] = {
        "earliest": boot,
        "days": None,
        "basis": "the resolver cache holds only this boot session"
                 + ("" if boot else " (boot time unavailable: {})".format(boot_err)),
        "note": "The cache includes hosts-file mappings loaded at startup and "
                "records obtained during this boot. An entry alone does not "
                "establish that an application looked it up or connected.",
    }
    r.ran("dns-cache")
    ctx.emit("[host] DNS cache entries: {} ({} DNS findings, {} protective "
             "sink entries)".format(len(rows), hits, blocked))


# --- 3. retrospective DNS history ------------------------------------------

def _check_dns_log(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] checking whether DNS-Client/Operational history exists")
    rows, err = _ps_json(
        "Get-WinEvent -ListLog '{}' -ErrorAction Stop"
        " | Select-Object @{{n='IsEnabled';e={{[bool]$_.IsEnabled}}}},"
        " @{{n='RecordCount';e={{[int]$_.RecordCount}}}}"
        " | ConvertTo-Json -Depth 3 -Compress".format(_DNS_LOG), timeout=60)

    if err or not rows:
        # Log absent or unreadable: the consequence for the user is identical
        # to it being disabled, so it is reported as the same gap, not as an
        # incidental error.
        r.submetrics["dns_log_enabled"] = 0
        r.submetrics["dns_log_records"] = 0
        r.could_not_run("dns-log", _DNS_LOG_GAP)
        r.note("dns-log: {} could not be queried ({})".format(
            _DNS_LOG, err or "log not present on this host"))
        r.note(_ARM_HINT)
        r.reach["dns-log"] = {
            "earliest": None,
            "days": 0,
            "basis": "DNS log metadata could not be read",
            "note": "No historical window could be established. Older or "
                    "unread records may still exist.",
            "how_to_enable": _HOW_TO_ENABLE,
        }
        return

    row = rows[0]
    enabled = bool(row.get("IsEnabled"))
    try:
        records = int(row.get("RecordCount") or 0)
    except (TypeError, ValueError):
        records = 0
    r.submetrics["dns_log_enabled"] = 1 if enabled else 0
    r.submetrics["dns_log_records"] = records

    if records <= 0:
        # The important branch, and the common one. This must never read clean.
        r.could_not_run("dns-log", _DNS_LOG_GAP)
        r.note("dns-log: {} enabled={} records={} — forward-looking checks are "
               "possible, retrospective ones are not.".format(
                   _DNS_LOG, enabled, records))
        r.note(_ARM_HINT)
        r.reach["dns-log"] = {
            "earliest": None,
            "days": 0,
            "basis": "DNS logging is {} and holds {} records".format(
                "enabled" if enabled else "disabled", records),
            "note": "No saved DNS events were available for this scan. "
                    "This does not establish whether older events existed or were cleared.",
            "how_to_enable": _HOW_TO_ENABLE,
        }
        return

    # IsEnabled controls current collection, not whether retained events can
    # be read. Disabling logging must not hide existing historical evidence.
    if not enabled:
        r.could_not_run("dns-log-recording",
                        "DNS logging is currently off; queries made while "
                        "logging was off may be missing")
        r.note("dns-log: logging is off; the log reports {} saved event(s). "
               "Checking them does not enable logging."
               .format(records))
    ctx.emit("[host] DNS-Client/Operational logging is {} ({} retained records); "
             "scanning messages".format("on" if enabled else "off", records))
    # -ErrorAction Stop, not SilentlyContinue: with SilentlyContinue a failure to
    # read the channel (ACL, corrupt .evtx, Event Log service degraded) exits 0
    # with no output, so `events` is [] and `ev_err` is "" - and the log, which is
    # ENABLED and holds records, gets reported as a check that ran and found
    # nothing. That rolls up to CLEAN: the one check the whole tool exists for,
    # silently certifying an unread log as clean history. ToString('o') gives ISO
    # 8601 so min()/max() sort chronologically rather than by locale date string.
    events, ev_err = _ps_json(
        "Get-WinEvent -LogName '{}' -MaxEvents {}"
        " -ErrorAction Stop"
        " | Select-Object @{{n='Time';e={{$_.TimeCreated.ToString('o')}}}},"
        " @{{n='Message';e={{[string]$_.Message}}}}"
        " | ConvertTo-Json -Depth 3 -Compress".format(
            _DNS_LOG, _DNS_EVENT_CAP), timeout=300)
    if (ev_err and not events) or (records > 0 and not events):
        reason = ("log has {} retained records but none could be read{} - this "
                  "machine's DNS history was NOT searched, so nothing here is "
                  "cleared".format(records, ": " + ev_err if ev_err else ""))
        r.could_not_run("dns-log", reason)
        return

    hits = 0
    times = [t for t in (_str(ev, "Time") for ev in events) if t]
    if times:
        # Retained records have dates even when logging is currently disabled.
        r.reach["dns-log"] = {
            "earliest": min(times),
            "days": None,
            "basis": "oldest of {:,} DNS events read (cap {:,})".format(
                len(times), _DNS_EVENT_CAP),
            "note": "Queries before this are either rotated out of the log or "
                    "beyond the bounded event read.",
        }
        if not enabled:
            r.reach["dns-log"]["note"] += " Logging is currently off; queries during unrecorded periods may be missing."
            r.reach["dns-log"]["how_to_enable"] = _HOW_TO_ENABLE
    for ev in events:
        when = _str(ev, "Time")
        hits += _match(
            r, ctx, _str(ev, "Message"),
            "{} @ {}".format(_DNS_LOG, when or "unknown time"),
            "indicator {ioc} appears as a name or address in a "
            "DNS-Client/Operational event" +
            (" at " + when if when else "") +
            " — the event alone does not establish successful resolution or "
            "endpoint contact",
            EV_DNS, when)

    r.checked += len(events)
    r.submetrics["dns_log_events_scanned"] = len(events)
    r.ran("dns-log")
    if records > len(events):
        # A note alone let the overall check appear complete and clean even
        # though older retained DNS records were never examined.
        r.could_not_run("dns-log-older-events",
                        "examined the most recent {} of {} retained records "
                        "(read cap {:,}); older entries were not checked".format(
                            len(events), records, _DNS_EVENT_CAP))
    ctx.emit("[host] DNS log events scanned: {} ({} indicator matches)"
             .format(len(events), hits))


# --- 4. hosts file ----------------------------------------------------------

def _check_hosts(r: ModuleResult, ctx) -> None:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    path = os.path.join(root, "System32", "drivers", "etc", "hosts")
    ctx.emit("[host] reading {}".format(path))
    problem = path_problem(path)
    if problem:
        r.could_not_run("hosts-file", problem)
        return
    if not os.path.exists(path):
        r.could_not_run("hosts-file", "no hosts file at {}".format(path))
        return
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.readlines()
    except OSError as exc:
        r.could_not_run("hosts-file", "could not read {}: {}".format(path, exc))
        return

    active = [ln.strip() for ln in raw
              if ln.strip() and not ln.strip().startswith("#")]
    # A hosts line is "<address> <hostname...>". Pointing an indicator at one of
    # these sink addresses is a deliberate BLOCK - protective, the OPPOSITE of a
    # compromise - so it is not reported as a hit at all, only counted. Only a
    # mapping to a REAL address is a finding (EV_CONFIGURED).
    _SINKS = _SINK_ADDRESSES
    hits = 0
    blocked = 0
    for line in active:
        parts = line.split()
        addr = parts[0] if parts else ""
        if addr in _SINKS:
            # Still check it DOES contain an indicator, for the block count, but
            # never raise a hit on a protective entry.
            if ctx.iocs.search(line.lower()):
                blocked += 1
            continue
        hits += _match(
            r, ctx, line, path,
            "indicator {ioc} is mapped in the hosts file to " + addr +
            " (line: " + line + "). This is NOT a sink/block address, so the "
            "name has been pointed at a real host on this machine - unusual, "
            "and worth checking who added it.",
            EV_CONFIGURED)

    r.checked += 1
    r.submetrics["hosts_entries"] = len(active)
    if blocked:
        r.submetrics["hosts_blocked_indicators"] = blocked
        r.note("hosts-file: {} indicator(s) are BLOCKED in the hosts file "
               "(pointed at a sink address). That is protective, not a finding."
               .format(blocked))
    r.ran("hosts-file")
    ctx.emit("[host] active hosts entries: {} ({} indicator matches, {} blocked)"
             .format(len(active), hits, blocked))


# --- 5. known fixed-path file drops -----------------------------------------

# Files this campaign and its tooling drop at a FIXED path, where the path itself
# is the lead. HW.sys is the signed-but-vulnerable kernel driver Candiru brings to
# disable protections (bring-your-own-vulnerable-driver); Avast documented its
# path and the exact hash. The path is a generic name, so presence alone is only a
# pointer - the check hashes the file and says whether it is the KNOWN-BAD build
# (hash in the IOC set) or merely a same-named file to look at.
# Path parts, not a backslash string: os.path.join builds the right separator on
# every OS. A literal "System32\\drivers\\HW.sys" would be one filename with
# embedded backslashes on POSIX, so the check (and its test) only worked on Windows.
_KNOWN_DROPS = [
    (("System32", "drivers", "HW.sys"),
     "the signed-but-vulnerable driver Candiru uses to disable protections "
     "(bring-your-own-vulnerable-driver); documented by Avast, CVE-2022-2294"),
]


def _check_known_paths(r: ModuleResult, ctx) -> None:
    import hashlib
    root = os.environ.get("SystemRoot", r"C:\Windows")
    known_hashes = {h.value for h in ctx.iocs.hashes}
    found = 0
    unavailable = 0
    for parts, why in _KNOWN_DROPS:
        path = os.path.join(root, *parts)
        try:
            problem = path_problem(path)
            if problem:
                raise PermissionError(13, problem, path)
            os.stat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            unavailable += 1
            r.skipped += 1
            r.could_not_run("known-path:" + path,
                            "could not inspect this path: {}".format(exc))
            continue
        found += 1
        digest = ""
        try:
            h = hashlib.sha256()
            with io.open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        except OSError as exc:
            unavailable += 1
            r.skipped += 1
            r.could_not_run("known-path:" + path,
                            "file exists but its fingerprint is unavailable: {}"
                            .format(exc))
            continue
        if digest and digest in known_hashes:
            ind = ctx.iocs.lookup(digest)
            tier = ind.tier if ind else "sample"
            # A `vuln-driver` match is legitimate signed software this actor
            # abuses - present on clean machines too. Calling that "KNOWN-BAD"
            # would tell an innocent owner they are infected, so the wording is
            # chosen from the tier (see NOT_MALWARE_TIERS in report.py).
            if tier == "vuln-driver":
                detail = ("the file at {} matches a published indicator for {}. "
                          "This file is LEGITIMATE, signed software that is also "
                          "installed for honest reasons - its presence is NOT "
                          "proof of spyware. Worth establishing how and when it "
                          "was installed. Do not delete it.".format(path, why))
            else:
                detail = ("the file at {} is the KNOWN-BAD build - {}. Its "
                          "SHA-256 matches a published indicator. Do not delete "
                          "it; it is evidence.".format(path, why))
            r.add_hit(Hit(
                indicator=digest, location=path, detail=detail,
                tier=tier,
                confidence=ind.confidence if ind else "secondary",
                source=ind.source if ind else "", evidence=EV_ON_DISK))
        else:
            # Present, but not the known-bad hash. A legitimate
            # driver of the same name exists, so this is a POINTER, not a hit:
            # recorded as a note, graded nowhere, so it never alarms on its own.
            r.note("known-paths: a file exists at {} ({}). This path is {}. "
                   "Its fingerprint does NOT match the known-bad build{}, so it "
                   "is most likely a legitimate same-named file - but given the "
                   "path it is worth a look.".format(
                       path, "SHA-256 " + digest[:16] + "..." if digest else
                       "unreadable", why,
                       "" if digest else " (could not read it)"))
    r.checked += len(_KNOWN_DROPS) - unavailable
    r.submetrics["known_paths_checked"] = len(_KNOWN_DROPS) - unavailable
    if found:
        r.submetrics["known_paths_present"] = found
    if unavailable < len(_KNOWN_DROPS):
        r.ran("known-paths")
    ctx.emit("[host] known fixed-path drops: {} checked, {} present".format(
        len(_KNOWN_DROPS), found))


# --- module entry point -----------------------------------------------------

def run_host(ctx) -> ModuleResult:
    r = ModuleResult(NAME_HOST)
    # Publish the result straight away so that if anything below raises, the CLI
    # can still recover whatever was found before the failure instead of
    # discarding it (see ScanContext.partial).
    ctx.partial = r

    system = platform.system()
    if system != "Windows" or winreg is None:
        # Never a fake CLEAN on a platform where nothing was observed.
        reason = "not supported on {}".format(system or "unknown platform")
        for name in ("com-persistence", "dns-cache", "dns-log", "hosts-file",
                     "known-paths"):
            r.could_not_run(name, reason)
        return r

    # Each check is isolated: one failure must not cost the others.
    for name, fn in (("com-persistence", _check_com),
                     ("dns-cache", _check_dns_cache),
                     ("dns-log", _check_dns_log),
                     ("hosts-file", _check_hosts),
                     ("known-paths", _check_known_paths)):
        try:
            fn(r, ctx)
        except Exception as exc:
            r.skipped += 1
            r.could_not_run(name, "{}: {}".format(type(exc).__name__, exc))

    return r


# --- modules/patternscan -----------------------------------------------------
_pattern_roots = _roots  # hash module default local roots
"""Optional, bounded matching of pinned public Candiru research rules.

Matches require investigation; they are neither exact sample identifications nor
confirmation of infection. No rule or sample is fetched by this module.
"""


import importlib as _pattern_importlib
import io as _pattern_io
import os as _pattern_os
import stat as _pattern_stat
import sys as _pattern_sys


NAME_PATTERNS = "patterns"
_PATTERN_MAX_BYTES = 1024 * 1024
_PATTERN_MAX_FILES = 50000
_PATTERN_MAX_DIRS = 20000
_PATTERN_MAX_ENTRIES = 100000
_PATTERN_MAX_DEPTH = 64
_PATTERN_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_PATTERN_TIMEOUT = 5
_PATTERN_PRUNE = ("cache", "cache_data", "gpucache", "code cache", "node_modules",
                  ".git", "servicepackfiles", "winsxs")
_PATTERN_CLOUD_ATTRIBUTES = 0x1000 | 0x40000 | 0x400000


class _PatternLimit(RuntimeError):
    """A resource bound left part of the requested scope unobserved."""


class _PatternNoRead(OSError):
    """A known preflight rejection before any file data read was attempted."""


def _pattern_budget(counts):
    if counts["files"] >= _PATTERN_MAX_FILES:
        raise _PatternLimit("file cap reached")
    if counts["bytes"] + _PATTERN_MAX_BYTES + 1 > _PATTERN_MAX_TOTAL_BYTES:
        raise _PatternLimit("byte cap reached")


def _pattern_walk(root, counts, r, onerror, depth=0):
    """Yield files from streaming scandir; never materialize directory entries.

    Entry budget includes refused and pruned entries, before any classification
    or locality/cloud checks. At most MAX_DEPTH iterators are open; early close
    unwinds every with-block. There is no growing pending-directory list.
    """
    _pattern_budget(counts)
    if counts["entries"] >= _PATTERN_MAX_ENTRIES:
        raise _PatternLimit("directory entry cap reached")
    if depth >= _PATTERN_MAX_DEPTH:
        raise _PatternLimit("directory depth cap reached")
    if counts["dirs"] >= _PATTERN_MAX_DIRS:
        raise _PatternLimit("directory cap reached")
    counts["dirs"] += 1
    r.submetrics["directories_pattern_visited"] = counts["dirs"]
    try:
        problem = _pattern_problem(root)
        if problem:
            raise OSError(problem)
        with _pattern_os.scandir(root) as entries:
            while True:
                # Check before requesting/classifying another entry. Reaching
                # the exact cap is conservatively a gap, even if it was last.
                _pattern_budget(counts)
                if counts["entries"] >= _PATTERN_MAX_ENTRIES:
                    raise _PatternLimit("directory entry cap reached")
                try:
                    entry = next(entries)
                except StopIteration:
                    return
                counts["entries"] += 1
                r.submetrics["filesystem_entries_considered"] = counts["entries"]
                try:
                    info = entry.stat(follow_symlinks=False)
                    if (_pattern_stat.S_ISLNK(info.st_mode)
                            or getattr(info, "st_file_attributes", 0) & 0x400):
                        raise OSError("symlink or reparse point was not followed")
                    if getattr(info, "st_file_attributes", 0) & _PATTERN_CLOUD_ATTRIBUTES:
                        raise OSError("offline or cloud-recall path was not opened")
                    if _pattern_stat.S_ISDIR(info.st_mode):
                        if entry.name.lower() in _PATTERN_PRUNE:
                            r.submetrics["directories_pruned"] = r.submetrics.get("directories_pruned", 0) + 1
                            onerror("directory skipped by pattern scan's size limits", entry.path)
                        else:
                            yield from _pattern_walk(entry.path, counts, r, onerror, depth + 1)
                    elif _pattern_stat.S_ISREG(info.st_mode):
                        yield entry.path
                    else:
                        raise OSError("special filesystem entry was not opened")
                except OSError as exc:
                    onerror(str(exc), entry.path)
    except OSError as exc:
        onerror(str(exc), root)


def _pattern_problem(path):
    problem = path_problem(path)
    if problem:
        return problem
    # OFFLINE and recall attributes can occur independently of reparse points.
    # Inspect every ancestor without opening the file's data stream.
    current = path
    while current:
        try:
            info = _pattern_os.lstat(current)
        except FileNotFoundError:
            return ""
        if getattr(info, "st_file_attributes", 0) & _PATTERN_CLOUD_ATTRIBUTES:
            return "offline or cloud-recall path was not opened"
        parent = _pattern_os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return ""


def _pattern_identity(info):
    return (info.st_dev, info.st_ino, info.st_size,
            getattr(info, "st_mtime_ns", info.st_mtime),
            getattr(info, "st_ctime_ns", info.st_ctime))


def _pattern_shared_identity(info):
    # Windows Python 3.12 can report different st_ctime_ns values for lstat
    # and fstat on the same file. Compare ctime only between calls to the same
    # API; volume, file ID, size and mtime remain comparable across APIs.
    return _pattern_identity(info)[:4]


def _pattern_read(path):
    """Bound the read, reject special files, and detect observable replacements.

    Like the shared locality guard, this is conservative filesystem validation,
    not a sandbox against a concurrent privileged filesystem adversary.
    """
    read_started = False
    try:
        problem = _pattern_problem(path)
        if problem:
            raise OSError(problem)
        before = _pattern_os.lstat(path)
        if not _pattern_stat.S_ISREG(before.st_mode):
            raise OSError("not a regular local file")
        if before.st_size > _PATTERN_MAX_BYTES:
            raise OSError("file exceeds 1 MiB pattern read cap")
        flags = (_pattern_os.O_RDONLY | getattr(_pattern_os, "O_BINARY", 0)
                 | getattr(_pattern_os, "O_NOFOLLOW", 0)
                 | getattr(_pattern_os, "O_NONBLOCK", 0))
        fd = _pattern_os.open(path, flags)
        try:
            stream = _pattern_io.open(fd, "rb", closefd=True)
        except Exception:
            _pattern_os.close(fd)
            raise
        with stream:
            opened = _pattern_os.fstat(stream.fileno())
            if (not _pattern_stat.S_ISREG(opened.st_mode)
                    or _pattern_shared_identity(before) != _pattern_shared_identity(opened)
                    or _pattern_identity(before) != _pattern_identity(_pattern_os.lstat(path))):
                raise OSError("file changed before bounded read")
            problem = _pattern_problem(path)
            if problem:
                raise OSError(problem)
            # From this point an incomplete/failed read may have consumed data;
            # preserve the caller's maximum reservation for every such failure.
            read_started = True
            data = stream.read(_PATTERN_MAX_BYTES + 1)
            after = _pattern_os.fstat(stream.fileno())
        final = _pattern_os.lstat(path)
        problem = _pattern_problem(path)
        if problem:
            raise OSError(problem)
        if (len(data) > _PATTERN_MAX_BYTES or len(data) != before.st_size
                or _pattern_shared_identity(before) != _pattern_shared_identity(after)
                or _pattern_identity(opened) != _pattern_identity(after)
                or _pattern_identity(before) != _pattern_identity(final)):
            raise OSError("file grew or changed during bounded read")
        return data
    except OSError as exc:
        if not read_started:
            raise _PatternNoRead(str(exc)) from exc
        raise


def _pattern_engine():
    if _pattern_sys.version_info < (3, 9):
        raise RuntimeError("optional Candiru patterns require Python 3.9 or newer")
    engine = _pattern_importlib.import_module("yara_x")
    metadata = _pattern_importlib.import_module("importlib.metadata")
    version = metadata.version("yara-x")
    if version != CANDIRU_ENGINE_VERSION:
        raise RuntimeError("unsupported yara-x version {}; supported pinned version is {}"
                           .format(version, CANDIRU_ENGINE_VERSION))
    compiler = engine.Compiler()
    compiler.enable_includes(False)
    for source in CANDIRU_RULE_SOURCES:
        compiler.add_source(source)
    scanner = engine.Scanner(compiler.build())
    scanner.set_timeout(_PATTERN_TIMEOUT)
    return scanner


def _pattern_selected_roots(ctx):
    requested = getattr(ctx, "pattern_paths", ())
    # High-value registered files go first. A broad root can exhaust the
    # bounded budget; it must not prevent these targeted paths from being read.
    roots = requested if requested else list(getattr(ctx, "pattern_candidate_paths", ())) + list(
        _pattern_roots())
    # Lexical normalization only: resolving first could follow a refused link.
    unique = []
    for root in roots:
        raw = _pattern_os.fspath(root)
        # Check traversal and UNC/device spellings before normalization.
        problem = path_problem(raw)
        normalized = raw if problem else _pattern_os.path.normpath(raw)
        key = _pattern_os.path.normcase(normalized)
        if not any(key == old[0] for old in unique):
            unique.append((key, normalized, bool(problem)))
    # An explicitly selected child remains meaningful even beneath a selected
    # parent: the parent traversal might prune its directory. File-level dedup
    # below avoids duplicate scans while retaining each requested root.
    return [path for _, path, _ in unique]


def run_patterns(ctx) -> ModuleResult:
    r = ModuleResult(NAME_PATTERNS)
    ctx.partial = r
    r.note("Optional public Candiru file patterns; matches require investigation, "
           "not an exact sample identification or confirmed infection. "
           "No match does not exclude encrypted, packed, memory-only, or other builds.")
    r.note("All regular file names are eligible, including extensionless files. "
           "Read cap: 1 MiB/file; scan caps: {} files, {} directories, {} entries, "
           "{} directory levels, {} MiB read budget; "
           "{} seconds per engine scan. Pruned directory names: {}."
           .format(_PATTERN_MAX_FILES, _PATTERN_MAX_DIRS, _PATTERN_MAX_ENTRIES,
                   _PATTERN_MAX_DEPTH, _PATTERN_MAX_TOTAL_BYTES // (1024 * 1024), _PATTERN_TIMEOUT,
                   ", ".join(_PATTERN_PRUNE)))
    try:
        scanner = _pattern_engine()
    except Exception as exc:
        r.could_not_run("pattern-engine", "optional pinned yara-x {} unavailable "
                        "or could not compile trusted rules: {}: {}"
                        .format(CANDIRU_ENGINE_VERSION, type(exc).__name__, exc))
        return r
    try:
        roots = _pattern_selected_roots(ctx)
    except (OSError, ValueError, TypeError) as exc:
        r.could_not_run("pattern-roots", str(exc))
        return r
    if not roots:
        r.could_not_run("pattern-roots", "no local pattern paths were selected")
        return r

    auto_candidates = set()
    if not getattr(ctx, "pattern_paths", ()):
        auto_candidates = {_pattern_os.path.normcase(_pattern_os.path.normpath(p))
                           for p in getattr(ctx, "pattern_candidate_paths", ())}
        if auto_candidates:
            auto_candidates.difference_update(
                _pattern_os.path.normcase(_pattern_os.path.normpath(p))
                for p in _pattern_roots())
        if auto_candidates:
            r.note("Also checking up to {} local, user-writable files named by "
                   "per-user COM registrations; registration alone is not a finding."
                   .format(len(auto_candidates)))
        omitted = getattr(ctx, "pattern_candidate_omitted", 0)
        if omitted:
            r.could_not_run("com-pattern-candidates", "{} registered file path(s) "
                            "were omitted by the registered-path safety cap".format(
                                omitted))

    counts = {"files": 0, "dirs": 0, "entries": 0, "bytes": 0}
    seen_files = {}  # bounded by MAX_FILES; value says whether scan succeeded
    for root in roots:
        name = "root:" + root
        tally = {"checked": 0, "covered": 0, "gaps": 0, "candidates": 0}

        def _pattern_gap(reason, location=root):
            tally["gaps"] += 1
            r.skipped += 1
            # Keep output and memory bounded even with a tree of refused files.
            if tally["gaps"] <= 10:
                r.note("Pattern file skipped at {}: {}".format(location, reason))

        try:
            problem = _pattern_problem(root)
            if problem:
                raise OSError(problem)
            info = _pattern_os.lstat(root)
            if _pattern_stat.S_ISREG(info.st_mode):
                entries = iter((root,))
            elif _pattern_stat.S_ISDIR(info.st_mode):
                if _pattern_os.path.normcase(_pattern_os.path.normpath(root)) in auto_candidates:
                    raise OSError("registered COM target changed into a directory; not traversed")
                entries = _pattern_walk(root, counts, r, _pattern_gap)
            else:
                raise OSError("not a regular file or directory")
        except OSError as exc:
            r.skipped += 1
            r.could_not_run(name, str(exc))
            continue
        ctx.emit("[patterns] scanning {} ...".format(root))
        try:
            for full in entries:
                key = _pattern_os.path.normcase(_pattern_os.path.normpath(full))
                if key in seen_files:
                    if seen_files[key]:
                        tally["covered"] += 1
                    else:
                        tally["gaps"] += 1
                    continue
                _pattern_budget(counts)
                counts["files"] += 1
                seen_files[key] = False
                tally["candidates"] += 1
                # Charge the maximum bounded read before touching data. Failed
                # reads retain the reservation, so changed/failed files cannot
                # bypass the aggregate budget. Proven preflight rejections
                # refund it all; successful reads refund only unused bytes.
                counts["bytes"] += _PATTERN_MAX_BYTES + 1
                try:
                    data = _pattern_read(full)
                    counts["bytes"] -= _PATTERN_MAX_BYTES + 1 - len(data)
                    matches = scanner.scan(data).matching_rules
                    known = []
                    for rule in matches:
                        identifier = rule.identifier
                        if identifier not in CANDIRU_RULE_METADATA:
                            raise RuntimeError("engine returned unknown rule identifier: {}".format(identifier))
                        known.append(identifier)
                except _PatternNoRead as exc:
                    counts["bytes"] -= _PATTERN_MAX_BYTES + 1
                    _pattern_gap("{}: {}".format(type(exc).__name__, exc), full)
                    continue
                except Exception as exc:
                    _pattern_gap("{}: {}".format(type(exc).__name__, exc), full)
                    continue
                r.checked += 1
                seen_files[key] = True
                tally["checked"] += 1
                r.submetrics["files_pattern_scanned"] = r.checked
                r.submetrics["bytes_pattern_scanned"] = r.submetrics.get("bytes_pattern_scanned", 0) + len(data)
                for identifier in known:
                    attribution = CANDIRU_RULE_METADATA[identifier]
                    detail = ("Public research rule {} matched; author: {}; license: {} ({}). "
                              "Pattern match requires investigation; not an exact sample "
                              "identification or confirmed infection. Source: {}"
                              .format(identifier, attribution["author"], attribution["license"],
                                      attribution["license_url"], attribution["source"]))
                    r.add_hit(Hit(indicator="yara:" + identifier, location=full,
                                  detail=detail, tier="candiru-pattern",
                                  confidence="research-rule", source=attribution["source"],
                                  evidence="file-pattern"))
                    # Match messages also preserve the DRL-required authorship.
                    ctx.emit("[patterns] !! MATCH {}: {}".format(full, detail))
        except _PatternLimit as exc:
            if tally["checked"] or tally["covered"]:
                r.ran(name + " (scanned subset)")
            r.could_not_run("pattern-limits", str(exc) +
                            "; this and remaining roots were not fully scanned")
            return r
        finally:
            close = getattr(entries, "close", None)
            if close:
                close()
        if tally["checked"] or tally["covered"]:
            r.ran(name)
        elif not tally["gaps"]:
            r.could_not_run(name, "no regular files were available for pattern scanning")
        if tally["gaps"]:
            r.could_not_run(name + " (coverage gaps)",
                            "{} file/subtree item(s) unreadable, unsafe, oversized, changed, "
                            "or not scanned successfully; {} file(s) scanned".format(
                                tally["gaps"], tally["checked"] + tally["covered"]))
    return r


# --- entry point ------------------------------------------------------------


def _load_embedded_iocs(path=None):
    """Parse the embedded indicator data, or an external file if one is given."""
    if path:
        return load(path)
    import tempfile
    tmp = tempfile.mkdtemp(prefix="adint_ioc_")
    try:
        p = os.path.join(tmp, "adfection_iocs.txt")
        with io.open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(IOC_DATA)
        ioc_set = load(p)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # Report the age of the DATA, not of the temp file we just wrote, so the
    # staleness warning stays truthful in a single-file build.
    ioc_set.source_mtime = IOC_BUILD_EPOCH
    ioc_set.source_path = "(embedded in this script)"
    return ioc_set


def _hold(args):
    """Keep the window open when this was double-clicked.

    Double-clicking a .py in Explorer opens a console that closes the instant
    the script ends - so the entire report would flash past unread, which is the
    most likely way a non-technical person runs this. Pausing costs a keypress
    for anyone running it from a terminal, and saves the report for everyone else.
    """
    if getattr(args, "no_pause", False) or not sys.stdout.isatty():
        return
    try:
        input("\nPress Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass


def _force_utf8_io():
    """Make stdout/stderr encode UTF-8 whatever the console code page is. On a
    stock Windows Python these default to cp1252, and printing a non-Latin
    profile name or username - Arabic, Hebrew, Persian, Cyrillic, CJK, i.e. this
    tool's users - then crashes with UnicodeEncodeError instead of producing a
    report, worst of all while writing the report file after the work is done.
    This makes the fix independent of the caller remembering `python -X utf8`."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    _force_utf8_io()
    p = argparse.ArgumentParser(
        prog="zero-breach",
        description="Read-only check for published AdFection / Candiru "
                    "indicators. A clean result is NOT a clean bill of health.")
    p.add_argument("--json", metavar="PATH",
                   help="also write a machine-readable report to PATH")
    p.add_argument("--iocs", metavar="PATH",
                   help="use an external indicator file instead of the "
                        "embedded one")
    p.add_argument("--version", action="version",
                   version="Zero Breach " + __version__)
    p.add_argument("--quick", action="store_true",
                   help="skip fingerprinting every file (roughly halves the "
                        "runtime). The skipped check is reported as a gap, not "
                        "as clean.")
    p.add_argument("--no-pause", action="store_true",
                   help="do not wait for a keypress before exiting")
    p.add_argument("--patterns", action="store_true",
                   help="experimental local Candiru file-pattern check; needs "
                        "Python 3.9+ and yara-x==1.21.0; no memory scan")
    p.add_argument("--pattern-path", action="append", default=[], metavar="PATH",
                   help="file or folder for --patterns (repeatable). Limits only "
                        "the pattern check, not the other checks")
    args = p.parse_args(sys.argv[1:] if argv is None else argv)
    if args.pattern_path and not args.patterns:
        p.error("--pattern-path requires --patterns")

    if sys.version_info < (3, 8):
        print("This needs Python 3.8 or newer; this is {}.{}.".format(
            *sys.version_info[:2]), file=sys.stderr)
        _hold(args)
        return 1

    # Refuse a user-typed --iocs/--json path that is not on a local disk.
    # Opening or creating a UNC path or mapped network drive makes Windows open
    # an SMB session to that host - sending this account's network credentials
    # and, for --json, the whole report. Checked before anything is opened and
    # before the scan rather than after it. This entry point is separate from
    # the source CLI, so the guard has to live here too. abspath first, because
    # path_problem refuses relative paths and "--json report.json" is the
    # documented usage.
    for label, value in (("--iocs", args.iocs), ("--json", args.json)):
        if value:
            problem = path_problem(os.path.abspath(value))
            if problem:
                print("error: {} {}: {} - use a path on a local disk".format(
                    label, value, problem), file=sys.stderr)
                _hold(args)
                return 1

    try:
        ioc_set = _load_embedded_iocs(args.iocs)
    except IocError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        _hold(args)
        return 1

    ctx = ScanContext(iocs=ioc_set, quick=args.quick, patterns=args.patterns,
                      pattern_paths=tuple(args.pattern_path))
    started = datetime.datetime.now()
    results = []
    # The whole scan runs inside the no-network guard (see the header).
    with no_network():
        modules = [("browser", run_browser), ("hash", run_hash), ("host", run_host)]
        if args.patterns:
            modules.append(("patterns", run_patterns))
        for name, fn in modules:
            if name == "hash" and args.quick:
                r = ModuleResult("hash")
                r.could_not_run(
                    "file-fingerprints",
                    "skipped by --quick. No file on this machine was "
                    "fingerprinted, so a known sample sitting on disk would "
                    "not have been found. Re-run without --quick to include it")
                results.append(r)
                print("[*] skipping file fingerprints (--quick)", file=sys.stderr)
                continue
            print("[*] running check: {}".format(name), file=sys.stderr)
            started_mod = time.time()
            ctx.partial = None
            try:
                result = fn(ctx)
            except Exception as exc:
                # Match the source CLI: an error after a hit must not erase it.
                partial = ctx.partial
                if isinstance(partial, ModuleResult) and partial.name == name:
                    result = partial
                else:
                    result = ModuleResult(name)
                result.could_not_run(name, "module error: {}".format(exc))
            finally:
                ctx.partial = None
            result.duration_s = time.time() - started_mod
            print("[*]   {} finished in {:.0f}s".format(name, result.duration_s),
                  file=sys.stderr)
            results.append(result)

    document = build_document(ioc_set, results, started)
    print(render_human(document))

    if args.json:
        try:
            write_json(document, args.json)
            print("\n[wrote JSON report to {}]".format(args.json),
                  file=sys.stderr)
        except OSError as exc:
            print("\n[could not write JSON report to {}: {}]".format(
                args.json, exc), file=sys.stderr)

    _hold(args)
    return 2 if document["verdict"]["status"] == "INDICATORS_FOUND" else 0


if __name__ == "__main__":
    raise SystemExit(main())
