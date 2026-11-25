"""
SOC Quarantine Intelligence  -  Reputation Analyzer  (v2.0)
============================================================
Python 3.10+

Install:
    pip install customtkinter requests keyring

Run:
    python soc_quarantine_analyzer.py

API keys can be entered in Settings or supplied as environment variables:
    VIRUSTOTAL_API_KEY   GEMINI_API_KEY   XAI_API_KEY   NVIDIA_API_KEY
Keys are stored only in the operating-system credential store (keyring).
Non-secret preferences are stored in ~/.soc_quarantine_analyzer/settings.json

Triage rules
------------
* 0 malicious + exactly 1 suspicious  -> "Suspicious"
* any malicious, or more than 1 suspicious -> "Malicious"
* 0 detections -> "Safe"  (never a guarantee that an indicator is harmless)
* Any lookup/API/report error -> "Unknown", never "Safe".
"""

from __future__ import annotations

import csv
import ipaddress
import json
import math
import os
import queue
import re
import socket
import threading
import time
import tkinter as tk
import webbrowser
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from urllib.parse import quote, urlparse

import customtkinter as ctk
import requests

try:
    import keyring
except ImportError:  # keyring is optional; keys then live only in memory / env vars
    keyring = None

APP_NAME = "SOC Quarantine Intelligence"
APP_VERSION = "2.0.0"
VT_BASE = "https://www.virustotal.com/api/v3"
CONFIG_DIR = Path(os.getenv("SOC_ANALYZER_HOME") or Path.home() / ".soc_quarantine_analyzer")
KEYRING_SERVICE = "SOCQuarantineAnalyzer"
FRAME_MS = 15  # ~66 fps animation tick

SAMPLE_DATA = """Email 1
Recipient: dawn.wynn@stellarlife.com
Sender Address: teams-meeting@smritycomputer.com
Time Received: 10/23/2026, 5:13:53 AM
Sender IP: 54.240.27.194
Subject Line: Conference
Reputation: Domain is Safe | IP is Safe
Observation:
Quarantine Reason: Antispam high-confidence phish
Detection technologies: Phish: Fingerprint matching | Spam: Fingerprint matching

Email 2
Recipient: john@stellarlife.com
Sender Address: chris.marais@justremotebase.com
Time Received: 10/23/2026, 2:22:40 AM
Sender IP: 98.90.245.176
Subject Line: Could AI take one task off your team's plate?
Reputation: Domain is Safe | IP is Safe
Observation:
Quarantine Reason: Antispam phishing
Detection technologies: Phish: Impersonation brand | Spam: Advanced filter

Email 3
Recipient: dawn.wynn@stellarlife.com
Sender Address: joanna.cox@stonecoveassetadvisors.com
Time Received: 10/22/2026, 10:26:54 PM
Sender IP: 2a01:111:f403:c408::1
Subject Line: Family Office Investment Opportunity
Reputation: Domain is Safe | IP is Safe
Observation:
Quarantine Reason: Antispam phishing
Detection technologies: Phish: General filter | Spam: Advanced filter

Email 4
Recipient: prashant.verma@stellarlife.com
Sender Address: mary@microbiltmarketing.com
Time Received: 10/22/2026, 6:49:40 PM
Sender IP: 143.244.91.60
Subject Line: Streamline Operations with Real-Time Verification
Reputation: Domain is Safe | IP is Safe
Observation:
Quarantine Reason: Antispam
Detection technologies: Spam: Advanced filter
"""

# --------------------------------------------------------------------------- #
#  Design tokens  (light, dark)
# --------------------------------------------------------------------------- #
PALETTE = {
    "bg":            ("#F2F5FB", "#0A0F1E"),
    "sidebar":       ("#FFFFFF", "#0D1427"),
    "surface":       ("#FFFFFF", "#121A30"),
    "surface2":      ("#EEF2F9", "#182242"),
    "surface3":      ("#E1E8F5", "#212E54"),
    "border":        ("#DCE3F0", "#26325C"),
    "text":          ("#0F172A", "#E8EEFF"),
    "muted":         ("#5F6F8F", "#8B9AC0"),
    "accent":        ("#4F6BF6", "#5B7BFA"),
    "accent_hover":  ("#3E56D6", "#7C97FF"),
    "on_accent":     ("#FFFFFF", "#FFFFFF"),
    "on_solid":      ("#FFFFFF", "#07121F"),
    "success":       ("#0E9F6E", "#34D399"),
    "success_hover": ("#0B7F58", "#5CE2B1"),
    "warning":       ("#B7791F", "#FBBF24"),
    "danger":        ("#DC2626", "#F87171"),
    "danger_hover":  ("#B91C1C", "#FCA5A5"),
    "unknown":       ("#64748B", "#94A3B8"),
}
VERDICT_COLOR = {"Malicious": "danger", "Suspicious": "warning", "Safe": "success",
                 "Unknown": "unknown", "Pending": "muted"}
VERDICT_RANK = {"Malicious": 0, "Suspicious": 1, "Unknown": 2, "Pending": 3, "Safe": 4}


def C(name: str):
    """Theme-aware (light, dark) colour tuple for customtkinter widgets."""
    return PALETTE[name]


def pick(color):
    """Resolve a (light, dark) tuple to the colour for the current appearance mode."""
    if isinstance(color, (tuple, list)):
        return color[0 if ctk.get_appearance_mode() == "Light" else 1]
    return color


def R(name: str) -> str:
    """Resolved hex colour for native tk/ttk widgets."""
    return pick(PALETTE[name])


def _rgb(hex_color: str):
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def mix(a: str, b: str, t: float) -> str:
    ra, ga, ba = _rgb(a)
    rb, gb, bb = _rgb(b)
    t = max(0.0, min(1.0, t))
    return "#%02x%02x%02x" % (round(ra + (rb - ra) * t), round(ga + (gb - ga) * t), round(ba + (bb - ba) * t))


# --------------------------------------------------------------------------- #
#  Fonts
# --------------------------------------------------------------------------- #
_FONTS = {"ui": "Segoe UI", "mono": "Consolas"}
_FONT_CACHE: dict = {}


def init_fonts():
    families = set(tkfont.families())
    for key, options in (
        ("ui", ("Segoe UI Variable Text", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter", "Ubuntu", "DejaVu Sans")),
        ("mono", ("Cascadia Mono", "Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Courier New")),
    ):
        _FONTS[key] = next((f for f in options if f in families), options[-1])


def font(size: int = 13, weight: str = "normal", mono: bool = False) -> ctk.CTkFont:
    key = (size, weight, mono)
    if key not in _FONT_CACHE:
        _FONT_CACHE[key] = ctk.CTkFont(family=_FONTS["mono" if mono else "ui"], size=size, weight=weight)
    return _FONT_CACHE[key]


# --------------------------------------------------------------------------- #
#  Animation engine (driven by Tk's event loop, time-based so speed is stable)
# --------------------------------------------------------------------------- #
def ease_out(t: float) -> float:
    return 1 - (1 - t) ** 3


def ease_in_out(t: float) -> float:
    return t * t * (3 - 2 * t)


class _Anim:
    def __init__(self, widget, duration_ms, step, done, ease):
        self.widget, self.duration, self.step, self.done, self.ease = widget, max(1, duration_ms), step, done, ease
        self.cancelled, self.job = False, None
        self.t0 = time.perf_counter()

    def tick(self):
        if self.cancelled:
            return
        try:
            p = min(1.0, (time.perf_counter() - self.t0) * 1000 / self.duration)
            self.step(self.ease(p))
            if p < 1.0:
                self.job = self.widget.after(FRAME_MS, self.tick)
            elif self.done:
                self.done()
        except tk.TclError:  # widget destroyed mid-animation
            self.cancelled = True

    def cancel(self):
        self.cancelled = True
        if self.job:
            try:
                self.widget.after_cancel(self.job)
            except tk.TclError:
                pass


def animate(widget, key: str, duration_ms: int, step, done=None, ease=ease_out):
    """Run `step(progress 0..1)`; a new animation with the same key replaces the old one."""
    registry = widget.__dict__.setdefault("_anims", {})
    previous = registry.pop(key, None)
    if previous:
        previous.cancel()
    anim = _Anim(widget, duration_ms, step, done, ease)
    registry[key] = anim
    anim.tick()
    return anim


# --------------------------------------------------------------------------- #
#  Data model + parsing
# --------------------------------------------------------------------------- #
@dataclass
class Incident:
    email_id: str
    recipient: str = ""
    sender: str = ""
    domain: str = ""
    sender_ip: str = ""
    received: str = ""
    subject: str = ""
    quarantine_reason: str = ""
    detection_technologies: str = ""
    input_reputation: str = ""
    observation: str = ""
    domain_reputation: str = "Pending"
    domain_detections: str = ""
    ip_reputation: str = "Pending"
    ip_detections: str = ""
    company_description: str = "Not checked yet"
    analysis_note: str = ""
    span: tuple = (0, 0)
    row_id: str = ""

    @property
    def verdict(self) -> str:
        reps = (self.domain_reputation, self.ip_reputation)
        if "Pending" in reps:
            return "Pending"
        for level in ("Malicious", "Suspicious"):
            if level in reps:
                return level
        return "Safe" if all(r == "Safe" for r in reps) else "Unknown"

    @property
    def reputation_line(self) -> str:
        return f"Reputation: Domain is {self.domain_reputation} | IP is {self.ip_reputation}"


CSV_FIELDS = ["email_id", "recipient", "sender", "domain", "received", "sender_ip", "subject",
              "quarantine_reason", "detection_technologies", "domain_reputation", "domain_detections",
              "ip_reputation", "ip_detections", "company_description", "analysis_note"]

_HEADING_RE = re.compile(r"(?im)^[ \t]*(?:\*{1,3}[ \t]*)?Email[ \t]+(\d+)[ \t]*(?:\*{1,3})?[ \t]*:?[ \t]*$")
_LABEL_CACHE: dict = {}
_DOMAIN_IN_ADDR = re.compile(r"@([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")


def normalize_text(raw: str) -> str:
    return (raw or "").replace("\r\n", "\n").replace("\r", "\n").replace("\ufeff", "").replace("\u200b", "")


def get_field(block: str, label: str) -> str:
    """Read `Label: value` (also `**Label:** value`) from a record block."""
    if label not in _LABEL_CACHE:
        _LABEL_CACHE[label] = re.compile(
            rf"(?im)^[ \t]*(\*{{0,3}})[ \t]*{re.escape(label)}[ \t]*\**[ \t]*:[ \t]*\**[ \t]*(.*?)[ \t]*$")
    m = _LABEL_CACHE[label].search(block)
    if not m:
        return ""
    value = m.group(2)
    return re.sub(r"\*{2,3}$", "", value).strip() if m.group(1) else value.strip()


def extract_domain(sender: str) -> str:
    found = _DOMAIN_IN_ADDR.findall(sender or "")
    return found[-1].lower().rstrip(".") if found else ""


def is_valid_domain(domain: str) -> bool:
    return bool(domain and _DOMAIN_RE.match(domain))


def ip_state(value: str) -> str:
    """'ok' (public), 'private' (reserved/internal), 'invalid' or 'missing'."""
    if not value:
        return "missing"
    try:
        return "ok" if ipaddress.ip_address(value).is_global else "private"
    except ValueError:
        return "invalid"


def parse_incidents(raw: str) -> tuple[str, list[Incident]]:
    """Return (normalized_text, incidents). Each incident keeps its span in that text."""
    text = normalize_text(raw)
    if not text.strip():
        return text, []
    blocks: list[tuple[str, int, int]] = []
    heads = list(_HEADING_RE.finditer(text))
    if heads:
        for i, m in enumerate(heads):
            blocks.append((m.group(1), m.start(), heads[i + 1].start() if i + 1 < len(heads) else len(text)))
    else:
        recips = list(re.finditer(r"(?im)^[ \t]*Recipient[ \t]*:", text))
        if len(recips) > 1:
            for i, m in enumerate(recips):
                blocks.append((str(i + 1), m.start(), recips[i + 1].start() if i + 1 < len(recips) else len(text)))
        else:
            blocks.append(("1", 0, len(text)))
    incidents: list[Incident] = []
    for number, start, end in blocks:
        block = text[start:end]
        sender, ip = get_field(block, "Sender Address"), get_field(block, "Sender IP")
        if not sender and not ip:
            continue
        incidents.append(Incident(
            email_id=f"Email {number}",
            recipient=get_field(block, "Recipient"),
            sender=sender,
            domain=extract_domain(sender),
            sender_ip=ip.strip("[] ").rstrip(".,;"),
            received=get_field(block, "Time Received"),
            subject=get_field(block, "Subject Line"),
            quarantine_reason=get_field(block, "Quarantine Reason"),
            detection_technologies=get_field(block, "Detection technologies"),
            input_reputation=get_field(block, "Reputation"),
            observation=get_field(block, "Observation"),
            span=(start, end),
            row_id=f"r{len(incidents)}",
        ))
    return text, incidents


def render_updated_text(text: str, incidents: list[Incident]) -> str:
    """Original text preserved exactly; only each record's Reputation line is replaced/added."""
    out, pos = [], 0
    for inc in sorted(incidents, key=lambda i: i.span[0]):
        s, e = inc.span
        block, line = text[s:e], inc.reputation_line
        new_block, n = re.subn(r"(?im)^([ \t]*)Reputation[ \t]*:.*$", lambda m: m.group(1) + line, block, count=1)
        if not n:
            new_block, n = re.subn(r"(?im)^([ \t]*Sender IP[ \t]*:.*)$", lambda m: m.group(1) + "\n" + line, block, count=1)
        if not n:
            stripped = block.rstrip("\n")
            new_block = stripped + "\n" + line + block[len(stripped):]
        out.append(text[pos:s])
        out.append(new_block)
        pos = e
    out.append(text[pos:])
    return "".join(out)


# --------------------------------------------------------------------------- #
#  Secrets, redaction, settings
# --------------------------------------------------------------------------- #
class Redactor:
    """Masks known secrets and common credential patterns in anything that reaches the log."""
    PATTERNS = (
        (re.compile(r"(?i)((?:x-apikey|api[_ -]?key)\s*[:=]\s*)[^\s,;&\"']+"), r"\1[REDACTED]"),
        (re.compile(r"(?i)([?&]key=)[^&\s\"']+"), r"\1[REDACTED]"),
        (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
        (re.compile(r"AIza[0-9A-Za-z_-]{20,}|nvapi-[0-9A-Za-z_-]+|xai-[0-9A-Za-z]{16,}"), "[REDACTED]"),
    )

    def __init__(self):
        self.secrets: set[str] = set()

    def add(self, *values: str):
        self.secrets.update(v.strip() for v in values if v and len(v.strip()) >= 8)

    def __call__(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, "[REDACTED]")
        for pattern, repl in self.PATTERNS:
            text = pattern.sub(repl, text)
        return text


class SecretStore:
    ENV = {"virustotal": "VIRUSTOTAL_API_KEY", "gemini": "GEMINI_API_KEY",
           "grok": "XAI_API_KEY", "nvidia": "NVIDIA_API_KEY"}

    @property
    def available(self) -> bool:
        return keyring is not None

    def load(self, name: str) -> str:
        env = os.getenv(self.ENV.get(name, ""), "")
        if env:
            return env
        if keyring is None:
            return ""
        try:
            return keyring.get_password(KEYRING_SERVICE, name) or ""
        except Exception:
            return ""

    def save(self, name: str, value: str) -> bool:
        if keyring is None:
            return False
        try:
            if value.strip():
                keyring.set_password(KEYRING_SERVICE, name, value.strip())
            else:
                try:
                    keyring.delete_password(KEYRING_SERVICE, name)
                except Exception:
                    pass
            return True
        except Exception:
            return False


class SettingsStore:
    DEFAULTS = {"theme": "dark", "ai_provider": "Auto", "model": "", "use_domainee": True,
                "use_dnsapi": True, "fetch_site": True, "vt_interval": 16.0}

    def __init__(self):
        self.path = CONFIG_DIR / "settings.json"
        self.data = dict(self.DEFAULTS)
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            self.data.update({k: v for k, v in loaded.items() if k in self.DEFAULTS})
        except (OSError, ValueError):
            pass

    def get(self, key):
        return self.data.get(key, self.DEFAULTS.get(key))

    def set(self, **values):
        self.data.update({k: v for k, v in values.items() if k in self.DEFAULTS})

    def save(self) -> bool:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            tmp.replace(self.path)
            return True
        except OSError:
            return False


# --------------------------------------------------------------------------- #
#  Public-domain evidence collection
# --------------------------------------------------------------------------- #
class _PageParser(HTMLParser):
    SKIP = ("script", "style", "noscript", "svg")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self._in_title, self._skip = False, 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in self.SKIP:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = (attrs.get("name") or attrs.get("property") or "").lower()
            val = (attrs.get("content") or "").strip()
            if key and val:
                self.meta[key] = val

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        value = " ".join(data.split())
        if not value:
            return
        if self._in_title:
            self.title_parts.append(value)
        if not self._skip:
            self.text_parts.append(value)


def is_public_host(host: str | None) -> bool:
    """True only when every address the host resolves to is globally routable (SSRF guard)."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    try:
        return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)
    except ValueError:
        return False


class EvidenceCollector:
    """Gathers public website text, search snippets and free-API data about a domain."""
    HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SOCDomainResearch/2.0)"}
    TIMEOUT = (4, 8)

    def __init__(self, session, log, *, domainee=True, dnsapi=True, fetch_site=True):
        self.session, self.log = session, log
        self.domainee, self.dnsapi, self.fetch_site = domainee, dnsapi, fetch_site

    # -- website --------------------------------------------------------------
    def _fetch_page(self, url: str, limit: int = 350_000):
        self.log("FREE API / WEB", "Website request", f"GET {url}\nTimeout: {self.TIMEOUT}")
        with self.session.get(url, headers=self.HEADERS, timeout=self.TIMEOUT, allow_redirects=True, stream=True) as r:
            ctype = r.headers.get("Content-Type", "")
            buf = bytearray()
            if "html" in ctype.lower():
                for chunk in r.iter_content(16384):
                    buf.extend(chunk)
                    if len(buf) >= limit:
                        break
            text = bytes(buf).decode(r.encoding or "utf-8", "replace")
            self.log("FREE API / WEB", "Website response",
                     f"HTTP {r.status_code}\nFinal URL: {r.url}\nContent-Type: {ctype}\nBody preview:\n{text[:2500]}")
            return r.ok, r.url, ctype, text

    def _site(self, domain: str) -> str:
        if not self.fetch_site:
            return ""
        if not is_public_host(domain):
            self.log("FREE API / WEB", "Website skipped", f"{domain} does not resolve to a public address.")
            return ""
        for url in (f"https://{domain}", f"https://www.{domain}", f"http://{domain}"):
            try:
                ok, final, ctype, text = self._fetch_page(url)
            except requests.RequestException:
                continue
            if not ok or "html" not in ctype.lower() or not is_public_host(urlparse(final).hostname):
                continue
            if "account suspended" in text[:50000].lower() or "suspendedpage.cgi" in final.lower():
                return (f"Website status: The domain resolves, but the hosting provider shows an "
                        f"account-suspended page ({final}). It does not identify the company's services.")
            parser = _PageParser()
            parser.feed(text)
            meta, body = parser.meta, " ".join(parser.text_parts)
            title = " ".join(parser.title_parts).strip()
            desc = meta.get("description") or meta.get("og:description") or ""
            lines = (f"Website URL: {final}",
                     f"Page title: {title}" if title else "",
                     f"Site name: {meta['og:site_name']}" if meta.get("og:site_name") else "",
                     f"Meta description: {desc}" if desc else "",
                     f"Visible website text: {body[:4500]}" if body else "")
            return "\n".join(x for x in lines if x)
        return ""

    def _search(self, domain: str) -> str:
        for query in (f'"{domain}" company services', f"site:{domain} about services products"):
            try:
                url = "https://html.duckduckgo.com/html/?q=" + quote(query)
                self.log("FREE API / WEB", "Public search request", f"GET {url}")
                r = self.session.get(url, headers=self.HEADERS, timeout=self.TIMEOUT)
                self.log("FREE API / WEB", "Public search response", f"HTTP {r.status_code}\nBody preview:\n{r.text[:2500]}")
                if r.ok:
                    parser = _PageParser()
                    parser.feed(r.text[:220000])
                    text = " ".join(parser.text_parts)
                    if text:
                        return f"Public search results for {domain}: {text[:2800]}"
            except requests.RequestException:
                continue
        return ""

    # -- keyless JSON APIs ------------------------------------------------------
    def _json_api(self, name, category, endpoints, limit, unwrap):
        out = []
        for label, url, params in endpoints:
            try:
                self.log(category, f"{label} request", f"GET {url}\nParams: {json.dumps(params)}\nTimeout: {self.TIMEOUT}")
                r = self.session.get(url, params=params, headers=self.HEADERS, timeout=self.TIMEOUT)
                self.log(category, f"{label} response", f"HTTP {r.status_code}\nURL: {r.url}\nBody:\n{r.text[:5000]}")
                if r.status_code == 429:
                    out.append(f"{name} {label}: rate limited (HTTP 429); skipped remaining {name} lookups.")
                    break
                if not r.ok:
                    out.append(f"{name} {label}: unavailable (HTTP {r.status_code}).")
                    continue
                payload = r.json()
                if unwrap:
                    if payload.get("ok") is False:
                        err = payload.get("error") or {}
                        out.append(f"{name} {label}: {err.get('code', 'API error')} - {err.get('message', 'lookup failed')}")
                        continue
                    payload = payload.get("data", payload)
                out.append(f"{name} {label} API evidence: {json.dumps(payload, ensure_ascii=False, default=str)[:limit]}")
            except (requests.RequestException, ValueError, TypeError) as exc:
                out.append(f"{name} {label}: lookup failed ({type(exc).__name__}).")
        return out

    def collect(self, domain: str) -> str:
        parts = []
        site = self._site(domain)
        if site:
            parts.append(site)
        if len(site) < 500:  # thin or unavailable homepage -> public-search fallback
            found = self._search(domain)
            if found:
                parts.append(found)
        if self.domainee:
            base = "https://api.domainee.dev/v1/tools"
            parts += self._json_api("Domainee", "FREE API / DOMAINEE", [
                ("DNS records", f"{base}/dns-record-lookup", {"domain": domain}),
                ("SSL certificate", f"{base}/ssl-check", {"host": domain}),
                ("Website status", f"{base}/website-status-checker", {"url": f"https://{domain}"}),
            ], 1600, True)
        if self.dnsapi:
            base = "https://dnsapi.ai/v1"
            parts += self._json_api("DNSAPI.ai", "FREE API / DNSAPI.AI", [
                ("Full domain lookup", f"{base}/lookup", {"q": domain, "output": "json"}),
                ("Threat intelligence", f"{base}/threat", {"q": domain, "output": "json"}),
                ("WHOIS registration", f"{base}/whois", {"q": domain, "output": "json"}),
            ], 1800, False)
        return "\n\n".join(parts)[:14000] or "No accessible public website text, search snippets, Domainee, or DNSAPI.ai data were retrieved."


def normalize_company_answer(raw, evidence: str) -> str:
    """Accept only a strict `Company:` / `Offers:` pair; reject reasoning or unusable output."""
    if not isinstance(raw, str):
        return ""
    cleaned = raw.replace("```text", "").replace("```", "").replace("\\r\\n", "\n").replace("\\n", "\n").strip()
    lines = [ln.strip().lstrip("-* ").strip() for ln in cleaned.splitlines() if ln.strip()]

    def grab(label):
        return next((re.sub(rf"^{label}\s*:\s*", "", ln, flags=re.I).strip()
                     for ln in lines if re.match(rf"^{label}\s*:", ln, re.I)), "")

    company, offers = grab("company"), grab("offers")
    bad = ("the user wants", "i need to", "i must", "plan:", "step 1", "search for", "constraints:", "i should")
    if not company or not offers or any(x in cleaned.lower() for x in bad):
        return ""
    if len(company) > 140 or len(offers) > 500:
        return ""
    if company.lower() in ("not identified", "unknown", "n/a", "could not confirm"):
        return "Company: Not identified\nOffers: Could not confirm"
    if evidence.startswith("No accessible public website") and offers.lower() not in ("could not confirm", "unknown"):
        return ""
    return f"Company: {company}\nOffers: {offers}"


# --------------------------------------------------------------------------- #
#  VirusTotal
# --------------------------------------------------------------------------- #
def classify_vt_stats(stats: dict) -> tuple[str, str]:
    """Apply the SOC triage rule to VirusTotal `last_analysis_stats`."""
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
    detail = f"{malicious} malicious, {suspicious} suspicious / {total} total"
    if malicious == 0 and suspicious == 1:
        return "Suspicious", detail
    if malicious > 0 or suspicious > 1:
        return "Malicious", detail
    return "Safe", f"0 malicious/suspicious / {total} total"


class VirusTotalClient:
    def __init__(self, api_key: str, log, stop: threading.Event, min_interval: float = 16.0):
        self.key, self.log, self.stop = api_key.strip(), log, stop
        self.min_interval = max(0.0, min_interval)
        self.session = requests.Session()
        self.lock = threading.Lock()
        self.last_call = 0.0

    def _pace(self):
        wait = self.min_interval - (time.monotonic() - self.last_call)
        if wait > 0:
            self.stop.wait(wait)  # interruptible, unlike time.sleep

    def lookup(self, indicator: str, kind: str) -> tuple[str, str]:
        if not self.key:
            return "Unknown", "API key not configured"
        url = f"{VT_BASE}/{'domains' if kind == 'domain' else 'ip_addresses'}/{quote(indicator, safe='')}"
        self.log("VIRUSTOTAL", "Request", f"GET {url}\nIndicator type: {kind}\nIndicator: {indicator}\nAuth header: redacted")
        response = None
        for attempt in range(2):
            with self.lock:
                self._pace()
                if self.stop.is_set():
                    return "Unknown", "Cancelled"
                try:
                    response = self.session.get(url, headers={"x-apikey": self.key}, timeout=25)
                except requests.RequestException as exc:
                    self.last_call = time.monotonic()
                    return "Unknown", f"Request error: {type(exc).__name__}"
                self.last_call = time.monotonic()
            self.log("VIRUSTOTAL", "Response", f"HTTP {response.status_code}\nURL: {response.url}\nBody:\n{response.text[:7000]}")
            if response.status_code == 429 and attempt == 0:
                self.log("VIRUSTOTAL", "Rate limited", "HTTP 429 - waiting 45 s before one retry.")
                self.stop.wait(45)
                continue
            break
        if response.status_code == 404:
            return "Unknown", "No VirusTotal report found"
        if response.status_code == 429:
            return "Unknown", "VirusTotal rate limit reached; retry later"
        if response.status_code in (401, 403):
            return "Unknown", "VirusTotal API key rejected or access unavailable"
        if not response.ok:
            return "Unknown", f"VirusTotal HTTP {response.status_code}"
        try:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            return classify_vt_stats(stats)
        except (ValueError, TypeError, AttributeError):
            return "Unknown", "Unexpected VirusTotal response format"


# --------------------------------------------------------------------------- #
#  AI company research (Gemini / Grok / NVIDIA, with automatic fallback)
# --------------------------------------------------------------------------- #
class AIResearcher:
    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models"
    GROK_MODELS, GROK_CHAT = "https://api.x.ai/v1/models", "https://api.x.ai/v1/chat/completions"
    NVIDIA_MODELS, NVIDIA_CHAT = "https://integrate.api.nvidia.com/v1/models", "https://integrate.api.nvidia.com/v1/chat/completions"
    RETRY_STATUS = (408, 425, 500, 502, 503, 504)
    GEMINI_RPM = {"gemini-2.5-flash": 5, "gemini-2.5-flash-lite": 10, "gemini-3-flash-preview": 5,
                  "gemini-3.1-flash-lite": 15, "gemini-3.5-flash-lite": 15, "gemini-3.8-flash": 5}
    SYSTEM_PROMPT = ("Identify the actual company behind the supplied domain and summarize its real products/services "
                     "using reliable public information. Do not guess from the domain name. If unknown, say so. "
                     "Return exactly two concise lines: Company: ... and Offers: ...")

    def __init__(self, provider_keys: dict, provider: str, model: str, collector: EvidenceCollector, log, stop):
        self.keys = {k: (v or "").strip() for k, v in provider_keys.items()}
        self.provider, self.model = provider, model.strip()
        self.collector, self.log, self.stop = collector, log, stop
        self.session = collector.session
        self._models_cache: dict = {}
        self._gemini_lock, self._gemini_last = threading.Lock(), 0.0

    # -- model discovery (cached per run) --------------------------------------
    def discover_models(self, provider: str, key: str) -> list[str]:
        if provider in self._models_cache:
            return list(self._models_cache[provider])
        models: list[str] = []
        try:
            if provider == "Gemini":
                self.log("AI MODELS", "Gemini model-list request", f"GET {self.GEMINI_URL}\nAPI key: redacted")
                r = self.session.get(self.GEMINI_URL, params={"key": key}, timeout=(5, 12))
                self.log("AI MODELS", "Gemini model-list response", f"HTTP {r.status_code}\nBody:\n{r.text[:6000]}")
                if r.ok:
                    excluded = ("embedding", "embed", "aqa", "image", "audio", "tts", "transcribe", "veo", "robotics",
                                "deep-research", "lyria", "antigravity", "computer-use", "gemma-vision")
                    for item in r.json().get("models", []):
                        name = item.get("name", "").replace("models/", "")
                        if name and "generateContent" in item.get("supportedGenerationMethods", []) \
                                and not any(x in name.lower() for x in excluded):
                            models.append(name)
                    preferred = ("gemini-3.5-flash-lite", "gemini-3.8-flash")
                    models.sort(key=lambda m: (preferred.index(m) if m in preferred else len(preferred), m))
            else:
                url = self.GROK_MODELS if provider == "Grok" else self.NVIDIA_MODELS
                self.log("AI MODELS", f"{provider} model-list request", f"GET {url}\nAuthorization: Bearer token redacted")
                r = self.session.get(url, headers={"Authorization": f"Bearer {key}"}, timeout=(5, 12))
                self.log("AI MODELS", f"{provider} model-list response", f"HTTP {r.status_code}\nBody:\n{r.text[:6000]}")
                if r.ok:
                    models = [x["id"] for x in r.json().get("data", []) if x.get("id")]
                    if provider == "NVIDIA":
                        models = [m for m in models if any(k in m.lower() for k in ("instruct", "chat", "nemotron", "llama", "qwen", "mistral"))
                                  and not any(k in m.lower() for k in ("embed", "rerank", "guard", "reward", "calibration", "audio", "tts"))]
        except (requests.RequestException, ValueError, TypeError, KeyError):
            models = []
        if models:
            self._models_cache[provider] = models
        return list(models)

    # -- transport ----------------------------------------------------------------
    def _send(self, label: str, url: str, *, params=None, headers=None, payload=None):
        """POST with retry/backoff. Returns (response | None, error_message)."""
        r = None
        for attempt in range(3):
            if self.stop.is_set():
                return None, "Cancelled"
            try:
                r = self.session.post(url, params=params, headers=headers, json=payload, timeout=(8, 25))
            except requests.RequestException as exc:
                if attempt < 2:
                    self.stop.wait(1.5 * (attempt + 1))
                    continue
                return None, f"Network/timeout error after retries: {type(exc).__name__}"
            self.log("AI MODEL REQUEST/RESPONSE", f"{label} attempt {attempt + 1} response", f"HTTP {r.status_code}\nBody:\n{r.text[:10000]}")
            if r.status_code not in self.RETRY_STATUS or attempt == 2:
                break
            try:
                delay = min(12.0, max(1.0, float(r.headers.get("Retry-After", "")))) if r.headers.get("Retry-After") else 1.5 * (attempt + 1)
            except ValueError:
                delay = 1.5 * (attempt + 1)
            self.stop.wait(delay)
        if r is not None and r.ok:
            return r, ""
        detail = ""
        try:
            detail = r.json().get("error", {}).get("message", "")
        except (ValueError, AttributeError):
            pass
        return None, f"HTTP {getattr(r, 'status_code', '?')}: {detail or getattr(r, 'text', '')[:180]}"

    def _ask_gemini(self, model: str, key: str, prompt: str) -> tuple[bool, str]:
        with self._gemini_lock:  # stay under the free-tier requests-per-minute limit
            wait = 60.0 / max(1, self.GEMINI_RPM.get(model, 5)) - (time.monotonic() - self._gemini_last)
            if wait > 0:
                self.stop.wait(wait)
            self._gemini_last = time.monotonic()
        # Thinking models spend output tokens on reasoning, so keep generous headroom.
        payload = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1024}}
        url = f"{self.GEMINI_URL}/{quote(model, safe='')}:generateContent"
        self.log("AI MODEL REQUEST/RESPONSE", f"Gemini request: {model}", f"POST {url}\nQuery API key: redacted\nJSON request body:\n{json.dumps(payload, ensure_ascii=False, indent=2)[:14000]}")
        r, err = self._send(f"Gemini/{model}", url, params={"key": key}, payload=payload)
        if r is None:
            return False, err
        try:
            parts = ((r.json().get("candidates") or [{}])[0].get("content") or {}).get("parts") or []
            answer = "\n".join(str(p.get("text", "")) for p in parts if isinstance(p, dict) and p.get("text")).strip()
            return (True, answer) if answer else (False, "Gemini returned no text; trying another model/provider.")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            return False, f"Invalid Gemini response: {exc}"

    def _ask_openai_compatible(self, provider: str, model: str, key: str, prompt: str) -> tuple[bool, str]:
        url = self.GROK_CHAT if provider == "Grok" else self.NVIDIA_CHAT
        payload = {"model": model, "temperature": 0.1, "max_tokens": 600,
                   "messages": [{"role": "system", "content": self.SYSTEM_PROMPT}, {"role": "user", "content": prompt}]}
        self.log("AI MODEL REQUEST/RESPONSE", f"{provider} request: {model}", f"POST {url}\nAuthorization: Bearer token redacted\nJSON request body:\n{json.dumps(payload, ensure_ascii=False, indent=2)[:14000]}")
        r, err = self._send(f"{provider}/{model}", url, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"}, payload=payload)
        if r is None:
            return False, err
        try:
            content = ((r.json().get("choices") or [{}])[0].get("message") or {}).get("content")
            if isinstance(content, list):  # some hosts return a list of text blocks
                content = "\n".join(str(p.get("text", "")) for p in content if isinstance(p, dict) and p.get("text"))
            if isinstance(content, str) and content.strip():
                return True, content.strip()
            return False, "Provider returned an empty response; trying another model/provider."
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            return False, f"Invalid provider response: {exc}"

    # -- public API -----------------------------------------------------------------
    def describe_domain(self, domain: str) -> str:
        self.log("AI MODEL REQUEST/RESPONSE", "Research started", f"Domain: {domain}")
        evidence = self.collector.collect(domain)
        self.log("AI MODEL REQUEST/RESPONSE", "Combined public evidence", evidence)
        prompt = ("Identify the organization operating this domain and its real business/products/services using ONLY "
                  "the evidence below. Do not guess from the domain name. Do not output reasoning, research plans, "
                  "security verdicts, WHOIS discussion, markdown fences, or generic verification steps. Do not invent facts. "
                  "Return exactly two lines and nothing else:\n"
                  "Company: [name or Not identified]\nOffers: [evidence-supported services/products or Could not confirm]\n\n"
                  f"DOMAIN: {domain}\nPUBLIC EVIDENCE:\n{evidence}")
        self.log("AI MODEL REQUEST/RESPONSE", "Final AI prompt", prompt[:16000])
        providers = [p for p in ("Gemini", "Grok", "NVIDIA") if self.keys.get(p)]
        if self.provider in providers:
            providers.remove(self.provider)
            providers.insert(0, self.provider)
        if not providers:
            return "Company: Not identified\nOffers: Configure a Gemini, Grok, or NVIDIA API key in Settings."
        for provider in providers:
            key = self.keys[provider]
            models = self.discover_models(provider, key)
            if self.model and provider == providers[0] and self.model in models:
                models.remove(self.model)
                models.insert(0, self.model)
            for model in models[:4]:
                if self.stop.is_set():
                    return "Company: Not identified\nOffers: Cancelled by user."
                try:
                    ok, result = (self._ask_gemini(model, key, prompt) if provider == "Gemini"
                                  else self._ask_openai_compatible(provider, model, key, prompt))
                except Exception as exc:  # one provider must never kill the batch
                    self.log("AI MODEL REQUEST/RESPONSE", f"{provider}/{model} error", f"{type(exc).__name__}: {exc}")
                    continue
                if ok:
                    answer = normalize_company_answer(result, evidence)
                    self.log("AI MODEL REQUEST/RESPONSE", f"{provider}/{model} normalized response",
                             answer or "(rejected: output format or evidence validation failed)")
                    if answer:
                        return f"{answer}\n\nSource provider/model: {provider} / {model}"
        return ("Company: Not identified\nOffers: Could not confirm from retrieved public evidence.\n"
                "Research status: All configured model attempts failed or returned unusable output.")


# --------------------------------------------------------------------------- #
#  Reusable animated widgets
# --------------------------------------------------------------------------- #
def card(master, **kw) -> ctk.CTkFrame:
    kw.setdefault("corner_radius", 16)
    return ctk.CTkFrame(master, fg_color=C("surface"), border_width=1, border_color=C("border"), **kw)


def label(master, text="", size=13, weight="normal", color="text", **kw) -> ctk.CTkLabel:
    return ctk.CTkLabel(master, text=text, font=font(size, weight), text_color=C(color), **kw)


def textbox(master, mono=True, size=12, **kw) -> ctk.CTkTextbox:
    return ctk.CTkTextbox(master, font=font(size, mono=mono), fg_color=C("surface2"), text_color=C("text"),
                          border_width=1, border_color=C("border"), corner_radius=12, wrap=kw.pop("wrap", "word"),
                          scrollbar_button_color=C("surface3"), scrollbar_button_hover_color=C("muted"), **kw)


class AButton(ctk.CTkButton):
    """Button with a smooth colour tween on hover and a disabled look that follows the theme."""
    VARIANTS = {  # base, hover, text, border
        "primary":   ("accent", "accent_hover", "on_accent", None),
        "success":   ("success", "success_hover", "on_solid", None),
        "danger":    ("danger", "danger_hover", "on_solid", None),
        "secondary": ("surface2", "surface3", "text", "border"),
        "ghost":     ("surface", "surface2", "muted", None),
        "nav":       ("sidebar", "surface2", "muted", None),
    }

    def __init__(self, master, text="", variant="secondary", icon="", width=120, height=38, anchor="center", **kw):
        base, hover, fg, border = self.VARIANTS[variant]
        self._a_cols = [C(base), C(hover)]
        self._a_fg, self._a_t, self._a_enabled = C(fg), 0.0, True
        self._a_variant = variant
        super().__init__(master, text=f"{icon}  {text}".strip() if icon else text, width=width, height=height,
                         fg_color=C(base), hover=False, text_color=C(fg), text_color_disabled=C("muted"),
                         corner_radius=10, border_width=1 if border else 0, border_color=C(border or base),
                         font=font(13, "bold"), anchor=anchor, **kw)
        for widget in (self._canvas, self._text_label):
            widget.bind("<Enter>", lambda e: self._go(1.0), add="+")
            widget.bind("<Leave>", lambda e: self._go(0.0), add="+")

    def _go(self, target: float):
        if not self._a_enabled:
            target = 0.0
        start = self._a_t
        if start == target:
            return

        def step(p):
            self._a_t = start + (target - start) * p
            self.configure(fg_color=mix(pick(self._a_cols[0]), pick(self._a_cols[1]), self._a_t))

        animate(self, "hover", 160, step, lambda: self.configure(fg_color=self._a_cols[1 if target else 0]))

    def set_colors(self, base: str, hover: str, text: str):
        """Used by nav buttons to switch active/inactive look with a colour tween."""
        old = pick(self.cget("fg_color"))
        self._a_cols, self._a_fg, self._a_t = [C(base), C(hover)], C(text), 0.0
        self.configure(text_color=self._a_fg)
        new = pick(self._a_cols[0])
        animate(self, "hover", 240, lambda p: self.configure(fg_color=mix(old, new, p)),
                lambda: self.configure(fg_color=self._a_cols[0]))

    def set_enabled(self, enabled: bool, text: str | None = None):
        self._a_enabled = enabled
        if text is not None:
            self.configure(text=text)
        if enabled:
            self.configure(state="normal", text_color=self._a_fg, fg_color=self._a_cols[0])
        else:
            self._a_t = 0.0
            self.configure(state="disabled", fg_color=C("surface3"))


class SmoothProgress(ctk.CTkProgressBar):
    def __init__(self, master, **kw):
        super().__init__(master, height=8, corner_radius=8, fg_color=C("surface3"), progress_color=C("accent"), **kw)
        self._value = 0.0
        super().set(0)

    def glide(self, target: float, ms: int = 420):
        start, target = self._value, max(0.0, min(1.0, target))

        def step(p):
            self._value = start + (target - start) * p
            super(SmoothProgress, self).set(self._value)

        animate(self, "glide", ms, step)

    def reset(self):
        self._value = 0.0
        super().set(0)


class KpiCard(ctk.CTkFrame):
    def __init__(self, master, title: str, color: str):
        super().__init__(master, corner_radius=16, fg_color=C("surface"), border_width=1, border_color=C("border"))
        self.color, self.shown = color, 0
        ctk.CTkFrame(self, height=3, width=34, corner_radius=3, fg_color=C(color)).grid(row=0, column=0, sticky="w", padx=18, pady=(14, 0))
        label(self, title.upper(), 11, "bold", "muted").grid(row=1, column=0, sticky="w", padx=18, pady=(8, 0))
        self.value = label(self, "0", 30, "bold", color)
        self.value.grid(row=2, column=0, sticky="w", padx=18)
        self.sub = label(self, " ", 11, "normal", "muted")
        self.sub.grid(row=3, column=0, sticky="w", padx=18, pady=(0, 14))

    def set(self, value: int, sub: str = " "):
        self.sub.configure(text=sub)
        start = self.shown
        if start == value:
            return
        self.shown = value
        animate(self, "count", 480, lambda p: self.value.configure(text=str(round(start + (value - start) * p))))


class StatusPill(ctk.CTkFrame):
    """Idle / working (pulsing) / success / error indicator."""
    STATES = {"idle": "muted", "working": "accent", "success": "success", "error": "danger", "warning": "warning"}

    def __init__(self, master):
        super().__init__(master, corner_radius=15, height=30, fg_color=C("surface2"), border_width=1, border_color=C("border"))
        self.dot = ctk.CTkLabel(self, text="●", font=font(12), text_color=C("muted"), width=14)
        self.dot.grid(row=0, column=0, padx=(12, 4), pady=4)
        self.text = label(self, "Ready", 12, "normal", "muted")
        self.text.grid(row=0, column=1, padx=(0, 14), pady=4)
        self.state, self._job = "idle", None

    def set(self, state: str, text: str):
        self.text.configure(text=text if len(text) <= 70 else text[:67] + "…")
        if state == self.state and state != "working":
            return
        self.state = state
        color = self.STATES[state]
        self.text.configure(text_color=C("text") if state != "idle" else C("muted"))
        if state == "working":
            self._pulse(time.perf_counter())
        else:
            self.dot.configure(text_color=C(color))

    def _pulse(self, t0):
        if self.state != "working":
            return
        try:
            k = (math.sin((time.perf_counter() - t0) * 5) + 1) / 2
            self.dot.configure(text_color=mix(pick(C("accent")), pick(C("surface2")), 0.65 * k))
            self.after(40, lambda: self._pulse(t0))
        except tk.TclError:
            pass


class ResultTable(ctk.CTkFrame):
    """Sortable, theme-aware Treeview with animated row highlight and VirusTotal links."""
    COLUMNS = ("email", "indicator", "verdict", "detections", "report")

    def __init__(self, master, indicator_title: str, vt_path: str, on_notify):
        super().__init__(master, fg_color="transparent")
        self.vt_path, self.notify = vt_path, on_notify
        self.urls: dict[str, str] = {}
        self.titles = {"email": "Email", "indicator": indicator_title, "verdict": "Verdict",
                       "detections": "VirusTotal detections", "report": "Report"}
        self._sort_state: tuple[str, bool] | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(self, columns=self.COLUMNS, show="headings", selectmode="browse", style="SOC.Treeview")
        for col, width, stretch in (("email", 76, False), ("indicator", 190, True), ("verdict", 108, False),
                                    ("detections", 190, True), ("report", 112, False)):
            self.tree.heading(col, text=self.titles[col], anchor="w", command=lambda c=col: self.sort(c))
            self.tree.column(col, width=width, minwidth=70, anchor="w", stretch=stretch)
        ys = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview, style="SOC.Vertical.TScrollbar")
        xs = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview, style="SOC.Horizontal.TScrollbar")
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy indicator", command=self._copy_indicator)
        self.menu.add_command(label="Open in VirusTotal", command=self._open_selected)
        self.tree.bind("<Double-1>", lambda e: self._open_selected())
        self.tree.bind("<Button-1>", self._on_click, add="+")
        self.tree.bind("<Motion>", self._on_motion)
        self.tree.bind("<Button-3>", self._on_context)
        self.tree.bind("<Button-2>", self._on_context)
        self.restyle()

    # -- theming ------------------------------------------------------------------
    def restyle(self):
        self.menu.configure(bg=R("surface"), fg=R("text"), activebackground=R("accent"), activeforeground="#FFFFFF",
                            bd=0, relief="flat")
        self.tree.tag_configure("odd", background=R("surface"))
        self.tree.tag_configure("even", background=R("surface2"))
        for verdict, color in VERDICT_COLOR.items():
            self.tree.tag_configure(verdict.lower(), foreground=R(color))

    # -- data -----------------------------------------------------------------------
    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.urls.clear()
        self._sort_state = None
        for col, title in self.titles.items():
            self.tree.heading(col, text=title)

    def upsert(self, iid: str, email: str, indicator: str, verdict: str, detections: str, flash: bool = True):
        url = f"https://www.virustotal.com/gui/{self.vt_path}/{quote(indicator, safe='')}" if indicator else ""
        self.urls[iid] = url
        values = (email, indicator or "—", f"●  {verdict}", detections, "VirusTotal  ↗" if url else "Unavailable")
        existing = self.tree.exists(iid)
        parity = "odd" if (self.tree.index(iid) if existing else len(self.tree.get_children())) % 2 == 0 else "even"
        tags = (parity, verdict.lower())
        if existing:
            self.tree.item(iid, values=values, tags=tags)
        else:
            self.tree.insert("", "end", iid=iid, values=values, tags=tags)
        if flash and verdict != "Pending":
            self._flash(iid, parity, verdict)

    def _flash(self, iid: str, parity: str, verdict: str):
        tag = f"fl_{iid}"
        base, glow = R("surface" if parity == "odd" else "surface2"), R(VERDICT_COLOR[verdict])
        self.tree.tag_configure(tag, background=mix(base, glow, 0.30))
        self.tree.item(iid, tags=(parity, verdict.lower(), tag))

        def step(p):
            self.tree.tag_configure(tag, background=mix(mix(base, glow, 0.30), base, p))

        def done():
            if self.tree.exists(iid):
                self.tree.item(iid, tags=(parity, verdict.lower()))

        animate(self.tree, tag, 900, step, done, ease_in_out)

    def sort(self, col: str):
        reverse = self._sort_state == (col, False)
        self._sort_state = (col, reverse)

        def key(iid):
            value = str(self.tree.set(iid, col))
            if col == "verdict":
                return VERDICT_RANK.get(value.replace("●", "").strip(), 9)
            if col == "email":
                digits = re.sub(r"\D", "", value)
                return int(digits) if digits else 0
            return value.lower()

        for index, iid in enumerate(sorted(self.tree.get_children(), key=key, reverse=reverse)):
            self.tree.move(iid, "", index)
            tags = [t for t in self.tree.item(iid, "tags") if t not in ("odd", "even")]
            self.tree.item(iid, tags=("odd" if index % 2 == 0 else "even", *tags))
        for name, title in self.titles.items():
            self.tree.heading(name, text=title + (("  ▼" if reverse else "  ▲") if name == col else ""))

    # -- interaction ---------------------------------------------------------------
    def _on_click(self, event):
        if self.tree.identify_region(event.x, event.y) == "cell" and self.tree.identify_column(event.x) == f"#{len(self.COLUMNS)}":
            self._open(self.tree.identify_row(event.y))

    def _on_motion(self, event):
        over_link = self.tree.identify_region(event.x, event.y) == "cell" and self.tree.identify_column(event.x) == f"#{len(self.COLUMNS)}"
        self.tree.configure(cursor="hand2" if over_link else "")

    def _on_context(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    def _open(self, iid: str):
        url = self.urls.get(iid, "")
        if url.startswith("https://www.virustotal.com/"):
            webbrowser.open(url)

    def _open_selected(self):
        sel = self.tree.selection()
        if sel:
            self._open(sel[0])

    def _copy_indicator(self):
        sel = self.tree.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.tree.set(sel[0], "indicator"))
            self.notify("Indicator copied", "success")


class Toast(ctk.CTkFrame):
    """Slide-in notification stacked at the bottom-right corner of the window."""
    ACCENT = {"info": "accent", "success": "success", "warning": "warning", "error": "danger"}

    def __init__(self, host, text: str, kind: str, on_close, ms: int = 3400):
        super().__init__(host, corner_radius=12, fg_color=C("surface"), border_width=1, border_color=C("border"))
        self.on_close, self.slide = on_close, 0.0
        ctk.CTkFrame(self, width=5, height=10, corner_radius=3, fg_color=C(self.ACCENT.get(kind, "accent"))).grid(row=0, column=0, sticky="ns", padx=(8, 0), pady=10)
        label(self, text, 13, "normal", "text", wraplength=300, justify="left").grid(row=0, column=1, padx=(12, 18), pady=12)
        self.after(ms, self.dismiss)

    def dismiss(self):
        start = self.slide
        def step(p):
            self.slide = start + (1 - start) * p
            self.on_close(self, layout_only=True)
        animate(self, "slide_out", 220, step, lambda: self.on_close(self), ease_in_out)


# --------------------------------------------------------------------------- #
#  Application
# --------------------------------------------------------------------------- #
NAV = [
    ("dashboard", "Dashboard", "▦", "Reputation analysis for quarantined email indicators"),
    ("research", "AI Research", "✦", "Identify who operates each sender domain"),
    ("logs", "Logs", "☰", "Request / response inspector — secrets are redacted"),
    ("settings", "Settings", "⚙", "Credentials, providers and appearance"),
]
KPI_DEFS = [("total", "Analyzed", "accent"), ("Malicious", "Malicious", "danger"), ("Suspicious", "Suspicious", "warning"),
            ("Safe", "Safe", "success"), ("Unknown", "Unknown", "unknown")]
LOG_CATEGORIES = ["All logs", "VIRUSTOTAL", "FREE API / WEB", "FREE API / DOMAINEE", "FREE API / DNSAPI.AI",
                  "AI MODELS", "AI MODEL REQUEST/RESPONSE"]
LOG_COLORS = ["accent", "warning", "success", "danger", "accent", "success", "warning"]
LOG_STORE_MAX, LOG_RENDER_MAX = 1500, 400
AI_HINT = "Click “Extract from input” to list unique sender domains here. You can also add or remove domains by hand (one per line)."
AI_RESULT_HINT = "AI research results appear here. They stay editable, so you can refine the notes before using them in a case."


def fmt_eta(seconds: float) -> str:
    seconds = int(max(0, seconds))
    return f"{seconds // 60}m {seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


class SecretEntry(ctk.CTkFrame):
    def __init__(self, master, placeholder: str):
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.entry = ctk.CTkEntry(self, placeholder_text=placeholder, show="•", height=38, corner_radius=10,
                                  fg_color=C("surface2"), border_color=C("border"), text_color=C("text"),
                                  placeholder_text_color=C("muted"), font=font(13))
        self.entry.grid(row=0, column=0, sticky="ew")
        self.toggle = AButton(self, "Show", "secondary", width=64, height=38, command=self._toggle)
        self.toggle.grid(row=0, column=1, padx=(8, 0))

    def _toggle(self):
        hidden = self.entry.cget("show") == "•"
        self.entry.configure(show="" if hidden else "•")
        self.toggle.configure(text="Hide" if hidden else "Show")

    def get(self) -> str:
        return self.entry.get().strip()

    def set(self, value: str):
        self.entry.delete(0, "end")
        if value:
            self.entry.insert(0, value)


class App(ctk.CTk):
    def __init__(self, settings: SettingsStore):
        ctk.set_appearance_mode(settings.get("theme"))
        ctk.set_default_color_theme("blue")
        super().__init__()
        init_fonts()
        self.settings, self.secrets, self.redactor = settings, SecretStore(), Redactor()
        self.events: queue.Queue = queue.Queue()
        self.records: list[Incident] = []
        self.original_text = ""
        self.verbose_logs: list[dict] = []
        self.toasts: list[Toast] = []
        self.pages: dict[str, ctk.CTkFrame] = {}
        self.nav_buttons: dict[str, AButton] = {}
        self.current_page: str | None = None
        self.stop_analysis, self.stop_ai = threading.Event(), threading.Event()
        self.analysis_running = self.ai_running = False
        self._ai_hint_active = True
        self._jobs: dict[str, str] = {}
        self._updated_dirty = False

        self.title(APP_NAME)
        self.geometry("1540x940")
        self.minsize(1200, 760)
        self.configure(fg_color=C("bg"))
        self._set_alpha(0.0)
        self._restyle_native()
        self._build_shell()
        self._build_dashboard()
        self._build_research()
        self._build_logs()
        self._build_settings()
        self._load_settings_into_widgets()
        self._restyle_native()
        self.navigate("dashboard", animated=False)
        self._bind_shortcuts()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(40, self._poll)
        self.after(80, self._fade_in)

    # ------------------------------------------------------------------ helpers
    def _set_alpha(self, value: float):
        try:
            self.attributes("-alpha", value)
        except tk.TclError:
            pass

    def _fade_in(self):
        animate(self, "fade", 380, lambda p: self._set_alpha(p), lambda: self._set_alpha(1.0))
        self.after(120, lambda: self._move_indicator(self.current_page, animated=False))

    def _debounce(self, key: str, ms: int, fn):
        if key in self._jobs:
            self.after_cancel(self._jobs[key])
        self._jobs[key] = self.after(ms, fn)

    @staticmethod
    def _set_text(box: ctk.CTkTextbox, text: str, keep_scroll: bool = False):
        top = box._textbox.yview()[0] if keep_scroll else 0.0
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        if keep_scroll:
            box._textbox.yview_moveto(top)

    def _bind_shortcuts(self):
        self.bind_all("<Control-Return>", lambda e: self.start_analysis())
        self.bind_all("<Control-s>", lambda e: self.save_settings())
        self.bind_all("<Control-t>", lambda e: self.toggle_theme())
        for i, (key, *_rest) in enumerate(NAV, start=1):
            self.bind_all(f"<Control-Key-{i}>", lambda e, k=key: self.navigate(k))

    def _on_close(self):
        self.stop_analysis.set()
        self.stop_ai.set()
        self.destroy()

    # ------------------------------------------------------------------ styling
    def _restyle_native(self):
        """Re-apply colours to the widgets customtkinter does not manage (ttk, tk.Menu, text tags)."""
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("SOC.Treeview", background=R("surface"), fieldbackground=R("surface"), foreground=R("text"),
                    rowheight=36, borderwidth=0, relief="flat", bordercolor=R("surface"), lightcolor=R("surface"),
                    darkcolor=R("surface"), focuscolor=R("surface"), font=(_FONTS["ui"], 10))
        s.configure("SOC.Treeview.Heading", background=R("surface3"), foreground=R("text"), relief="flat",
                    borderwidth=0, padding=(10, 9), font=(_FONTS["ui"], 10, "bold"))
        s.map("SOC.Treeview", background=[("selected", R("accent"))], foreground=[("selected", "#FFFFFF")])
        s.map("SOC.Treeview.Heading", background=[("active", R("border"))])
        for orient in ("Vertical", "Horizontal"):
            name = f"SOC.{orient}.TScrollbar"
            s.configure(name, background=R("surface3"), troughcolor=R("surface"), bordercolor=R("surface"),
                        darkcolor=R("surface3"), lightcolor=R("surface3"), arrowcolor=R("muted"), relief="flat", gripcount=0)
            s.map(name, background=[("active", R("muted"))])
        for table in (getattr(self, "domain_table", None), getattr(self, "ip_table", None)):
            if table:
                table.restyle()
        if hasattr(self, "log_text"):
            self.log_text.tag_config("ts", foreground=R("muted"))
            self.log_text.tag_config("title", foreground=R("text"))
            self.log_text.tag_config("body", foreground=R("muted"))
            for i, color in enumerate(LOG_COLORS):
                self.log_text.tag_config(f"cat{i}", foreground=R(color))

    def toggle_theme(self):
        self.set_theme("light" if ctk.get_appearance_mode() == "Dark" else "dark")

    def set_theme(self, mode: str):
        mode = mode.lower()
        if mode == ctk.get_appearance_mode().lower():
            return

        def swap_and_return():
            ctk.set_appearance_mode(mode)
            self._restyle_native()
            self._sync_theme_controls()
            self.settings.set(theme=mode)
            self.settings.save()
            animate(self, "theme_in", 240, lambda p: self._set_alpha(0.62 + 0.38 * p), lambda: self._set_alpha(1.0))

        animate(self, "theme_out", 140, lambda p: self._set_alpha(1 - 0.38 * p), swap_and_return, ease_in_out)

    def _sync_theme_controls(self):
        dark = ctk.get_appearance_mode() == "Dark"
        self.theme_btn.configure(text="☀" if dark else "☾")
        if hasattr(self, "theme_seg"):
            self.theme_seg.set("Dark" if dark else "Light")

    # ------------------------------------------------------------------ toasts
    def notify(self, text: str, kind: str = "info"):
        toast = Toast(self, text, kind, self._toast_closed)
        toast.enter = 0.0
        self.toasts.append(toast)
        self.update_idletasks()
        self._layout_toasts()

        def step(p):
            toast.enter = p
            self._layout_toasts()

        animate(toast, "slide_in", 340, step)

    def _layout_toasts(self):
        y = 24
        for toast in reversed(self.toasts):
            if not toast.winfo_exists():
                continue
            offset = int((1 - getattr(toast, "enter", 1)) * 400 + toast.slide * 400)
            toast.place(relx=1.0, rely=1.0, x=-24 + offset, y=-y, anchor="se")
            toast.lift()
            y += toast.winfo_reqheight() + 10

    def _toast_closed(self, toast: Toast, layout_only: bool = False):
        if layout_only:
            self._layout_toasts()
            return
        if toast in self.toasts:
            self.toasts.remove(toast)
        toast.destroy()
        self._layout_toasts()

    # ------------------------------------------------------------------ shell
    def _new_page(self, key: str) -> ctk.CTkFrame:
        page = ctk.CTkFrame(self.stage, fg_color="transparent")
        self.pages[key] = page
        return page

    def _build_shell(self):
        self.grid_columnconfigure(2, weight=1)
        self.grid_rowconfigure(0, weight=1)
        side = ctk.CTkFrame(self, width=244, corner_radius=0, fg_color=C("sidebar"))
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(2, weight=1)
        self.side = side
        ctk.CTkFrame(self, width=1, corner_radius=0, fg_color=C("border")).grid(row=0, column=1, sticky="ns")

        logo = ctk.CTkFrame(side, fg_color="transparent")
        logo.grid(row=0, column=0, sticky="ew", padx=22, pady=(26, 22))
        badge = ctk.CTkFrame(logo, width=42, height=42, corner_radius=13, fg_color=C("accent"))
        badge.grid(row=0, column=0, rowspan=2, padx=(0, 12))
        badge.grid_propagate(False)
        ctk.CTkLabel(badge, text="◈", font=font(22, "bold"), text_color="#FFFFFF").place(relx=0.5, rely=0.5, anchor="center")
        label(logo, "SOC Quarantine", 15, "bold").grid(row=0, column=1, sticky="sw")
        label(logo, "Intelligence", 12, "normal", "muted").grid(row=1, column=1, sticky="nw")

        self.nav_frame = ctk.CTkFrame(side, fg_color="transparent")
        self.nav_frame.grid(row=1, column=0, sticky="ew", padx=14)
        label(self.nav_frame, "WORKSPACE", 10, "bold", "muted").pack(anchor="w", padx=10, pady=(0, 8))
        for key, title, icon, _sub in NAV:
            btn = AButton(self.nav_frame, title, "nav", icon=icon, width=210, height=42, anchor="w",
                          command=lambda k=key: self.navigate(k))
            btn.pack(fill="x", pady=2)
            self.nav_buttons[key] = btn
        self.nav_indicator = ctk.CTkFrame(side, width=4, height=24, corner_radius=2, fg_color=C("accent"))

        foot = ctk.CTkFrame(side, fg_color="transparent")
        foot.grid(row=3, column=0, sticky="sew", padx=22, pady=(0, 22))
        label(foot, "Ctrl+Enter  analyze", 11, "normal", "muted").pack(anchor="w")
        label(foot, "Ctrl+1…4  switch page · Ctrl+T  theme", 11, "normal", "muted").pack(anchor="w", pady=(2, 8))
        label(foot, f"v{APP_VERSION}", 11, "bold", "muted").pack(anchor="w")

        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=2, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        top = ctk.CTkFrame(main, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=30, pady=(24, 14))
        top.grid_columnconfigure(0, weight=1)
        self.page_title = label(top, "", 26, "bold")
        self.page_title.grid(row=0, column=0, sticky="w")
        self.page_sub = label(top, "", 13, "normal", "muted")
        self.page_sub.grid(row=1, column=0, sticky="w")
        self.pill = StatusPill(top)
        self.pill.grid(row=0, column=1, rowspan=2, padx=(0, 12))
        self.theme_btn = AButton(top, "☀", "secondary", width=44, height=36, command=self.toggle_theme)
        self.theme_btn.configure(font=font(16))
        self.theme_btn.grid(row=0, column=2, rowspan=2)
        self.stage = ctk.CTkFrame(main, fg_color="transparent")
        self.stage.grid(row=1, column=0, sticky="nsew", padx=30, pady=(0, 26))
        self.stage.grid_columnconfigure(0, weight=1)
        self.stage.grid_rowconfigure(0, weight=1)
        self._sync_theme_controls()

    def navigate(self, key: str, animated: bool = True):
        if key == self.current_page or key not in self.pages:
            return
        old = self.pages.get(self.current_page) if self.current_page else None
        self.current_page = key
        if old:
            old.place_forget()
        _, title, _, sub = next(n for n in NAV if n[0] == key)
        self.page_title.configure(text=title)
        self.page_sub.configure(text=sub)
        for k, btn in self.nav_buttons.items():
            btn.set_colors(*(("surface2", "surface3", "accent") if k == key else ("sidebar", "surface2", "muted")))
        page = self.pages[key]
        page.place(x=0, y=20 if animated else 0, relwidth=1, relheight=1)
        self._move_indicator(key, animated)
        if animated:
            animate(page, "enter", 280, lambda p: page.place_configure(y=round(20 * (1 - p))))
            bg, fg = pick(C("bg")), pick(C("text"))
            animate(self.page_title, "fade", 280, lambda p: self.page_title.configure(text_color=mix(bg, fg, p)),
                    lambda: self.page_title.configure(text_color=C("text")))

    def _move_indicator(self, key: str | None, animated: bool = True):
        if not key:
            return
        self.update_idletasks()
        btn = self.nav_buttons[key]
        target = self.nav_frame.winfo_y() + btn.winfo_y() + (btn.winfo_height() - 24) // 2
        if not self.nav_indicator.winfo_ismapped() or not animated:
            self.nav_indicator.place(x=0, y=target)
            return
        start = self.nav_indicator.winfo_y()
        animate(self.nav_indicator, "move", 340, lambda p: self.nav_indicator.place_configure(y=round(start + (target - start) * p)), ease=ease_in_out)

    # ------------------------------------------------------------------ dashboard
    def _build_dashboard(self):
        page = self._new_page("dashboard")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)

        kp = ctk.CTkFrame(page, fg_color="transparent")
        kp.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        self.kpis: dict[str, KpiCard] = {}
        for i, (key, title, color) in enumerate(KPI_DEFS):
            kp.grid_columnconfigure(i, weight=1, uniform="kpi")
            self.kpis[key] = KpiCard(kp, title, color)
            self.kpis[key].grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 7, 0 if i == len(KPI_DEFS) - 1 else 7))

        body = ctk.CTkFrame(page, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=3, uniform="body")
        body.grid_columnconfigure(1, weight=5, uniform="body")
        body.grid_rowconfigure(0, weight=1)

        inp = card(body)
        inp.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        inp.grid_columnconfigure(0, weight=1)
        inp.grid_rowconfigure(2, weight=1)
        hdr = ctk.CTkFrame(inp, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 8))
        hdr.grid_columnconfigure(0, weight=1)
        label(hdr, "Incident input", 15, "bold").grid(row=0, column=0, sticky="w")
        self.count_chip = label(hdr, "0 emails detected", 12, "normal", "muted")
        self.count_chip.grid(row=0, column=1)
        tools = ctk.CTkFrame(inp, fg_color="transparent")
        tools.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))
        for text, cmd in (("Paste", self.paste_input), ("Sample", self.load_sample), ("Clear", self.clear_input)):
            AButton(tools, text, "secondary", width=84, height=32, command=cmd).pack(side="left", padx=(0, 8))
        self.input_box = textbox(inp)
        self.input_box.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 12))
        for seq in ("<KeyRelease>", "<<Paste>>", "<<Cut>>"):
            self.input_box.bind(seq, lambda e: self._debounce("count", 350, self._update_count))
        act = ctk.CTkFrame(inp, fg_color="transparent")
        act.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 18))
        act.grid_columnconfigure(0, weight=1)
        self.analyze_btn = AButton(act, "Analyze incidents", "primary", icon="▶", width=200, height=44, command=self.start_analysis)
        self.analyze_btn.grid(row=0, column=0, sticky="ew")
        self.stop_btn = AButton(act, "Stop", "danger", width=92, height=44, command=self.stop_analysis_run)
        self.stop_btn.grid(row=0, column=1, padx=(10, 0))
        self.stop_btn.set_enabled(False)

        res = card(body)
        res.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        res.grid_columnconfigure(0, weight=1)
        res.grid_rowconfigure(1, weight=1)
        bar = ctk.CTkFrame(res, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 10))
        bar.grid_columnconfigure(1, weight=1)
        self.view_seg = ctk.CTkSegmentedButton(
            bar, values=["Domains", "IPs", "Updated input"], command=self._switch_view, height=34, font=font(13, "bold"),
            fg_color=C("surface2"), unselected_color=C("surface2"), unselected_hover_color=C("surface3"),
            selected_color=("#FFFFFF", "#2C3B70"), selected_hover_color=("#FFFFFF", "#2C3B70"), text_color=C("text"))
        self.view_seg.grid(row=0, column=0)
        self.view_seg.set("Domains")
        AButton(bar, "Export", "secondary", width=88, height=34, command=self.export_report).grid(row=0, column=2)
        AButton(bar, "Copy updated", "secondary", width=122, height=34, command=self.copy_updated).grid(row=0, column=1, sticky="e", padx=(0, 8))
        holder = ctk.CTkFrame(res, fg_color="transparent")
        holder.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 16))
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        self.domain_table = ResultTable(holder, "Sender domain", "domain", self.notify)
        self.ip_table = ResultTable(holder, "Sender IP", "ip-address", self.notify)
        self.updated_box = textbox(holder)
        self.views = {"Domains": self.domain_table, "IPs": self.ip_table, "Updated input": self.updated_box}
        for widget in self.views.values():
            widget.grid(row=0, column=0, sticky="nsew")
        self.domain_table.tkraise()

        foot = card(page, corner_radius=14)
        foot.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        foot.grid_columnconfigure(0, weight=1)
        self.progress = SmoothProgress(foot)
        self.progress.grid(row=0, column=0, sticky="ew", padx=(18, 14), pady=16)
        self.progress_text = label(foot, "Idle", 12, "normal", "muted")
        self.progress_text.grid(row=0, column=1, padx=(0, 18))
        label(foot, "Lookup errors are always Unknown, never Safe — review before blocking indicators.", 11, "normal", "muted").grid(
            row=1, column=0, columnspan=2, sticky="w", padx=18, pady=(0, 12))
        self._recount()

    def _switch_view(self, name: str):
        self.views[name].tkraise()

    def _update_count(self):
        _, found = parse_incidents(self.input_box.get("1.0", "end-1c"))
        self.count_chip.configure(text=f"{len(found)} email{'s' if len(found) != 1 else ''} detected")

    def paste_input(self):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            self.notify("Clipboard is empty", "warning")
            return
        self._set_text(self.input_box, text)
        self._update_count()

    def load_sample(self):
        self._set_text(self.input_box, SAMPLE_DATA)
        self._update_count()

    def clear_input(self):
        self._set_text(self.input_box, "")
        self._update_count()

    def copy_updated(self):
        value = self.updated_box.get("1.0", "end-1c").strip()
        if not value:
            self.notify("Run an analysis first", "warning")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.notify("Updated incident input copied", "success")

    # ------------------------------------------------------------------ dashboard logic
    def _recount(self):
        total = len(self.records)
        done = sum(1 for r in self.records if r.verdict != "Pending")
        self.kpis["total"].set(done, f"of {total} email{'s' if total != 1 else ''}")
        for key in ("Malicious", "Suspicious", "Safe", "Unknown"):
            n = sum(1 for r in self.records if r.verdict == key)
            self.kpis[key].set(n, f"{round(n * 100 / total)}% of emails" if total else " ")

    def _push_row(self, inc: Incident, flash: bool):
        pending = "Queued" if inc.domain_reputation == "Pending" else inc.domain_detections
        self.domain_table.upsert(inc.row_id, inc.email_id, inc.domain, inc.domain_reputation, pending, flash)
        pending = "Queued" if inc.ip_reputation == "Pending" else inc.ip_detections
        self.ip_table.upsert(inc.row_id, inc.email_id, inc.sender_ip, inc.ip_reputation, pending, flash)

    def _refresh_updated(self):
        self._updated_dirty = False
        if self.records:
            self._set_text(self.updated_box, render_updated_text(self.original_text, self.records), keep_scroll=True)

    def _queue_updated_refresh(self):
        if not self._updated_dirty:
            self._updated_dirty = True
            self.after(120, self._refresh_updated)

    def _register_secrets(self):
        self.redactor.add(self.vt_entry.get(), *self._provider_keys().values())

    def start_analysis(self):
        if self.analysis_running:
            return
        self.navigate("dashboard")
        text, found = parse_incidents(self.input_box.get("1.0", "end-1c"))
        if not found:
            self.notify("No incidents found — paste records with Sender Address / Sender IP fields.", "warning")
            return
        vt_key = self.vt_entry.get()
        if not vt_key and not messagebox.askyesno("VirusTotal key missing",
                                                   "No VirusTotal API key is configured, so every result will be Unknown.\n\nContinue anyway?"):
            return
        self._register_secrets()
        self.original_text, self.records = text, found
        self.domain_table.clear()
        self.ip_table.clear()
        for inc in found:
            self._push_row(inc, flash=False)
        self._recount()
        self._refresh_updated()
        self.progress.reset()
        self.analysis_running = True
        self.stop_analysis = threading.Event()
        self.analyze_btn.set_enabled(False, "Analyzing…")
        self.stop_btn.set_enabled(True)
        self.pill.set("working", f"Analyzing {len(found)} emails")
        client = VirusTotalClient(vt_key, self._log, self.stop_analysis, self._vt_interval())
        threading.Thread(target=self._analysis_worker, args=(found, client, self.stop_analysis), daemon=True).start()

    def stop_analysis_run(self):
        if self.analysis_running:
            self.stop_analysis.set()
            self.stop_btn.set_enabled(False, "Stopping…")
            self.pill.set("warning", "Stopping…")

    def _analysis_worker(self, incidents: list[Incident], client: VirusTotalClient, stop: threading.Event):
        plan = {("domain", i.domain) for i in incidents if is_valid_domain(i.domain)}
        plan |= {("ip", i.sender_ip) for i in incidents if ip_state(i.sender_ip) == "ok"}
        total, finished, cache = max(1, len(plan)), 0, {}

        def check(kind: str, value: str):
            nonlocal finished
            if (kind, value) not in cache:
                eta = fmt_eta((total - finished) * client.min_interval)
                self.events.put(("progress", finished / total, f"Querying VirusTotal · {kind} {value} · {finished + 1}/{total} · ~{eta} left"))
                cache[(kind, value)] = client.lookup(value, kind)
                finished += 1
                self.events.put(("progress", finished / total, f"Checked {finished}/{total} unique indicators"))
            return cache[(kind, value)]

        try:
            for index, inc in enumerate(incidents):
                if stop.is_set():
                    break
                if not inc.domain:
                    inc.domain_reputation, inc.domain_detections = "Unknown", "Sender domain not parsed"
                elif not is_valid_domain(inc.domain):
                    inc.domain_reputation, inc.domain_detections = "Unknown", "Invalid sender domain"
                else:
                    inc.domain_reputation, inc.domain_detections = check("domain", inc.domain)
                state = ip_state(inc.sender_ip)
                if state == "ok":
                    if stop.is_set():
                        break
                    inc.ip_reputation, inc.ip_detections = check("ip", inc.sender_ip)
                else:
                    note = {"missing": "Sender IP not found", "invalid": "Invalid IP address format",
                            "private": "Private/reserved address — not checked"}[state]
                    inc.ip_reputation, inc.ip_detections = "Unknown", note
                self.events.put(("record", index))
        finally:
            self.events.put(("analysis_done", stop.is_set()))

    # ------------------------------------------------------------------ AI research page
    def _build_research(self):
        page = self._new_page("research")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        bar = card(page, corner_radius=14)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        bar.grid_columnconfigure(4, weight=1)
        AButton(bar, "Extract from input", "secondary", width=172, command=self.extract_domains).grid(row=0, column=0, padx=(16, 8), pady=14)
        self.ai_run_btn = AButton(bar, "Run AI research", "success", icon="▶", width=170, command=self.run_ai)
        self.ai_run_btn.grid(row=0, column=1, padx=8)
        self.ai_stop_btn = AButton(bar, "Stop", "danger", width=84, command=self.stop_ai_run)
        self.ai_stop_btn.grid(row=0, column=2, padx=8)
        self.ai_stop_btn.set_enabled(False)
        AButton(bar, "Copy results", "secondary", width=130, command=self.copy_ai).grid(row=0, column=3, padx=8)
        self.ai_summary = label(bar, "", 12, "normal", "muted")
        self.ai_summary.grid(row=0, column=4, sticky="e", padx=18)

        body = ctk.CTkFrame(page, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=3, uniform="ai")
        body.grid_columnconfigure(1, weight=7, uniform="ai")
        body.grid_rowconfigure(0, weight=1)
        for col, title, attr, hint in ((0, "Sender domains", "ai_domains", AI_HINT), (1, "AI analysis · editable notes", "ai_results", AI_RESULT_HINT)):
            panel = card(body)
            panel.grid(row=0, column=col, sticky="nsew", padx=(0, 8) if col == 0 else (8, 0))
            panel.grid_columnconfigure(0, weight=1)
            panel.grid_rowconfigure(1, weight=1)
            label(panel, title, 15, "bold").grid(row=0, column=0, sticky="w", padx=18, pady=(16, 10))
            box = textbox(panel, wrap="none" if col == 0 else "word")
            box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
            box.insert("1.0", hint)
            setattr(self, attr, box)
        self.ai_domains.bind("<FocusIn>", lambda e: self._clear_hint(self.ai_domains, AI_HINT))

        foot = card(page, corner_radius=14)
        foot.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        foot.grid_columnconfigure(0, weight=1)
        self.ai_progress = SmoothProgress(foot)
        self.ai_progress.grid(row=0, column=0, sticky="ew", padx=(18, 14), pady=16)
        self.ai_progress_text = label(foot, "Idle", 12, "normal", "muted")
        self.ai_progress_text.grid(row=0, column=1, padx=(0, 18))

    @staticmethod
    def _clear_hint(box, hint):
        if box.get("1.0", "end-1c") == hint:
            box.delete("1.0", "end")

    def _refresh_ai_summary(self):
        parts = [f"Provider: {self.provider_menu.get()}"]
        parts += [name for name, var in (("Domainee", self.use_domainee), ("DNSAPI.ai", self.use_dnsapi), ("Website fetch", self.fetch_site)) if var.get()]
        self.ai_summary.configure(text="  ·  ".join(parts))

    def extract_domains(self):
        _, found = parse_incidents(self.input_box.get("1.0", "end-1c"))
        domains = sorted({i.domain for i in found if is_valid_domain(i.domain)})
        if domains:
            self._set_text(self.ai_domains, "\n".join(domains))
            self.notify(f"Extracted {len(domains)} unique sender domain{'s' if len(domains) != 1 else ''}", "success")
        else:
            self.notify("No valid sender domains found in the incident input", "warning")

    def _domains_from_box(self) -> list[str]:
        seen: dict[str, None] = {}
        for line in self.ai_domains.get("1.0", "end").splitlines():
            domain = line.strip().lower().rstrip(".")
            if is_valid_domain(domain):
                seen.setdefault(domain)
        return list(seen)

    def run_ai(self):
        if self.ai_running:
            return
        domains = self._domains_from_box()
        if not domains:
            self.extract_domains()
            domains = self._domains_from_box()
        if not domains:
            return
        keys = self._provider_keys()
        if not any(keys.values()):
            self.notify("Add a Gemini, Grok or NVIDIA API key in Settings first", "warning")
            self.navigate("settings")
            return
        self._register_secrets()
        self._set_text(self.ai_results, "")
        self._ai_hint_active = False
        self.ai_running = True
        self.stop_ai = threading.Event()
        self.ai_progress.reset()
        self.ai_run_btn.set_enabled(False, "Researching…")
        self.ai_stop_btn.set_enabled(True)
        collector = EvidenceCollector(requests.Session(), self._log, domainee=self.use_domainee.get(),
                                      dnsapi=self.use_dnsapi.get(), fetch_site=self.fetch_site.get())
        researcher = AIResearcher(keys, self.provider_menu.get(), self.model_entry.get().strip(), collector, self._log, self.stop_ai)
        threading.Thread(target=self._ai_worker, args=(domains, researcher, self.stop_ai), daemon=True).start()

    def stop_ai_run(self):
        if self.ai_running:
            self.stop_ai.set()
            self.ai_stop_btn.set_enabled(False, "Stopping…")

    def _ai_worker(self, domains: list[str], researcher: AIResearcher, stop: threading.Event):
        try:
            for i, domain in enumerate(domains, start=1):
                if stop.is_set():
                    break
                self.events.put(("ai_status", i, len(domains), domain))
                try:
                    text = researcher.describe_domain(domain) or "Company: Not identified\nOffers: Provider returned an empty response."
                except Exception as exc:
                    text = f"Company: Not identified\nOffers: Analysis failed safely ({type(exc).__name__})."
                self.events.put(("ai_result", domain, text, i, len(domains)))
        finally:
            self.events.put(("ai_done", stop.is_set()))

    def copy_ai(self):
        value = self.ai_results.get("1.0", "end-1c").strip()
        if not value or value == AI_RESULT_HINT:
            self.notify("No AI results to copy yet", "warning")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.notify("AI notes copied", "success")

    # ------------------------------------------------------------------ logs page
    def _build_logs(self):
        page = self._new_page("logs")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        bar = card(page, corner_radius=14)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        bar.grid_columnconfigure(2, weight=1)
        self.log_filter = ctk.CTkOptionMenu(bar, values=LOG_CATEGORIES, command=lambda _v: self._render_logs(), width=230, height=36,
                                            font=font(13), dropdown_font=font(13), fg_color=C("surface2"), button_color=C("surface3"),
                                            button_hover_color=C("border"), text_color=C("text"), dropdown_fg_color=C("surface"),
                                            dropdown_hover_color=C("surface2"), dropdown_text_color=C("text"))
        self.log_filter.grid(row=0, column=0, padx=(16, 8), pady=14)
        self.log_search = ctk.CTkEntry(bar, placeholder_text="Search logs…", width=220, height=36, corner_radius=10, fg_color=C("surface2"),
                                       border_color=C("border"), text_color=C("text"), placeholder_text_color=C("muted"), font=font(13))
        self.log_search.grid(row=0, column=1, padx=8)
        self.log_search.bind("<KeyRelease>", lambda e: self._debounce("logsearch", 250, self._render_logs))
        self.log_count = label(bar, "0 entries", 12, "normal", "muted")
        self.log_count.grid(row=0, column=2, sticky="e", padx=12)
        AButton(bar, "Copy", "secondary", width=74, height=36, command=self.copy_logs).grid(row=0, column=3, padx=4)
        AButton(bar, "Export", "secondary", width=82, height=36, command=self.export_logs).grid(row=0, column=4, padx=4)
        AButton(bar, "Clear", "danger", width=76, height=36, command=self.clear_logs).grid(row=0, column=5, padx=(4, 16))
        panel = card(page)
        panel.grid(row=1, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)
        self.log_text = textbox(panel, size=11)
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=14, pady=14)
        self.log_text.configure(state="disabled")

    def _log(self, category: str, title: str, detail):
        """Thread-safe: redact first, then hand over to the UI thread."""
        self.events.put(("log", time.strftime("%H:%M:%S"), category, title, self.redactor(str(detail or ""))))

    def _log_visible(self, item: dict) -> bool:
        wanted = self.log_filter.get()
        if wanted != "All logs" and item["cat"] != wanted:
            return False
        needle = self.log_search.get().strip().lower()
        return not needle or needle in f"{item['cat']} {item['title']} {item['detail']}".lower()

    def _write_log(self, item: dict):
        t = self.log_text
        idx = LOG_CATEGORIES.index(item["cat"]) if item["cat"] in LOG_CATEGORIES else 0
        t.insert("end", f"{item['ts']}  ", "ts")
        t.insert("end", item["cat"], f"cat{idx}")
        t.insert("end", f"   {item['title']}\n", "title")
        t.insert("end", item["detail"][:6000] + "\n" + "─" * 80 + "\n\n", "body")

    def _on_log(self, ts, cat, title, detail):
        item = {"ts": ts, "cat": cat, "title": title, "detail": detail}
        self.verbose_logs.append(item)
        if len(self.verbose_logs) > LOG_STORE_MAX:
            del self.verbose_logs[:len(self.verbose_logs) - LOG_STORE_MAX]
        if self._log_visible(item):
            stick = self.log_text._textbox.yview()[1] > 0.97
            self.log_text.configure(state="normal")
            self._write_log(item)
            self.log_text.configure(state="disabled")
            if stick:
                self.log_text._textbox.see("end")
            self.log_count.configure(text=f"{len(self.verbose_logs)} entries")

    def _render_logs(self):
        shown = [x for x in self.verbose_logs if self._log_visible(x)]
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        for item in shown[-LOG_RENDER_MAX:]:
            self._write_log(item)
        self.log_text.configure(state="disabled")
        self.log_text._textbox.see("end")
        extra = f" (showing last {LOG_RENDER_MAX})" if len(shown) > LOG_RENDER_MAX else ""
        self.log_count.configure(text=f"{len(shown)} of {len(self.verbose_logs)} entries{extra}")

    def _visible_logs(self) -> list[dict]:
        return [x for x in self.verbose_logs if self._log_visible(x)]

    def copy_logs(self):
        entries = self._visible_logs()
        if not entries:
            self.notify("No matching logs to copy", "warning")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(f"[{x['ts']}] [{x['cat']}] {x['title']}\n{x['detail']}" for x in entries))
        self.notify(f"Copied {len(entries)} log entries", "success")

    def export_logs(self):
        path = filedialog.asksaveasfilename(title="Export logs", defaultextension=".txt", initialfile="soc_analyzer_logs.txt",
                                            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")])
        if not path:
            return
        entries = self._visible_logs()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                if path.lower().endswith(".json"):
                    json.dump(entries, fh, ensure_ascii=False, indent=2)
                else:
                    for x in entries:
                        fh.write(f"[{x['ts']}] [{x['cat']}] {x['title']}\n{x['detail']}\n{'=' * 90}\n")
            self.notify(f"Exported {len(entries)} log entries", "success")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def clear_logs(self):
        if messagebox.askyesno("Clear logs", "Clear all in-memory logs? This cannot be undone."):
            self.verbose_logs.clear()
            self._render_logs()

    # ------------------------------------------------------------------ settings page
    def _build_settings(self):
        page = self._new_page("settings")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(0, weight=1)
        scroll = ctk.CTkScrollableFrame(page, fg_color="transparent", corner_radius=0, scrollbar_button_color=C("surface3"),
                                        scrollbar_button_hover_color=C("muted"))
        scroll.grid(row=0, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        def section(row, title, subtitle):
            box = card(scroll)
            box.grid(row=row, column=0, sticky="ew", pady=(0, 14), padx=(0, 6))
            box.grid_columnconfigure(1, weight=1)
            label(box, title, 15, "bold").grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(18, 0))
            label(box, subtitle, 12, "normal", "muted").grid(row=1, column=0, columnspan=2, sticky="w", padx=20, pady=(2, 8))
            box.grid_rowconfigure(99, minsize=18)
            return box

        def row(box, r, title, widget, hint="", sticky="ew"):
            label(box, title, 13, "bold").grid(row=r, column=0, sticky="nw", padx=(20, 18), pady=(12, 0))
            widget.grid(row=r, column=1, sticky=sticky, padx=(0, 20), pady=(8, 0))
            if hint:
                label(box, hint, 11, "normal", "muted", wraplength=640, justify="left").grid(row=r + 1, column=1, sticky="w", padx=(0, 20))

        creds = section(0, "API credentials", "Stored in the operating-system credential store — never written to disk by this app.")
        self.vt_entry = SecretEntry(creds, "VirusTotal API key")
        self.gemini_entry = SecretEntry(creds, "Gemini API key")
        self.grok_entry = SecretEntry(creds, "Grok (xAI) API key")
        self.nvidia_entry = SecretEntry(creds, "NVIDIA API key")
        for i, (title, widget, hint) in enumerate((
                ("VirusTotal", self.vt_entry, "Required for reputation checks. Public keys allow ~4 requests per minute."),
                ("Gemini", self.gemini_entry, ""), ("Grok", self.grok_entry, ""), ("NVIDIA", self.nvidia_entry, ""))):
            row(creds, 2 + i * 2, title, widget, hint)

        ai = section(1, "AI research", "Auto mode discovers available models and falls back to other models/providers on failure.")
        self.provider_menu = ctk.CTkOptionMenu(ai, values=["Auto", "Gemini", "Grok", "NVIDIA"], width=180, height=38, font=font(13),
                                               dropdown_font=font(13), fg_color=C("surface2"), button_color=C("surface3"),
                                               button_hover_color=C("border"), text_color=C("text"), dropdown_fg_color=C("surface"),
                                               dropdown_hover_color=C("surface2"), dropdown_text_color=C("text"),
                                               command=lambda _v: self._refresh_ai_summary())
        self.model_entry = ctk.CTkEntry(ai, placeholder_text="Preferred model (optional)", height=38, corner_radius=10, fg_color=C("surface2"),
                                        border_color=C("border"), text_color=C("text"), placeholder_text_color=C("muted"), font=font(13))
        row(ai, 2, "Preferred provider", self.provider_menu, sticky="w")
        row(ai, 3, "Preferred model", self.model_entry)

        net = section(2, "Enrichment & network", "Choose which public sources are queried when researching a domain.")
        self.use_domainee, self.use_dnsapi, self.fetch_site = tk.BooleanVar(), tk.BooleanVar(), tk.BooleanVar()
        switch_kw = dict(font=font(13), text_color=C("text"), progress_color=C("accent"), button_color=("#FFFFFF", "#E8EEFF"),
                         button_hover_color=("#FFFFFF", "#FFFFFF"), fg_color=C("surface3"), command=self._refresh_ai_summary)
        row(net, 2, "Domainee", ctk.CTkSwitch(net, text="DNS, SSL and website status (no key)", variable=self.use_domainee, **switch_kw), sticky="w")
        row(net, 3, "DNSAPI.ai", ctk.CTkSwitch(net, text="Lookup, threat intel and WHOIS (no key)", variable=self.use_dnsapi, **switch_kw), sticky="w")
        row(net, 4, "Website fetch", ctk.CTkSwitch(net, text="Read the sender's public homepage", variable=self.fetch_site, **switch_kw),
            "Contacts the sender's site directly from this machine and exposes your IP to it. Turn off for sensitive investigations.", sticky="w")
        self.vt_interval_entry = ctk.CTkEntry(net, width=110, height=38, corner_radius=10, fg_color=C("surface2"), border_color=C("border"),
                                              text_color=C("text"), font=font(13))
        row(net, 6, "VirusTotal interval", self.vt_interval_entry, "Seconds between lookups. 16 suits a public key; use 0 for premium keys.", sticky="w")

        look = section(3, "Appearance", "Switch instantly with Ctrl+T or the toggle in the top bar.")
        self.theme_seg = ctk.CTkSegmentedButton(look, values=["Dark", "Light"], command=self.set_theme, height=36, font=font(13, "bold"),
                                                fg_color=C("surface2"), unselected_color=C("surface2"), unselected_hover_color=C("surface3"),
                                                selected_color=("#FFFFFF", "#2C3B70"), selected_hover_color=("#FFFFFF", "#2C3B70"), text_color=C("text"))
        row(look, 2, "Theme", self.theme_seg, sticky="w")

        foot = ctk.CTkFrame(page, fg_color="transparent")
        foot.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        AButton(foot, "Save settings", "primary", width=160, height=42, command=self.save_settings).pack(side="left")
        self.keys_note = label(foot, "", 12, "normal", "muted")
        self.keys_note.pack(side="left", padx=16)

    def _load_settings_into_widgets(self):
        self.vt_entry.set(self.secrets.load("virustotal"))
        self.gemini_entry.set(self.secrets.load("gemini"))
        self.grok_entry.set(self.secrets.load("grok"))
        self.nvidia_entry.set(self.secrets.load("nvidia"))
        self.provider_menu.set(self.settings.get("ai_provider"))
        self.model_entry.insert(0, self.settings.get("model") or "")
        self.use_domainee.set(bool(self.settings.get("use_domainee")))
        self.use_dnsapi.set(bool(self.settings.get("use_dnsapi")))
        self.fetch_site.set(bool(self.settings.get("fetch_site")))
        self.vt_interval_entry.insert(0, str(self.settings.get("vt_interval")))
        self.keys_note.configure(text="" if self.secrets.available else "Install “keyring” to persist API keys securely (pip install keyring).")
        self._sync_theme_controls()
        self._refresh_ai_summary()
        self._register_secrets()

    def _provider_keys(self) -> dict:
        return {"Gemini": self.gemini_entry.get(), "Grok": self.grok_entry.get(), "NVIDIA": self.nvidia_entry.get()}

    def _vt_interval(self) -> float:
        try:
            return max(0.0, min(300.0, float(self.vt_interval_entry.get().strip())))
        except ValueError:
            return 16.0

    def save_settings(self):
        self.settings.set(ai_provider=self.provider_menu.get(), model=self.model_entry.get().strip(),
                          use_domainee=self.use_domainee.get(), use_dnsapi=self.use_dnsapi.get(),
                          fetch_site=self.fetch_site.get(), vt_interval=self._vt_interval())
        saved_prefs = self.settings.save()
        self._register_secrets()
        self._refresh_ai_summary()
        if not self.secrets.available:
            self.notify("Preferences saved. Install “keyring” to also store API keys.", "warning")
        elif all([self.secrets.save("virustotal", self.vt_entry.get()), self.secrets.save("gemini", self.gemini_entry.get()),
                  self.secrets.save("grok", self.grok_entry.get()), self.secrets.save("nvidia", self.nvidia_entry.get())]) and saved_prefs:
            self.notify("Settings and API keys saved securely", "success")
        else:
            self.notify("Some settings could not be saved — check credential-store access", "error")

    # ------------------------------------------------------------------ export
    def export_report(self):
        if not self.records:
            self.notify("Analyze some incidents first", "warning")
            return
        path = filedialog.asksaveasfilename(title="Export reputation report", defaultextension=".csv",
                                            initialfile=f"soc_reputation_report_{time.strftime('%Y%m%d')}.csv",
                                            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json")])
        if not path:
            return
        rows = [{k: getattr(r, k) for k in CSV_FIELDS} for r in self.records]
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(rows, fh, ensure_ascii=False, indent=2)
            else:
                def safe(value):  # neutralise spreadsheet formula injection from attacker-controlled fields
                    text = str(value)
                    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
                with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                    writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
                    writer.writeheader()
                    writer.writerows({k: safe(v) for k, v in row.items()} for row in rows)
            self.notify(f"Report saved · {Path(path).name}", "success")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    # ------------------------------------------------------------------ event loop
    def _poll(self):
        try:
            for _ in range(300):
                kind, *args = self.events.get_nowait()
                getattr(self, f"_ev_{kind}")(*args)
        except queue.Empty:
            pass
        self.after(50, self._poll)

    def _ev_log(self, ts, cat, title, detail):
        self._on_log(ts, cat, title, detail)

    def _ev_progress(self, fraction, text):
        self.progress.glide(fraction)
        self.progress_text.configure(text=text if len(text) < 90 else text[:87] + "…")
        if self.analysis_running and not self.stop_analysis.is_set():
            self.pill.set("working", text)

    def _ev_record(self, index):
        self._push_row(self.records[index], flash=True)
        self._recount()
        self._queue_updated_refresh()

    def _ev_analysis_done(self, stopped):
        self.analysis_running = False
        self.analyze_btn.set_enabled(True, "▶  Analyze incidents")
        self.stop_btn.set_enabled(False, "Stop")
        self._refresh_updated()
        self._recount()
        bad = sum(1 for r in self.records if r.verdict == "Malicious")
        sus = sum(1 for r in self.records if r.verdict == "Suspicious")
        done = sum(1 for r in self.records if r.verdict != "Pending")
        if stopped:
            self.progress_text.configure(text=f"Stopped · {done}/{len(self.records)} processed")
            self.pill.set("warning", f"Stopped · {done}/{len(self.records)} processed")
            self.notify("Analysis stopped — remaining emails stay Pending", "warning")
        else:
            self.progress.glide(1.0)
            summary = f"Complete · {bad} malicious · {sus} suspicious"
            self.progress_text.configure(text=summary)
            self.pill.set("error" if bad else "success", summary)
            self.notify(f"Analysis complete — {done} emails, {bad} malicious, {sus} suspicious", "error" if bad else "success")

    def _ev_ai_status(self, i, total, domain):
        self.ai_progress.glide((i - 1) / total)
        self.ai_progress_text.configure(text=f"Researching {i}/{total} · {domain}")
        self.pill.set("working", f"AI research {i}/{total}")

    def _ev_ai_result(self, domain, text, i, total):
        box = self.ai_results
        box.insert("end", f"DOMAIN: {domain}\n{text.strip()}\n\n{'-' * 72}\n\n")
        box._textbox.see("end")
        for inc in self.records:
            if inc.domain == domain:
                inc.company_description = text.strip()
        self.ai_progress.glide(i / total)

    def _ev_ai_done(self, stopped):
        self.ai_running = False
        self.ai_run_btn.set_enabled(True, "▶  Run AI research")
        self.ai_stop_btn.set_enabled(False, "Stop")
        self.ai_progress_text.configure(text="Stopped" if stopped else "Research complete")
        self.pill.set("warning" if stopped else "success", "AI research stopped" if stopped else "AI research complete")
        self.notify("AI research stopped" if stopped else "AI domain research complete", "warning" if stopped else "success")


def main():
    settings = SettingsStore()
    app = App(settings)
    app.mainloop()


if __name__ == "__main__":
    main()
