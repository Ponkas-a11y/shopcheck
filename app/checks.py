"""Prüflogik: sammelt Indizien, ob ein Online-Shop seriös wirkt."""
import ipaddress
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept-Language": "de,en;q=0.8",
}
TIMEOUT = 8
MAX_BYTES = 1_500_000
BASE_SCORE = 20
_tld = tldextract.TLDExtract(suffix_list_urls=())  # offline, nutzt mitgelieferte Liste

EU_VAT = "AT BE BG CY CZ DE DK EE EL ES FI FR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK".split()
_other = "|".join(c for c in EU_VAT if c not in ("AT", "NL"))
VAT_RE = re.compile(rf"\b(?:(AT)\s?(U\d{{8}})|(NL)\s?(\d{{9}}B\d{{2}})|({_other})[\s.-]?(\d{{8,12}}))\b")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"(?:\+|00)\d[\d\s/().-]{7,}\d|\b0\d{2,5}[\s/-]?\d{4,}[\d\s/-]*")
PLZ_RE = re.compile(r"\b\d{5}\s+[A-ZÄÖÜ][\wäöüß.-]+|\b[A-Z]{1,2}-?\d{4,5}\s+[A-Z][\w-]+")
FORM_RE = re.compile(
    r"\b[A-ZÄÖÜ][\w&.\-äöüß]*(?:\s[\w&.\-äöüß]+){0,4}\s"
    r"(?:GmbH(?: & Co\. ?KG)?|UG(?: \(haftungsbeschränkt\))?|AG|e\.\s?K\.|KG|OHG|GbR|Ltd\.?|Limited|B\.V\.|S\.L\.|S\.A\.|SAS|SARL|Sp\. z o\.o\.)"
)
REG_RE = re.compile(r"\b(?:HRB|HRA|GnR|VR)\s?\d+|\bFN\s?\d+\s?[a-z]\b|Handelsregister", re.I)
STOP = {"tmg", "ddg", "impressum", "angaben", "gemäß", "firma", "inhaber", "betreiber", "anbieter", "und"}
LINK_PATTERNS = {
    "impressum": r"impressum|imprint|anbieterkennzeichnung|legal notice|rechtliche hinweise",
    "agb": r"\bagb\b|allgemeine gesch|terms|bedingungen",
    "widerruf": r"widerruf|rückgabe|ruckgabe|return|refund|rücksendung|cancellation",
    "datenschutz": r"datenschutz|privacy",
}
URGENCY = [
    r"nur noch \d+", r"only \d+ left", r"countdown", r"angebot endet", r"nur heute", r"limited time",
    r"letzte chance", r"\d+ (personen|menschen|people) (sehen|schauen|viewing)", r"-\s?[5-9]\d\s?%",
    r"[5-9]\d\s?% (rabatt|off|sale)", r"flash ?sale", r"räumungsverkauf|lagerräumung|geschäftsaufgabe|closing down",
]
CHEAP_TLDS = {"top", "xyz", "shop", "store", "online", "site", "icu", "cyou", "click", "buzz", "vip", "cfd", "sbs", "lol", "rest"}


def F(level, title, detail="", pts=0, crit=False):
    return {"level": level, "title": title, "detail": detail, "points": pts, "crit": crit}


# ---------- Netzwerk (mit SSRF-Schutz) ----------
def normalize(raw):
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname or "." not in p.hostname:
        raise ValueError("Ungültige URL.")
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname.lower()}{port}{p.path or '/'}", p.hostname.lower()


def public_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)


def fetch(url, hops=5):
    """GET mit manuellem Redirect-Handling; jede Station muss öffentlich sein."""
    for _ in range(hops + 1):
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname or not public_host(p.hostname):
            raise ValueError("Zieladresse nicht erlaubt oder nicht auflösbar.")
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False, stream=True)
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        raw = r.raw.read(MAX_BYTES, decode_content=True)
        r.close()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode(r.encoding or "latin-1", errors="replace")
        return url, r.status_code, text
    raise ValueError("Zu viele Weiterleitungen.")


# ---------- Einzelprüfungen ----------
def _norm_dt(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return None


def registration_date(domain):
    try:
        r = requests.get(f"https://rdap.org/domain/{quote(domain)}", timeout=TIMEOUT,
                         headers={**HEADERS, "Accept": "application/rdap+json"})
        if r.ok:
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    try:
                        return _norm_dt(datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00")))
                    except (ValueError, KeyError):
                        pass
    except Exception:
        pass
    try:
        import whois
        v = whois.whois(domain).creation_date
        vals = [_norm_dt(x) for x in (v if isinstance(v, list) else [v])]
        vals = [x for x in vals if x]
        return min(vals) if vals else None
    except Exception:
        return None


def wayback_first(domain):
    try:
        r = requests.get("https://web.archive.org/cdx/search/cdx", timeout=TIMEOUT,
                         params={"url": domain, "limit": 1, "output": "json", "fl": "timestamp"})
        rows = r.json()
        if len(rows) > 1:
            return datetime.strptime(rows[1][0][:8], "%Y%m%d").replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def age_findings(created, wb):
    ref = created or wb
    if not ref:
        return [F("info", "Domainalter nicht ermittelbar",
                  "Bei manchen Endungen (z. B. .de) wird das Registrierdatum nicht öffentlich ausgegeben.")]
    days = (datetime.now(timezone.utc) - ref).days
    src = "Registrierung" if created else "erster Eintrag im Webarchiv"
    d = f"{src}: {ref:%d.%m.%Y} (vor {days} Tagen)"
    out = []
    if days < 30:
        out.append(F("bad", "Domain ist brandneu (< 30 Tage)", d + ". Typisch für kurzlebige Fake-Shops.", -30, crit=True))
    elif days < 180:
        out.append(F("bad", "Domain ist sehr jung (< 6 Monate)", d, -15))
    elif days < 365:
        out.append(F("warn", "Domain ist jünger als 1 Jahr", d, -5))
    elif days < 730:
        out.append(F("ok", "Domain existiert seit über 1 Jahr", d, 5))
    else:
        out.append(F("ok", "Domain existiert seit über 2 Jahren", d, 15))
    if created and wb and (created - wb).days > 365 and days < 365:
        out.append(F("warn", "Domain wurde neu registriert, hatte aber früher Inhalte",
                     f"Frühester Archiv-Eintrag {wb:%d.%m.%Y}. Gebrauchte Domains werden gern für Fake-Shops genutzt.", -5))
    return out


def ssl_check(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
            cert = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return [F("bad", "TLS-Zertifikat ungültig", e.verify_message, -20)]
    except OSError:
        return [F("bad", "Kein HTTPS erreichbar", "Seriöse Shops nutzen durchgehend HTTPS.", -20)]
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
    start = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    return [F("ok", "Gültiges TLS-Zertifikat", f"Aussteller: {issuer}, ausgestellt am {start:%d.%m.%Y}", 5)]


def safe_browsing(url):
    key = os.environ.get("GSB_API_KEY")
    if not key:
        return []
    body = {"client": {"clientId": "shopcheck", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=TIMEOUT)
    if r.json().get("matches"):
        return [F("bad", "Von Google Safe Browsing als gefährlich gemeldet", "Phishing/Malware-Treffer.", -50, crit=True)]
    return [F("ok", "Kein Treffer bei Google Safe Browsing", "", 3)]


def trustpilot(domain):
    try:
        r = requests.get(f"https://www.trustpilot.com/review/{quote(domain)}", headers=HEADERS, timeout=TIMEOUT)
    except Exception:
        return [F("info", "Trustpilot nicht abrufbar")]
    if r.status_code == 404:
        return [F("warn", "Kein Trustpilot-Profil", "Neue Shops haben oft noch keins – ein Gütesiegel ist das Fehlen aber auch nicht.")]
    if r.status_code != 200:
        return [F("info", f"Trustpilot nicht abrufbar (HTTP {r.status_code})", "Bewertungen bitte manuell prüfen (Links unten).")]
    i = r.text.find('"AggregateRating"')
    blk = r.text[max(0, i - 300): i + 400] if i >= 0 else ""
    rv, rc = re.search(r'"ratingValue"\s*:\s*"?([\d.]+)', blk), re.search(r'"reviewCount"\s*:\s*"?(\d+)', blk)
    if not (rv and rc):
        return [F("info", "Trustpilot-Profil vorhanden, Bewertung nicht auslesbar")]
    rating, count = float(rv.group(1)), int(rc.group(1))
    d = f"{rating:.1f} von 5 bei {count} Bewertungen"
    if count >= 20 and rating >= 4:
        return [F("ok", "Gute Trustpilot-Bewertung", d + " (Fake-Bewertungen sind möglich – Stichproben lesen).", 10)]
    if count >= 5 and rating < 3:
        return [F("bad", "Schlechte Trustpilot-Bewertung", d, -20)]
    if count >= 5 and rating < 3.8:
        return [F("warn", "Mäßige Trustpilot-Bewertung", d, -5)]
    return [F("info", "Wenige Trustpilot-Bewertungen", d)]


def vies(cc, num):
    try:
        j = requests.get(f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{cc}/vat/{num}",
                         headers=HEADERS, timeout=TIMEOUT).json()
    except Exception:
        return None
    if "UNAVAILABLE" in str(j.get("userError", "")).upper() or "isValid" not in j:
        return None
    return j


def _text(html):
    s = BeautifulSoup(html, "html.parser")
    for t in s(["script", "style", "noscript"]):
        t.decompose()
    return s, s.get_text(" ", strip=True)


def _page(u):
    try:
        _, st, h = fetch(u)
        return _text(h)[1] if st < 400 else None
    except Exception:
        return None


def analyze_site(url):
    out, meta = [], {"company": None}
    final, status, html = fetch(url)
    if status >= 400:
        return [F("info", f"Startseite lieferte HTTP {status}",
                  "Die Seite blockiert evtl. automatische Abfragen – Ergebnis ist eingeschränkt.")], meta
    soup, home = _text(html)
    links = {}
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        label = f"{a.get_text(' ', strip=True)} {href}".lower()
        for k, pat in LINK_PATTERNS.items():
            if k not in links and re.search(pat, label):
                links[k] = urljoin(final, href)

    imp = _page(links.get("impressum") or urljoin(final, "/impressum"))
    agb = _page(links["agb"]) if "agb" in links else None
    blob = " ".join(filter(None, [home, imp, agb]))
    low = blob.lower()

    # --- Impressum ---
    if not imp or len(imp) < 80:
        out.append(F("bad", "Kein Impressum gefunden",
                     "In DE/AT/CH und der EU ist ein Impressum mit ladungsfähiger Anschrift Pflicht.", -25))
    else:
        email = EMAIL_RE.search(imp)
        phone = PHONE_RE.search(imp)
        addr = PLZ_RE.search(imp)
        m = FORM_RE.search(imp)
        company = None
        if m:
            toks = m.group(0).split()
            while toks and (toks[0].lower() in STOP or toks[0].isdigit()):
                toks.pop(0)
            company = " ".join(toks) or None
        has_person = bool(re.search(r"inhaber|geschäftsführer|vertreten durch|managing director|verantwortlich", imp, re.I))
        meta["company"] = company
        found = [x for x, ok in (("Firma", company), ("Anschrift", addr), ("E-Mail", email), ("Telefon", phone),
                                 ("Register", REG_RE.search(imp))) if ok]
        if addr and (company or has_person) and (email or phone):
            out.append(F("ok", "Impressum vollständig wirkend", "Gefunden: " + ", ".join(found), 15))
        elif addr:
            out.append(F("warn", "Impressum unvollständig", "Gefunden: " + ", ".join(found) + ". Es fehlen z. B. Firma/Vertretungsberechtigter oder Kontakt.", -5))
        else:
            out.append(F("bad", "Impressum ohne ladungsfähige Anschrift", "Gefunden: " + (", ".join(found) or "fast nichts"), -15))
        if email and re.search(r"@(gmail|googlemail|gmx|web|outlook|hotmail|yahoo|icloud|proton|protonmail|aol)\.", email.group(0), re.I):
            out.append(F("warn", "Freemail-Adresse im Impressum", email.group(0), -3))
        if re.search(r"hong ?kong|shenzhen|guangzhou|dongguan|guangdong|china|\.cn\b", imp, re.I):
            out.append(F("warn", "Firmensitz/Kontakt in China/Hongkong", "Häufig bei Dropshipping- und Fake-Shops mit deutscher Fassade.", -10))

        # --- USt-IdNr / VIES ---
        vat = next(({"cc": g[0], "num": g[1]} for g in ([x for x in mm.groups() if x] for mm in VAT_RE.finditer(imp))), None)
        if vat:
            j = vies(vat["cc"], vat["num"])
            label = f'{vat["cc"]}{vat["num"]}'
            if j is None:
                out.append(F("info", f"USt-IdNr. {label} gefunden", "EU-Prüfdienst (VIES) war nicht erreichbar."))
            elif j.get("isValid"):
                nm = (j.get("name") or "").strip()
                d = f"{label} ist bei VIES gültig."
                if nm and nm != "---":
                    d += f" Registrierter Name: {nm}."
                    if company:
                        a = {w for w in re.findall(r"\w{3,}", nm.lower())}
                        b = {w for w in re.findall(r"\w{3,}", company.lower())}
                        if a and b and not (a & b):
                            out.append(F("warn", "Name bei VIES passt nicht zur Firma im Impressum", f"VIES: {nm} · Impressum: {company}", -10))
                out.append(F("ok", "Gültige USt-IdNr.", d, 15))
            else:
                out.append(F("bad", "USt-IdNr. im Impressum ist ungültig", f"{label} existiert laut VIES nicht – möglicherweise erfunden.", -25, crit=True))
        else:
            out.append(F("warn", "Keine USt-IdNr. im Impressum",
                         "Nur Kleinunternehmer dürfen ohne sein. Fehlt sie bei einem größeren Shop, ist das verdächtig.", -5))

    # --- Rechtstexte ---
    missing = []
    for key, label, pts in (("agb", "AGB", 4), ("datenschutz", "Datenschutzerklärung", 3)):
        if key in links:
            out.append(F("ok", f"{label} vorhanden", links[key], pts))
        else:
            missing.append(label)
            out.append(F("warn", f"{label} nicht gefunden", "", -5))
    if "widerruf" in links or re.search("widerruf", agb or "", re.I):
        out.append(F("ok", "Widerrufs-/Rückgabeinfos vorhanden", "", 4))
    else:
        out.append(F("bad", "Keine Widerrufsbelehrung gefunden", "Im EU-Onlinehandel Pflicht (14 Tage Widerruf).", -8))

    # --- Zahlungsarten ---
    safe = re.search(r"paypal|klarna|kreditkarte|credit card|visa|mastercard|apple ?pay|google ?pay|auf rechnung|stripe|sofort", low)
    risky = re.search(r"vorkasse|banküberweisung|bank transfer|bitcoin|krypto|crypto|usdt|western union|gift ?card|paysafe", low)
    if risky and not safe:
        out.append(F("bad", "Nur Vorkasse/Krypto als Zahlungsart", "Kein Käuferschutz – klassisches Fake-Shop-Muster.", -15))
    elif safe:
        out.append(F("ok", "Geschützte Zahlungsarten genannt", safe.group(0), 5))
    else:
        out.append(F("info", "Zahlungsarten nicht erkennbar", "Evtl. erst im Checkout sichtbar – dort prüfen."))

    # --- Verkaufsdruck & Lieferung ---
    hits = [p for p in URGENCY if re.search(p, home.lower())]
    if len(hits) >= 3:
        out.append(F("warn", "Viel künstlicher Zeitdruck/Rabatt-Tricks", f"{len(hits)} Muster (Countdown, „nur noch X“, 50–90 % Rabatt …).", -10))
    if re.search(r"versand aus china|ships? from china|dropship|aliexpress|temu|cj ?dropshipping", low):
        out.append(F("warn", "Hinweise auf Dropshipping/Versand aus Asien", "", -8))
    else:
        for a, b in re.findall(r"(\d{1,2})\s*(?:-|–|bis)\s*(\d{1,2})\s*(?:werktage|tage|days|business days)", low):
            if int(b) >= 14:
                out.append(F("warn", "Sehr lange Lieferzeit angegeben", f"{a}–{b} Tage – oft Direktversand aus Asien.", -8))
                break
    return out, meta


def ref_links(domain, company):
    q = quote(domain)
    L = [
        ("Google: Erfahrungen / Betrug", f"https://www.google.com/search?q={quote(domain + ' Erfahrungen Betrug')}"),
        ("Trustpilot", f"https://www.trustpilot.com/review/{q}"),
        ("ScamAdviser", f"https://www.scamadviser.com/check-website/{q}"),
        ("Fakeshop-Finder (Verbraucherzentrale)", "https://www.verbraucherzentrale.de/fakeshopfinder-71560"),
        ("Watchlist Internet (Warnungen)", "https://www.watchlist-internet.at/"),
        ("Wayback Machine", f"https://web.archive.org/web/*/{q}"),
        ("Handelsregister (DE)", "https://www.handelsregister.de/"),
    ]
    if company:
        L.append((f"OpenCorporates: {company}", f"https://opencorporates.com/companies?q={quote(company)}"))
        L.append((f"Google: {company} Erfahrungen", f"https://www.google.com/search?q={quote(company + ' Erfahrungen')}"))
    return L


def run_checks(raw):
    url, host = normalize(raw)
    if not public_host(host):
        raise ValueError("Domain nicht auflösbar oder nicht öffentlich erreichbar.")
    domain = _tld(host).registered_domain or host
    suffix = _tld(host).suffix

    with ThreadPoolExecutor(6) as ex:
        jobs = {
            "created": ex.submit(registration_date, domain),
            "wb": ex.submit(wayback_first, domain),
            "ssl": ex.submit(ssl_check, host),
            "tp": ex.submit(trustpilot, domain),
            "gsb": ex.submit(safe_browsing, url),
            "site": ex.submit(analyze_site, url),
        }
        res, err = {}, {}
        for k, j in jobs.items():
            try:
                res[k] = j.result()
            except Exception as e:
                err[k] = e

    findings, meta = [], {"company": None}
    findings += age_findings(res.get("created"), res.get("wb"))
    for k in ("ssl", "tp", "gsb"):
        if k in res:
            findings += res[k]
    if "site" in res:
        f, meta = res["site"]
        findings += f
    else:
        findings.append(F("warn", "Website nicht abrufbar", str(err.get("site", "")) or "Keine Antwort.", -5))

    if suffix in CHEAP_TLDS:
        findings.append(F("warn", f"Endung .{suffix}", "Billig-Endungen sind bei Fake-Shops überproportional häufig.", -3))
    label = domain.split(".")[0]
    if label.count("-") >= 2 or sum(c.isdigit() for c in label) >= 3:
        findings.append(F("warn", "Auffälliger Domainname", "Viele Bindestriche/Ziffern wirken oft automatisiert generiert.", -3))

    score = max(0, min(100, BASE_SCORE + sum(f["points"] for f in findings)))
    if any(f["crit"] for f in findings):
        score = min(score, 40)
    key, verdict = ("good", "Wirkt seriös") if score >= 75 else ("warn", "Unklar – Vorsicht") if score >= 50 else ("bad", "Hohes Risiko – nicht kaufen")
    return {"url": url, "domain": domain, "company": meta.get("company"), "score": score, "verdict": verdict,
            "verdict_key": key, "findings": findings, "links": ref_links(domain, meta.get("company"))}
