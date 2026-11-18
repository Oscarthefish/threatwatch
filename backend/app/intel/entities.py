"""Rule-based threat entity extraction.

Deterministic extraction of CVEs, ATT&CK technique IDs, known actors, malware
and ransomware families, vendors/products, regions and defanged IOCs. AI
extraction (optional) supplements this, but AI-proposed entities are only kept
when the value literally occurs in the article text (see ``grounded``).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# ---------------------------------------------------------------- dictionaries
# canonical name -> aliases (matching is case-insensitive, word-bounded)
ACTORS: dict[str, list[str]] = {
    "APT28": ["Fancy Bear", "Forest Blizzard", "Sofacy", "STRONTIUM", "Sednit", "UAC-0001"],
    "APT29": ["Cozy Bear", "Midnight Blizzard", "NOBELIUM", "The Dukes", "UNC2452"],
    "Sandworm": ["Seashell Blizzard", "APT44", "Voodoo Bear", "IRIDIUM"],
    "Turla": ["Secret Blizzard", "Venomous Bear", "Snake"],
    "Lazarus Group": ["Lazarus", "Diamond Sleet", "Hidden Cobra", "ZINC"],
    "Kimsuky": ["Emerald Sleet", "APT43", "Velvet Chollima"],
    "Andariel": ["Onyx Sleet", "APT45"],
    "APT41": ["Brass Typhoon", "Wicked Panda", "Winnti", "Double Dragon"],
    "APT40": ["Gingham Typhoon", "Leviathan", "Kryptonite Panda"],
    "Volt Typhoon": ["Vanguard Panda", "BRONZE SILHOUETTE", "Insidious Taurus"],
    "Salt Typhoon": ["GhostEmperor", "FamousSparrow", "Earth Estries", "UNC2286"],
    "Silk Typhoon": ["Hafnium"],
    "Flax Typhoon": ["Ethereal Panda"],
    "Linen Typhoon": ["APT27", "Emissary Panda"],
    "Violet Typhoon": ["APT31", "Zirconium", "Judgment Panda"],
    "Mustang Panda": ["Twill Typhoon", "TA416", "RedDelta", "Earth Preta"],
    "UNC5221": [],
    "UNC3886": [],
    "Storm-0558": [],
    "APT35": ["Charming Kitten", "Mint Sandstorm", "Phosphorus"],
    "APT33": ["Peach Sandstorm", "Elfin"],
    "MuddyWater": ["Mango Sandstorm", "Static Kitten", "Seedworm"],
    "CyberAv3ngers": [],
    "Scattered Spider": ["UNC3944", "Octo Tempest", "0ktapus", "Scatter Swine"],
    "ShinyHunters": ["UNC6040"],
    "Lapsus$": ["LAPSUS$", "DEV-0537", "Strawberry Tempest"],
    "FIN7": ["Carbanak", "Sangria Tempest"],
    "FIN8": [],
    "TA505": ["Lace Tempest"],
    "TA577": [],
    "Evil Corp": ["Indrik Spider", "Manatee Tempest"],
    "Wizard Spider": ["Periwinkle Tempest"],
    "Storm-1175": [],
    "Gamaredon": ["Aqua Blizzard", "Primitive Bear", "Shuckworm"],
    "Star Blizzard": ["Callisto", "COLDRIVER", "SEABORGIUM"],
    "OilRig": ["APT34", "Hazel Sandstorm", "Helix Kitten"],
    "Sidewinder": ["Rattlesnake"],
    "Transparent Tribe": ["APT36"],
    "Famous Chollima": ["UNC5267"],
    "TraderTraitor": ["Jade Sleet", "UNC4899"],
    "Void Blizzard": ["Laundry Bear"],
    "UNC6395": [],
    "Crimson Collective": [],
}

RANSOMWARE: dict[str, list[str]] = {
    "LockBit": ["LockBit 3.0", "LockBit Black"],
    "ALPHV": ["BlackCat", "Noberus"],
    "Cl0p": ["Clop"],
    "Akira": [],
    "Play": ["PlayCrypt"],
    "Black Basta": [],
    "Qilin": ["Agenda"],
    "RansomHub": [],
    "Medusa": [],
    "MedusaLocker": [],  # a separate, older family; not an alias of Medusa
    "Rhysida": [],
    "BianLian": [],
    "8Base": [],
    "Hunters International": [],
    "INC Ransom": ["INC ransomware", "Lynx"],
    "Interlock": [],
    "SafePay": [],
    "DragonForce": [],
    "Fog": [],
    "BlackSuit": ["Royal"],
    "Conti": [],
    "Ryuk": [],
    "Hive": [],
    "Babuk": [],
    "Cactus": [],
    "Embargo": [],
    "Gunra": [],
    "Warlock": [],
    "Kraken": [],
    "Chaos": [],
    "Sinobi": [],
    "The Gentlemen": [],
    "Rapture": [],
    "Termite": [],
    "Hellcat": [],
    "Nova": [],
    "Everest": [],
    "Cicada3301": [],
    "Mallox": ["TargetCompany"],
    "Phobos": [],
    "Scattered LAPSUS$ Hunters": [],
}

MALWARE: dict[str, list[str]] = {
    "Cobalt Strike": [],
    "Sliver": [],
    "Brute Ratel": ["BRc4"],
    "Havoc": [],
    "Mythic": [],
    "Emotet": [],
    "QakBot": ["Qbot", "Pinkslipbot"],
    "IcedID": ["BokBot"],
    "Bumblebee": [],
    "Latrodectus": [],
    "Pikabot": [],
    "DarkGate": [],
    "SocGholish": ["FakeUpdates"],
    "Raspberry Robin": [],
    "Gootloader": [],
    "SystemBC": [],
    "Lumma Stealer": ["LummaC2", "Lumma"],
    "RedLine Stealer": ["RedLine"],
    "Remus Stealer": ["Remus"],
    "Vidar": [],
    "StealC": [],
    "Rhadamanthys": [],
    "Atomic Stealer": ["AMOS"],
    "Agent Tesla": ["AgentTesla"],
    "FormBook": ["XLoader"],
    "AsyncRAT": [],
    "Remcos": ["Remcos RAT"],
    "njRAT": ["Bladabindi"],
    "XWorm": [],
    "QuasarRAT": ["Quasar RAT"],
    "NetSupport RAT": ["NetSupport Manager RAT"],
    "PlugX": ["Korplug"],
    "ShadowPad": [],
    "BRICKSTORM": [],
    "Mirai": [],
    "Glupteba": [],
    "Snake Keylogger": [],
    "SmokeLoader": [],
    "Danabot": ["DanaBot"],
    "TrickBot": [],
    "Ursnif": ["Gozi", "ISFB"],
    "Prometei": [],
    "XMRig": [],
    "Shai-Hulud": [],
    "ClickFix": [],
    "Mimikatz": [],
    "Impacket": [],
    "AdaptixC2": [],
    "Pegasus": [],
    "Predator": [],
}

VENDORS: dict[str, list[str]] = {
    "Microsoft": ["Windows", "Exchange Server", "SharePoint", "Microsoft 365", "Azure", "Entra ID", "Outlook"],
    "Fortinet": ["FortiOS", "FortiGate", "FortiWeb", "FortiManager", "FortiClient", "FortiSIEM", "FortiProxy"],
    "Ivanti": ["Connect Secure", "Pulse Secure", "EPMM", "Ivanti EPM"],
    "Cisco": ["Cisco IOS", "IOS XE", "ASA", "Firepower", "ISE", "Cisco Webex"],
    "Palo Alto Networks": ["PAN-OS", "GlobalProtect", "Cortex XDR"],
    "Citrix": ["NetScaler", "Citrix ADC", "Citrix Gateway"],
    "VMware": ["ESXi", "vCenter", "Broadcom VMware", "Workspace ONE"],
    "Atlassian": ["Confluence", "Jira", "Bitbucket"],
    "Apple": ["iOS", "macOS", "iPadOS", "Safari", "WebKit"],
    "Google": ["Chrome", "Android", "Chromium", "Pixel"],
    "Oracle": ["E-Business Suite", "WebLogic", "Oracle Cloud"],
    "SAP": ["NetWeaver", "SAP S/4HANA"],
    "SonicWall": ["SonicOS", "SMA 100"],
    "Juniper": ["Junos"],
    "F5": ["BIG-IP"],
    "Progress Software": ["MOVEit", "WS_FTP", "Telerik"],
    "WordPress": [],
    "Linux": ["Linux kernel"],
    "OpenSSH": [],
    "Veeam": [],
    "Zimbra": [],
    "Check Point": [],
    "WatchGuard": ["Firebox"],
    "Zyxel": [],
    "D-Link": [],
    "TP-Link": [],
    "CrushFTP": [],
    "Cleo": [],
    "Commvault": [],
    "SolarWinds": ["Serv-U", "Web Help Desk"],
    "ConnectWise": ["ScreenConnect"],
    "Kaseya": [],
    "Okta": [],
    "Salesforce": [],
    "Snowflake": [],
    "GitHub": [],
    "npm": [],
    "PyPI": [],
    "Mozilla": ["Firefox", "Thunderbird"],
    "Adobe": ["ColdFusion", "Acrobat", "Adobe Commerce", "Magento"],
    "Samsung": [],
    "Qualcomm": [],
    "SimpleHelp": [],
    "Gladinet": [],
    "BeyondTrust": [],
    "Sitecore": [],
    "Craft CMS": [],
    "Erlang/OTP": [],
    "7-Zip": [],
    "WinRAR": [],
    "Docker": [],
    "Kubernetes": [],
    "Jenkins": [],
    "GitLab": [],
}

# A compact ATT&CK reference for display names (technique IDs found in text are
# always kept; names are shown when known).
ATTACK: dict[str, str] = {
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment", "T1566.002": "Spearphishing Link",
    "T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services", "T1078": "Valid Accounts",
    "T1189": "Drive-by Compromise", "T1195": "Supply Chain Compromise", "T1199": "Trusted Relationship",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1204": "User Execution", "T1204.002": "Malicious File", "T1053": "Scheduled Task/Job", "T1053.005": "Scheduled Task",
    "T1047": "Windows Management Instrumentation", "T1569.002": "Service Execution",
    "T1547": "Boot or Logon Autostart Execution", "T1547.001": "Registry Run Keys / Startup Folder",
    "T1543.003": "Windows Service", "T1136": "Create Account", "T1505.003": "Web Shell", "T1098": "Account Manipulation",
    "T1068": "Exploitation for Privilege Escalation", "T1055": "Process Injection", "T1548": "Abuse Elevation Control Mechanism",
    "T1562": "Impair Defenses", "T1562.001": "Disable or Modify Tools", "T1070": "Indicator Removal",
    "T1070.001": "Clear Windows Event Logs", "T1027": "Obfuscated Files or Information", "T1218": "System Binary Proxy Execution",
    "T1036": "Masquerading", "T1112": "Modify Registry", "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory",
    "T1003.006": "DCSync", "T1110": "Brute Force", "T1110.003": "Password Spraying", "T1555": "Credentials from Password Stores",
    "T1558.003": "Kerberoasting", "T1621": "Multi-Factor Authentication Request Generation", "T1539": "Steal Web Session Cookie",
    "T1087": "Account Discovery", "T1482": "Domain Trust Discovery", "T1018": "Remote System Discovery",
    "T1046": "Network Service Discovery", "T1083": "File and Directory Discovery", "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol", "T1021.002": "SMB/Windows Admin Shares", "T1021.006": "Windows Remote Management",
    "T1570": "Lateral Tool Transfer", "T1219": "Remote Access Software", "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols", "T1572": "Protocol Tunneling", "T1090": "Proxy", "T1105": "Ingress Tool Transfer",
    "T1567": "Exfiltration Over Web Service", "T1567.002": "Exfiltration to Cloud Storage", "T1041": "Exfiltration Over C2 Channel",
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery", "T1489": "Service Stop", "T1485": "Data Destruction",
    "T1657": "Financial Theft", "T1560": "Archive Collected Data", "T1114": "Email Collection", "T1530": "Data from Cloud Storage",
}

# Keyword -> technique, clearly labelled "keyword-inferred" in the UI.
ATTACK_KEYWORDS: list[tuple[str, str]] = [
    (r"\bspear-?phishing\b|\bphishing\b", "T1566"),
    (r"\bpassword spray(ing)?\b", "T1110.003"),
    (r"\bbrute[- ]forc(e|ing)\b", "T1110"),
    (r"\bweb ?shells?\b", "T1505.003"),
    (r"\bcredential dumping\b|\blsass\b|\bmimikatz\b", "T1003"),
    (r"\bkerberoast(ing)?\b", "T1558.003"),
    (r"\bdcsync\b", "T1003.006"),
    (r"\bmfa (fatigue|bombing)\b|\bpush bombing\b", "T1621"),
    (r"\bsupply[- ]chain (attack|compromise)\b", "T1195"),
    (r"\bremote desktop protocol\b|\bRDP\b", "T1021.001"),
    (r"\b(remote (monitoring and management|access) (tools?|software)|RMM tools?|AnyDesk|ScreenConnect)\b", "T1219"),
    (r"\bpowershell\b", "T1059.001"),
    (r"\bscheduled tasks?\b", "T1053.005"),
    (r"\bexfiltrat(e|ed|ion)\b", "T1041"),
    (r"\bencrypt(ed|s|ing)? (files|systems|servers|data)\b", "T1486"),
    (r"\bshadow cop(y|ies)\b", "T1490"),
    (r"\bsession (cookie|token)s? (theft|stolen|hijack)", "T1539"),
    (r"\bexploit(ed|ing|ation)? (of )?(a |an )?(public-facing|internet-facing|edge)\b", "T1190"),
    (r"\bvalid accounts\b|\bstolen credentials\b|\bcompromised credentials\b", "T1078"),
    (r"\bclickfix\b|\bfake captcha\b", "T1204"),
    (r"\bdll side-?loading\b", "T1574.002"),
    (r"\bliving[- ]off[- ]the[- ]land\b|\bLOLBins?\b", "T1218"),
]
ATTACK.setdefault("T1574.002", "DLL Side-Loading")

REGIONS: dict[str, list[str]] = {
    "NZ": ["New Zealand", "Aotearoa", "NZ", "Auckland", "Wellington", "Christchurch", "Kiwi", "NCSC NZ", "CERT NZ", "Te Whatu Ora"],
    "AU": ["Australia", "Australian", "Sydney", "Melbourne", "Canberra", "Brisbane", "Perth", "ASD", "ACSC", "OAIC"],
    "APAC": ["Asia-Pacific", "APAC", "Singapore", "Japan", "Japanese", "South Korea", "Korean", "Taiwan", "Taiwanese",
             "Philippines", "Indonesia", "Malaysia", "Vietnam", "Thailand", "India", "Indian", "Hong Kong",
             "Pacific Islands", "Fiji", "Samoa", "Tonga", "Papua New Guinea", "Five Eyes"],
}

# --------------------------------------------------------------------- regexes
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
TECH_RE = re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
IPV4_RE = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\[\.\]|\.)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\[\.\]|\.)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\[\.\]|\.)(?:25[0-5]|2[0-4]\d|1?\d?\d))\b")
DEFANGED_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\[\.\]|\(\.\)|\[dot\]))+(?:[a-z0-9\-]+\.)*[a-z]{2,24})\b", re.I)
DEFANGED_URL_RE = re.compile(r"\bhxxps?\[?:\]?//[^\s\"'<>]+", re.I)


@dataclass(frozen=True)
class Entity:
    type: str
    value: str
    normalized: str
    in_title: bool = False


def _compile_dict(d: dict[str, list[str]]) -> list[tuple[re.Pattern, str]]:
    out = []
    for canon, aliases in d.items():
        names = sorted({canon, *aliases}, key=len, reverse=True)
        pat = "|".join(re.escape(n) for n in names)
        # Names are proper nouns: match case-sensitively to avoid common-word noise ("Play", "Progress").
        out.append((re.compile(rf"(?<![\w$-])(?:{pat})(?![\w-])"), canon))
    return out


_ACTOR_P = _compile_dict(ACTORS)
_RANSOM_P = _compile_dict(RANSOMWARE)
_MALWARE_P = _compile_dict(MALWARE)
_VENDOR_P = [(re.compile(rf"(?<![\w-])(?:{re.escape(v)})(?![\w-])"), v) for v in VENDORS]
_PRODUCT_P = [
    (re.compile(rf"(?<![\w-]){re.escape(p)}(?![\w-])"), p, v)
    for v, ps in VENDORS.items() for p in ps
]
_REGION_P = [(re.compile(rf"(?<![\w-])(?:{'|'.join(re.escape(n) for n in names)})(?![\w-])"), r) for r, names in REGIONS.items()]
_ATTACK_KW = [(re.compile(p, re.I), t) for p, t in ATTACK_KEYWORDS]

# Ambiguous family names that are common English words need a qualifier nearby.
_NEEDS_QUALIFIER = {"Play", "Fog", "Hive", "Chaos", "Nova", "Embargo", "Kraken", "Medusa", "Cactus", "Interlock",
                    "Termite", "Rapture", "Everest", "Snake", "Predator", "Pegasus", "Mythic", "Havoc", "Sliver",
                    "Agenda", "Royal", "Lynx", "Warlock", "Phobos", "Sinobi", "Lazarus", "Remus"}
_QUALIFIER = re.compile(r"ransomware|gang|operators?|affiliates?|malware|spyware|threat actor|group|hackers?|c2|framework|apt|botnet|stealer|loader|backdoor", re.I)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def refang(s: str) -> str:
    return s.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("hxxp", "http").replace("[:]", ":")


def _public_ip(s: str) -> bool:
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def _qualified(text: str, m: re.Match, name: str) -> bool:
    if name not in _NEEDS_QUALIFIER and m.group(0) not in _NEEDS_QUALIFIER:
        return True
    window = text[max(0, m.start() - 60): m.end() + 60]
    return bool(_QUALIFIER.search(window))


def extract(title: str, body: str) -> list[Entity]:
    text = f"{title}\n{body}"
    found: dict[tuple[str, str], Entity] = {}

    def add(t: str, value: str, normalized: str | None = None):
        n = normalized or _norm(value)
        key = (t, n)
        in_title = value.lower() in title.lower() or (normalized or "").lower() in title.lower()
        if key not in found or (in_title and not found[key].in_title):
            found[key] = Entity(t, value, n, in_title)

    for m in CVE_RE.finditer(text):
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        add("cve", cve, cve.lower())
    for m in TECH_RE.finditer(text):
        add("attack_technique", m.group(1), m.group(1).lower())
    for pat, tid in _ATTACK_KW:
        if pat.search(text):
            add("attack_technique_inferred", tid, tid.lower())
    for pats, typ in ((_ACTOR_P, "actor"), (_RANSOM_P, "ransomware"), (_MALWARE_P, "malware")):
        for pat, canon in pats:
            m = pat.search(text)
            if m and _qualified(text, m, canon):
                add(typ, canon)
    for pat, v in _VENDOR_P:
        if pat.search(text):
            add("vendor", v)
    for pat, p, v in _PRODUCT_P:
        if pat.search(text):
            add("product", p if p.lower().startswith(v.lower()) else f"{v} {p}" if len(p) <= 4 else p)
    for pat, r in _REGION_P:
        if pat.search(text):
            add("region", r, r.lower())

    # IOCs — hashes and public IPs anywhere; domains/URLs only when defanged
    # (plain domains in prose are overwhelmingly benign references).
    for m in SHA256_RE.finditer(body):
        add("sha256", m.group(0).lower())
    for m in SHA1_RE.finditer(body):
        if not SHA256_RE.search(body[max(0, m.start() - 24): m.end() + 24]):
            add("sha1", m.group(0).lower())
    for m in MD5_RE.finditer(body):
        ctx = body[max(0, m.start() - 40): m.end() + 40]
        if not SHA1_RE.search(ctx) and not SHA256_RE.search(ctx):
            add("md5", m.group(0).lower())
    for m in IPV4_RE.finditer(body):
        ip = refang(m.group(1))
        if _public_ip(ip) and ("[.]" in m.group(1) or re.search(r"\b(IOC|indicator|C2|C&C|command and control|IP address|scanning|attacker)", body[max(0, m.start() - 200): m.end() + 80], re.I)):
            add("ipv4", ip, ip)
    for m in DEFANGED_DOMAIN_RE.finditer(body):
        d = refang(m.group(1)).lower()
        if "." in d:
            add("domain", d, d)
    for m in DEFANGED_URL_RE.finditer(body):
        add("url", refang(m.group(0)), refang(m.group(0)).lower())

    return list(found.values())


def grounded(value: str, text: str) -> bool:
    """True when an AI-proposed entity value appears verbatim (case-insensitive) in the source text."""
    v = value.strip()
    if len(v) < 3:
        return False
    return v.lower() in text.lower() or refang(v).lower() in refang(text).lower()


def technique_name(tid: str) -> str | None:
    return ATTACK.get(tid.upper())


IOC_TYPES = {"sha256", "sha1", "md5", "ipv4", "domain", "url"}
