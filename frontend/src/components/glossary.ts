/**
 * Glossary content. Plain language; "In Threat Watch" lines describe what this app actually does
 * (keep them in step with the code: severity rules live in backend/app/intel/classify.py).
 * External links go to the official home of each standard only.
 */
export interface Term {
  id: string
  term: string
  full?: string
  group: 'vuln' | 'intel' | 'app'
  body: string
  inApp?: string
  see?: string[]
  link?: { label: string; url: string }
}

export const GROUPS: [Term['group'], string, string][] = [
  ['vuln', 'Vulnerabilities and scores', 'How flaws are named, scored and prioritised.'],
  ['intel', 'Threat intelligence', 'Who attacks, how, and how that is described.'],
  ['app', 'Threat Watch terms', 'Labels and figures used in this app.'],
]

export const TERMS: Term[] = [
  // ---------------------------------------------------------------- vulnerabilities
  { id: 'cve', term: 'CVE', full: 'Common Vulnerabilities and Exposures', group: 'vuln',
    body: 'The public naming system for software flaws. Each flaw gets one ID in the form CVE-year-number, such as CVE-2024-3400, so everyone can refer to the same issue. IDs are assigned by CVE Numbering Authorities (vendors, CERTs and others) under the CVE Program run by MITRE.',
    inApp: 'CVE IDs are pulled from every report. Each has its own page with the vendor, product, scores, KEV status and the reports that mention it.',
    see: ['cvss', 'epss', 'kev', 'nvd'], link: { label: 'cve.org', url: 'https://www.cve.org/' } },
  { id: 'cvss', term: 'CVSS', full: 'Common Vulnerability Scoring System', group: 'vuln',
    body: 'A 0 to 10 score for how severe a flaw is if exploited: how it can be reached, how hard it is to exploit, and what an attacker gains. Ratings: Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0. It describes potential impact, not whether anyone is exploiting it. Maintained by FIRST; versions 3.1 and 4.0 are in use.',
    inApp: 'Taken from the CVE record. A CVSS of 9.0 or more adds one point to a story\'s severity. Shown as "n/a" until the record has a score.',
    see: ['epss', 'kev', 'severity'], link: { label: 'first.org/cvss', url: 'https://www.first.org/cvss/' } },
  { id: 'epss', term: 'EPSS', full: 'Exploit Prediction Scoring System', group: 'vuln',
    body: 'A daily estimate of the probability that a CVE will be exploited in the wild in the next 30 days, from 0% to 100%. It is a model built from observed attack data, published by FIRST. Most CVEs score well under 1%; a few percent is already notable.',
    inApp: 'Fetched twice a day (FIRST publishes once a day). Values of 10% or more are highlighted, and 50% or more adds a severity point when the CVE is not already in KEV.',
    see: ['cvss', 'kev'], link: { label: 'first.org/epss', url: 'https://www.first.org/epss/' } },
  { id: 'kev', term: 'KEV', full: 'Known Exploited Vulnerabilities catalogue', group: 'vuln',
    body: 'A list run by CISA (the US Cybersecurity and Infrastructure Security Agency) of CVEs with reliable evidence of exploitation in real attacks, each with a required action and, for US federal agencies, a fix-by date. Entries also say whether the flaw is known to be used by ransomware. KEV is the strongest single signal of what to patch first.',
    inApp: 'Checked every two hours and complete. A KEV listing adds two severity points and an urgent "Patch now" step quoting CISA\'s action and deadline. See Breaking, Vulnerabilities (Exploited filter) and Trends.',
    see: ['cvss', 'epss', 'zero-day'], link: { label: 'CISA KEV catalogue', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' } },
  { id: 'cwe', term: 'CWE', full: 'Common Weakness Enumeration', group: 'vuln',
    body: 'A catalogue of the kinds of mistakes that cause vulnerabilities, such as CWE-79 (cross-site scripting) or CWE-787 (out-of-bounds write). A CVE is one specific flaw; a CWE is the category it belongs to.',
    inApp: 'Shown on CVE pages when CISA KEV lists them.', see: ['cve'], link: { label: 'cwe.mitre.org', url: 'https://cwe.mitre.org/' } },
  { id: 'nvd', term: 'NVD', full: 'National Vulnerability Database', group: 'vuln',
    body: 'The US government (NIST) database of CVEs, with analysis such as scores and affected product lists. It sometimes lags behind the CVE record itself.',
    inApp: 'Each CVE page links to its NVD entry.', see: ['cve', 'cvss'], link: { label: 'nvd.nist.gov', url: 'https://nvd.nist.gov/' } },
  { id: 'zero-day', term: 'Zero-day', group: 'vuln',
    body: 'A flaw attackers exploit before the vendor has released a fix, often before the vendor knows about it. Once a patch exists it is sometimes still called a zero-day in reporting, meaning it was exploited before the fix.',
    inApp: 'Mentioning a zero-day adds a severity point.', see: ['kev', 'poc'] },
  { id: 'poc', term: 'Proof of concept', full: 'PoC', group: 'vuln',
    body: 'Code or steps showing that a flaw can be exploited. A public PoC usually makes real attacks more likely soon after, but is not evidence that attacks have happened.',
    see: ['epss', 'kev'] },
  { id: 'patch-tuesday', term: 'Patch Tuesday', group: 'vuln',
    body: 'Microsoft\'s monthly security update release on the second Tuesday of each month (Wednesday morning in New Zealand). Other vendors, including Adobe and SAP, publish on the same day.',
    see: ['cve'] },
  { id: 'advisory', term: 'Vendor advisory', group: 'vuln',
    body: 'The vendor\'s own notice about a flaw: affected versions, fixed versions and workarounds. It is the primary source for what to patch.',
    inApp: 'Listed under "Further reading" on articles when the CVE record links to it.', see: ['cve'] },

  // ---------------------------------------------------------------- threat intelligence
  { id: 'threat-actor', term: 'Threat actor', group: 'intel',
    body: 'A person or group behind malicious activity. Security companies track the same group under different names, so one group can have many aliases (Turla is also Secret Blizzard and Venomous Bear).',
    inApp: 'Each known group, ransomware operation and malware family has a profile with a reporting chart, aliases and its MITRE ATT&CK entry.', see: ['apt', 'attack', 'attribution'] },
  { id: 'apt', term: 'APT', full: 'Advanced persistent threat', group: 'intel',
    body: 'A well-resourced group, usually linked to a state, that runs long-term intrusions for espionage or disruption. Numbered names like APT28 come from security vendors.',
    see: ['threat-actor', 'attribution'] },
  { id: 'raas', term: 'Ransomware-as-a-service', full: 'RaaS', group: 'intel',
    body: 'A model where a ransomware group supplies the malware and infrastructure and "affiliates" carry out the break-ins for a share of the ransom. One brand can therefore show many different intrusion styles.',
    see: ['threat-actor'] },
  { id: 'leak-site', term: 'Leak site', full: 'Data leak site (DLS)', group: 'intel',
    body: 'A website, usually on Tor, where a ransomware group names organisations it says it has breached and threatens to publish their data unless they pay. Posts are a pressure tactic: groups exaggerate, re-post old or other groups\' victims, and sometimes list organisations they never breached.',
    inApp: 'The Ransomware page and group profiles count leak-site claims collected by ransomware.live. Threat Watch never links to the leak sites themselves, only to the tracker\'s record.', see: ['leak-site-claim', 'raas'] },
  { id: 'leak-site-claim', term: 'Leak-site claim', group: 'intel',
    body: 'One victim posted on a ransomware leak site. A claim is the group\'s own statement, not a confirmed compromise; the victim may deny it or never have been breached.',
    inApp: 'Counted by the date the tracker first saw the post. A claim links to Threat Watch reporting only when a collected story names the victim, which is the closest thing to independent confirmation the app has.',
    see: ['leak-site'] },
  { id: 'ioc', term: 'IOC', full: 'Indicator of compromise', group: 'intel',
    body: 'A concrete artefact of an attack you can search for: IP addresses, domains, URLs and file hashes. Useful for hunting, but short-lived: attackers change infrastructure often.',
    inApp: 'Extracted from source text and "refanged" (hxxp and [.] turned back into usable form) so they can be copied into tools. Handle with care.', see: ['ttp'] },
  { id: 'ttp', term: 'TTPs', full: 'Tactics, techniques and procedures', group: 'intel',
    body: 'How an attacker operates: their goals (tactics), methods (techniques) and specific ways of doing them (procedures). Behaviour changes more slowly than IOCs, so detections built on TTPs last longer.',
    see: ['attack', 'ioc'] },
  { id: 'attack', term: 'MITRE ATT&CK', group: 'intel',
    body: 'A public knowledge base of attacker behaviour. Techniques have IDs like T1566 (Phishing), groups like G0010 (Turla) and software like S0002 (Mimikatz), each with documented examples and sources.',
    inApp: 'Synced weekly from MITRE. Group profiles show MITRE\'s description and the reports it cites; technique IDs link to MITRE. Techniques marked "keyword-inferred" were matched from wording, not stated by the source.',
    see: ['ttp', 'threat-actor'], link: { label: 'attack.mitre.org', url: 'https://attack.mitre.org/' } },
  { id: 'attribution', term: 'Attribution', group: 'intel',
    body: 'Saying who is responsible for an attack. It is a judgement with varying confidence, and vendors often disagree. Two names appearing in the same story is not attribution.',
    inApp: '"Reported alongside" on group profiles is co-occurrence only.', see: ['threat-actor'] },
  { id: 'dfir', term: 'DFIR', full: 'Digital forensics and incident response', group: 'intel',
    body: 'Investigating and handling an intrusion: collecting evidence, working out what happened, containing it and recovering. The SOC & DFIR section collects detection and investigation content.',
    see: ['soc'] },
  { id: 'soc', term: 'SOC', full: 'Security operations centre', group: 'intel',
    body: 'The team that monitors for attacks, triages alerts and responds. "What to do" steps in Threat Watch are written for a SOC.',
    see: ['dfir', 'playbook'] },

  // ---------------------------------------------------------------- Threat Watch terms
  { id: 'severity', term: 'Severity', group: 'app',
    body: 'Threat Watch\'s rating of a story: info, low, medium, high or critical. It is a points system applied to the source text. Every story starts at low, then gains points for a CISA KEV listing (two), reported active exploitation (one or two), scanning or exploitation attempts, a zero-day, CVSS 9.0 or more, EPSS of 50% or more, emergency wording in the headline, an incident at an organisation (and again for large-scale impact), and an official advisory. Roundups and podcasts lose a point, and some sources such as release notes are capped.',
    inApp: 'Select any severity label to see the reasons for that story.', see: ['confidence', 'kev', 'cvss', 'epss'] },
  { id: 'confidence', term: 'Confidence', group: 'app',
    body: 'How well-sourced a story is. Official source: published by a government CERT, CISA or the vendor. Corroborated: three or more independent sources. 2 sources: two independent sources. Single source: only one so far; treat details as provisional.',
    see: ['severity', 'story'] },
  { id: 'story', term: 'Story', group: 'app',
    body: 'Several articles about the same event, grouped so it counts once. Grouping uses shared CVEs, names and similar headlines within a few days; articles from the same publisher are never grouped together.',
    inApp: 'Counts on Trends and group profiles are stories, not articles. "+2 sources" on a card means two more outlets covered the same story.', see: ['share'] },
  { id: 'roundup', term: 'Roundup', group: 'app',
    body: 'A newsletter, weekly digest or podcast that covers many unrelated items. Useful context, but a name appearing in one says little about that subject.',
    inApp: 'Roundups lose a severity point, never count as important updates to things you follow, and are left out of group counts.', see: ['severity', 'follow'] },
  { id: 'follow', term: 'Follow and bookmark', group: 'app',
    body: 'Bookmark saves one article, with a private note. Follow tracks a subject (an incident, CVE, actor, malware family or topic): new reports are matched to it automatically, its record is versioned, and you are told about important changes.',
    see: ['review-queue', 'significance'] },
  { id: 'review-queue', term: 'Review queue', group: 'app',
    body: 'Reports that partly match something you follow, such as the same actor in a different incident, wait for you to decide. Nothing is linked on a guess.',
    see: ['follow'] },
  { id: 'significance', term: 'Important, adds detail, little new', group: 'app',
    body: 'How much a new report changes a followed item. Important: exploitation reported alongside the subject, a CISA KEV listing, or a first official source; also new names stated alongside the subject in a high-severity, single-subject report. Adds detail: new names stated alongside the subject, or a new independent source. Little new: a passing mention or a roundup. Repeat coverage: the same story again. Names elsewhere in a broad bulletin are not counted as changes.',
    see: ['follow', 'roundup'] },
  { id: 'playbook', term: 'Evidence-backed and playbook steps', group: 'app',
    body: '"What to do" steps come in two kinds. Backed by the evidence: stated by the source, the CVE record or CISA KEV. Standard practice (playbook): general advice for that kind of threat, not a claim about the incident.',
    see: ['soc', 'kev'] },
  { id: 'share', term: 'Share of stories', group: 'app',
    body: 'A subject\'s stories as a percentage of all stories in the period. Rising and falling use share rather than raw counts, so a busier collection period does not make everything look like it is rising.',
    see: ['story', 'backlog'] },
  { id: 'backlog', term: 'Incomplete period', group: 'app',
    body: 'Feeds only list their newest items, so stories dated before collection began came from whatever each feed still held and are under-counted. Charts shade these periods, and comparisons that depend on them are marked indicative.',
    see: ['share'] },
  { id: 'date-check', term: 'Date check', group: 'app',
    body: 'Shown when a story\'s dates disagree: a title that names a later month than its publication date, a specific date more than two days off, or a date in the future. The publisher\'s title is never changed; check the source.',
    see: ['story'] },
]
