import { navigate } from "~/router";

const FAQ_SECTIONS: { heading: string; items: { q: string; a: string }[] }[] = [
  {
    heading: "About the product",
    items: [
      {
        q: "What does Am I Being Pwned do?",
        a: "We continuously audit browser extensions across your entire device fleet. Every extension is scored for risk using a combination of static analysis, LLM-assisted behavioural review, and human expert verification, giving you a clear, evidence-based picture of your exposure before an incident occurs.",
      },
      {
        q: "How is this different from Chrome Web Store's built-in review?",
        a: "The Web Store screens extensions against known malware signatures. It does not audit for covert data exfiltration, session hijacking, code injection, network tampering, or exploitable CVEs in extension dependencies. We do. Many of the extensions we have flagged were and remain -available on the Web Store.",
      },
      {
        q: "What types of risk do you identify?",
        a: "We cover five categories: data harvesting (covert upload of browsing history, keystrokes, and form data), session hijacking (theft of auth tokens and cookies), code injection (arbitrary JavaScript execution on visited pages), network tampering (traffic proxying and request modification), and known CVEs in extension code. Every category is based on real findings from live Chrome Web Store extensions.",
      },
      {
        q: "How accurate are the findings?",
        a: "Critical and High severity findings are reviewed by our security researchers before publication. Medium findings are AI-assisted and are clearly labelled as such in every report. Where we have made a mistake, we correct it promptly contact hello@amibeingpwned.com.",
      },
    ],
  },
  {
    heading: "Data privacy & security",
    items: [
      {
        q: "What data does the scan collect?",
        a: "Only extension IDs and metadata such as the version installed. No browsing history, page content, credentials, or personally identifiable information is ever collected or transmitted.",
      },
      {
        q: "Does the partial scan on your homepage send data to your servers?",
        a: "No. The homepage scan runs entirely in the browser via a service worker. Nothing is transmitted to our servers. It checks the extensions installed in your current browser against a locally-loaded snapshot of our database.",
      },
      {
        q: "What data does the enterprise product collect?",
        a: "Extension inventory data only: extension IDs, versions, and declared permissions, attributed to a device identifier you control. This is the minimum required to match extensions against our risk intelligence database.",
      },
      {
        q: "Where is data stored, and what certifications do you hold?",
        a: "Data is processed and stored in the EU. If you have specific data residency or compliance requirements, contact us and we will work through them with you.",
      },
    ],
  },
  {
    heading: "Deployment & IT",
    items: [
      {
        q: "How long does it take to get started?",
        a: "Most customers have their first fleet-wide report within 48 hours of signing. There are no infrastructure changes, no firewall rules to update, and no agents to install on servers.",
      },
      {
        q: "How does fleet-wide monitoring work?",
        a: "We provide a lightweight Chrome extension that inventories installed extensions on each managed device and reports back to your dashboard. It is deployed via Google Admin Console, Microsoft Intune, Jamf, or any MDM platform that supports Chrome policy -the same way you push any other managed extension.",
      },
      {
        q: "Do employees need to install or configure anything?",
        a: "No. The extension is deployed silently by IT and runs in the background with no user-facing interface. Employees are unaffected.",
      },
      {
        q: "What happens when a new risky extension is detected?",
        a: "You receive a real-time alert via the dashboard and optionally by email or webhook. The alert includes the affected device, the extension, the specific risk category, and our recommended action. You can also configure automated block policies through your MDM to prevent high-risk extensions from running.",
      },
    ],
  },
  {
    heading: "Compliance & reporting",
    items: [
      {
        q: "What does an audit report include?",
        a: "Each report contains a risk-scored extension inventory, evidence of the specific malicious or risky behaviour observed, CVE references where applicable, recommended remediation steps, and an executive summary written for non-technical stakeholders. Reports are exportable as PDF.",
      },
      {
        q: "Can reports be used as evidence for procurement or legal review?",
        a: "Yes. Reports are designed to be shared with security, legal, and procurement teams. They include our methodology, confidence levels for each finding, and references to underlying technical evidence.",
      },
      {
        q: "Which compliance frameworks do your reports support?",
        a: "Our findings map to CIS Controls v8, ISO 27001 Annex A, and common SOC 2 Trust Services Criteria. Framework-specific exports are available on request.",
      },
      {
        q: "How current is the risk intelligence?",
        a: "Our database is updated continuously. Enterprise customers receive weekly digest reports and real-time alerts whenever a new Critical or High severity finding is identified across their fleet.",
      },
    ],
  },
  {
    heading: "Pricing & ROI",
    items: [
      {
        q: "What is included in the free tier?",
        a: "A one-time scan of the extensions installed in your current browser, checked against our database of analysed extensions. It is a useful first look -but it is not a substitute for continuous, fleet-wide monitoring.",
      },
      {
        q: "How is enterprise pricing calculated?",
        a: "Pricing is based on fleet size -the number of managed devices under monitoring. We work with teams of all sizes. Contact us at hello@amibeingpwned.com or book a demo for a tailored quote.",
      },
      {
        q: "Is there a trial period?",
        a: "Yes. Enterprise customers can trial full fleet monitoring for 14 days at no cost, with no obligation.",
      },
      {
        q: "Why not build this capability in-house?",
        a: "Deep extension analysis requires dedicated security researchers, static analysis tooling, continuous database maintenance, and the ability to keep pace with a constantly-evolving threat landscape. Our service delivers broader coverage -updated daily -at a fraction of the cost and time of an equivalent internal programme. Most customers break even within the first quarter.",
      },
    ],
  },
  {
    heading: "Other",
    items: [
      {
        q: "Is Am I Being Pwned affiliated with HaveIBeenPwned?",
        a: "No. Am I Being Pwned? is an independent product. Troy Hunt (founder of HaveIBeenPwned) has confirmed he has no objection to the name.",
      },
      {
        q: "I have found an error in a report -how do I get it corrected?",
        a: "Email hello@amibeingpwned.com with the extension name and the specific finding you believe is inaccurate. We take accuracy seriously and aim to respond within one business day.",
      },
      {
        q: "I am an extension developer and my extension appears on this site.",
        a: "If you believe a finding is incorrect, contact hello@amibeingpwned.com with supporting details and we will review it promptly. If we have inadvertently disclosed an unpatched vulnerability, email vulnerabilities@amibeingpwned.com immediately -we will unpublish the entry to give you time to issue a fix.",
      },
    ],
  },
];

export function FaqPage() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-24">
      <a
        href="/"
        onClick={(e) => {
          e.preventDefault();
          navigate("/");
        }}
        className="text-muted-foreground hover:text-foreground mb-8 inline-block text-sm"
      >
        &larr; Back to home
      </a>
      <h1 className="text-foreground mb-2 text-4xl font-bold tracking-tight">
        Frequently Asked Questions
      </h1>
      <p className="text-muted-foreground mb-12 text-lg">
        Everything you need to know about Am I Being Pwned.
      </p>

      {FAQ_SECTIONS.map((section, si) => (
        <div key={section.heading}>
          <div className={si !== 0 ? "border-border mt-16 border-t pt-16" : ""}>
            <p className="text-primary mb-10 text-xs font-semibold tracking-widest uppercase">
              {section.heading}
            </p>
            <div className="space-y-10">
              {section.items.map((item) => (
                <div key={item.q}>
                  <h2 className="text-foreground mb-2 text-lg font-semibold">
                    {item.q}
                  </h2>
                  <p className="text-muted-foreground leading-relaxed">
                    {item.a}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      ))}
    </main>
  );
}
