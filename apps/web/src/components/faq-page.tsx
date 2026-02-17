import { navigate } from "~/router";

const FAQ_ITEMS: { q: string; a: string }[] = [
  {
    q: "Why does this exist?",
    a: "I had some free time on my hands and decided to take a closer look at my extensions I had installed and saw some questionable practices, so then I decided to scrape and process as many extensions as I could, speeding up the job with static analysis tools and AI, letting me discover hundreds of concerning or outright malicious extensions. This is not acceptable.",
  },
  {
    q: "What should I do if I see an extension I have installed on the list?",
    a: "I'd recommend you disable it if you don't absolutely need it. These reports are AI generated and can contain inaccuracies, but if the AI is warning you, it's likely for a good reason. Manually confirmed malicious extensions will be labeled soon.",
  },
  {
    q: "I've spotted a mistake, how can I get it corrected?",
    a: "Email help@amibeingpwned.com and we'll get it sorted as soon as possible",
  },
  {
    q: "I don't like my extension being on this site, how can I take it down?",
    a: "If we've made a mistake in our labelling then feel free to reach out. If your extension is vulnerable, and I've accidentally published vulnerabilities, please let me know ASAP at vulnerabilities@amibeingpwned.com and we'll take it down to give you time to fix it. If you're hosting a malicious extension then we will keep the up and you can reach out after you have updated it.",
  },
  {
    q: "Are the Chrome Web Store doing anything about this?",
    a: "It's early days but they seem receptive, although a lot of these malicious and vulnerable extensions should have never made it to the store, they hundreds of thousands of extensions to process and some things slip through the cracks. The goal of this project is to clean up the store, not to cause problems for small developers, I love how anyone can create extensions and it would be an awful result if this added major barriers to entry for small devs.",
  },
  {
    q: "How can I contribute?",
    a: "I'm still working out the details here but please email: contbutions@amibeingpwned.com",
  },
  {
    q: "Is this associated with HaveIbeenPwned?",
    a: "Nope, although Troy Hunt (founder of HaveIBeenPwned) said he was all good with me using the AmIBeingPwned name.",
  },
  // TODO: add real FAQ items
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
      <div className="space-y-8">
        {FAQ_ITEMS.map((item) => (
          <div key={item.q}>
            <h2 className="text-foreground mb-2 text-lg font-semibold">
              {item.q}
            </h2>
            <p className="text-muted-foreground leading-relaxed">{item.a}</p>
          </div>
        ))}
      </div>
    </main>
  );
}
