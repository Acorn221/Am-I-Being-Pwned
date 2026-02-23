export function MethodologySection() {
  return (
    <section className="border-border/50 border-y">
      <div className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="text-foreground mb-2 text-xl font-semibold">
          Permissions tell you what an extension <em>can</em> do. We find out
          what it <em>actually</em> does.
        </h2>
        <p className="text-muted-foreground mb-10 text-sm">
          Most browser extension security tools flag everything with broad
          permissions. It generates noise, misses real threats, and gives
          security teams false confidence.
        </p>

        <div className="grid gap-12 sm:grid-cols-2">
          {/* Left - The permissions trap */}
          <div className="rounded-xl border border-red-500/15 bg-red-500/5 p-6">
            <h3 className="text-foreground mb-4 font-semibold">
              The permissions trap
            </h3>
            <ul className="text-muted-foreground space-y-4 text-sm">
              <li>
                Most tools work by checking <code>manifest.json</code>. If an
                extension requests <code>&lt;all_urls&gt;</code> or{" "}
                <code>tabs</code>, it gets flagged.
              </li>
              <li>
                Problem: every legitimate VPN, ad blocker, and password manager
                requests exactly those permissions. You end up flagging 80% of
                your fleet and ignoring the rest.
              </li>
              <li>
                The real threat: some of the most dangerous extensions we've
                found had <strong>zero suspicious permissions</strong>. The
                malicious behaviour was buried in obfuscated JS, phoning home to
                a remote server, hidden behind a legitimate-looking UI.
              </li>
            </ul>
          </div>

          {/* Right - We read the code */}
          <div className="bg-card border-border rounded-xl border p-6">
            <h3 className="text-foreground mb-4 font-semibold">
              We read the code
            </h3>
            <ul className="text-muted-foreground space-y-4 text-sm">
              <li>
                We de-obfuscate/decompile every extension and analyse what it{" "}
                <em>actually executes</em>, what data it reads, where it sends
                it, and whether any of that matches what the user was told.
              </li>
              <li>
                Static analysis catches known-bad patterns at scale. Our
                LLM-powered workflow surfaces subtle, novel, and obfuscated
                behaviours. Human researchers verify every finding before it
                reaches a report.
              </li>
              <li>
                Result: precise, evidence-backed findings with minimal false
                positives.
              </li>
            </ul>
          </div>
        </div>

        {/* Proof strip */}
        <div className="border-border/50 mt-12 grid grid-cols-2 gap-6 border-t pt-12 sm:grid-cols-4">
          <div>
            <p className="text-foreground text-2xl font-bold">4+ major vulns</p>
            <p className="text-muted-foreground mt-1 text-xs">
              found by our analysis, not reported by vendors, responsible
              disclosure in progress
            </p>
          </div>
          <div>
            <p className="text-foreground text-2xl font-bold">CVSS 8.3-9.6</p>
            <p className="text-muted-foreground mt-1 text-xs">
              all findings rated high or critical severity
            </p>
          </div>
          <div>
            <p className="text-foreground text-2xl font-bold">Featured</p>
            <p className="text-muted-foreground mt-1 text-xs">
              several affected extensions were featured by Google and carried
              verified publisher badges
            </p>
          </div>
          <div>
            <p className="text-foreground text-2xl font-bold">Millions</p>
            <p className="text-muted-foreground mt-1 text-xs">
              of affected users across the extensions we audited
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
