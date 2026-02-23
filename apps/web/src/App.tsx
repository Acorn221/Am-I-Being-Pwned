import { useState } from "react";

import type { ReportMap } from "~/hooks/use-extension-database";
import { useExtensionProbe } from "~/hooks/use-extension-probe";
import { HeroCycleProvider } from "~/components/hero-cycle-context";
import { HeroSection } from "~/components/hero-section";
import { Navbar } from "~/components/navbar";
import { ScanModal } from "~/components/scan-modal";
import { ScanResultsSection } from "~/components/scan-results-section";
import { ThreatCarousel } from "~/components/threat-carousel";
import { VideosSection } from "~/components/videos-section";
import { HowItWorksSection } from "~/components/how-it-works-section";
import { PricingSection } from "~/components/pricing-section";
import { Footer } from "~/components/footer";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function App({ reports }: { reports: ReportMap }) {
  const { detected, probing, checkedCount } = useExtensionProbe();
  const [modalDismissed, setModalDismissed] = useState(false);

  const threats = detected.filter(
    (e) => e.risk === "CRITICAL" || e.risk === "HIGH",
  );
  const showModal = !probing && !modalDismissed && threats.length > 0;

  return (
    <div className="bg-background min-h-screen">
      <HeroCycleProvider>
        <HeroSection />
      </HeroCycleProvider>

      <Navbar />

      <ScanModal
        detected={threats}
        open={showModal}
        onClose={() => setModalDismissed(true)}
        checkedCount={checkedCount}
      />

      <ScanResultsSection
        detected={detected}
        probing={probing}
        checkedCount={checkedCount}
      />

      <section className="border-border/50 border-y">
        <div className="mx-auto max-w-6xl px-6 py-16">
          <h2 className="text-foreground mb-2 text-xl font-semibold">
            What we detect
          </h2>
          <p className="text-muted-foreground mb-10 text-sm">
            Five categories of malicious behavior, all found in real extensions
            on the Chrome Web Store.
          </p>
          <ThreatCarousel />
        </div>
      </section>

      <VideosSection />

      <HowItWorksSection />

      <PricingSection />

      <Footer />
    </div>
  );
}

export default App;
