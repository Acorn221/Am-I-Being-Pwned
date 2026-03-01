import { useState } from "react";

import { useExtensionProbe } from "~/hooks/use-extension-probe";
import { HeroCycleProvider } from "~/components/hero-cycle-context";
import { HeroSection } from "~/components/hero-section";
import { Navbar } from "~/components/navbar";
import { ScanModal } from "~/components/scan-modal";
import { ScanResultsSection } from "~/components/scan-results-section";
import { ThreatCarousel } from "~/components/threat-carousel";
import { MethodologySection } from "~/components/methodology-section";
import { VideosSection } from "~/components/videos-section";
import { HowItWorksSection } from "~/components/how-it-works-section";
import { PricingSection, DEMO_HREF } from "~/components/pricing-section";
import { TestimonialsSection } from "~/components/testimonials-section";
import { Footer } from "~/components/footer";
import { Button } from "@amibeingpwned/ui";

function App() {
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

      <TestimonialsSection />

      <MethodologySection />

      <VideosSection />

      <HowItWorksSection />

      <PricingSection />

      <section className="border-border/50 border-t">
        <div className="mx-auto max-w-6xl px-6 py-20 text-center">
          <h2 className="text-foreground mb-3 text-2xl font-semibold">
            Ready to secure your fleet?
          </h2>
          <p className="text-muted-foreground mx-auto mb-8 max-w-md text-sm">
            Book a 30-minute call and we'll walk you through what we've found in
            extensions your team is already using.
          </p>
          <Button size="lg" asChild>
            <a href={DEMO_HREF} target="_blank" rel="noreferrer">
              Book a call
            </a>
          </Button>
        </div>
      </section>

      <Footer />
    </div>
  );
}

export default App;
