import {
  Body,
  Container,
  Head,
  Hr,
  Html,
  Preview,
  Section,
  Text,
  Tailwind,
} from "@react-email/components";
import * as React from "react";

interface EmailLayoutProps {
  previewText: string;
  children: React.ReactNode;
  appUrl: string;
}

export function EmailLayout({ previewText, children, appUrl: _appUrl }: EmailLayoutProps) {
  return (
    <Html>
      <Head />
      <Preview>{previewText}</Preview>
      <Tailwind>
        <Body className="bg-[#0a0a0a] my-auto mx-auto font-sans">
          <Container className="bg-[#111111] border border-solid border-white/10 rounded-lg my-[40px] mx-auto p-[24px] w-[480px]">
            {/* Header */}
            <Section className="mb-[24px]">
              <Text className="text-white text-[16px] font-bold m-0 flex items-center gap-2">
                🛡️ Am I Being Pwned?
              </Text>
            </Section>

            {children}

            {/* Footer */}
            <Hr className="border border-solid border-white/10 my-[24px] mx-0 w-full" />
            <Text className="text-white/30 text-[11px] leading-[20px] m-0">
              You're receiving this because you manage a fleet on Am I Being Pwned.
              To change your notification preferences, visit your dashboard settings.
            </Text>
          </Container>
        </Body>
      </Tailwind>
    </Html>
  );
}
