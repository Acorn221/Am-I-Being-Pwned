import {
  Button,
  Heading,
  Hr,
  Section,
  Text,
} from "@react-email/components";
import * as React from "react";
import { EmailLayout } from "./shared/layout";

export interface ThreatDetectedProps {
  orgName: string;
  appUrl: string;
  threats: Array<{
    extensionName: string;
    chromeExtensionId: string;
    riskLevel: string;
    flaggedReason: string | null;
    deviceCount: number;
  }>;
}

export function ThreatDetectedEmail({ orgName, appUrl, threats }: ThreatDetectedProps) {
  const count = threats.length;
  const previewText = `${count} malicious extension${count !== 1 ? "s" : ""} detected across ${orgName}'s fleet`;

  return (
    <EmailLayout previewText={previewText} appUrl={appUrl}>
      {/* Alert heading */}
      <Section className="mb-[8px]">
        <Text className="text-[11px] font-semibold uppercase tracking-widest text-red-400 m-0">
          ⚠ Critical Security Alert
        </Text>
      </Section>
      <Heading className="text-white text-[22px] font-bold p-0 mt-[8px] mb-[12px] mx-0">
        {count} malicious extension{count !== 1 ? "s" : ""} detected
      </Heading>
      <Text className="text-white/70 text-[14px] leading-[22px] mt-0">
        The following extensions have been flagged as malicious across your fleet
        and should be removed immediately.
      </Text>

      <Hr className="border border-solid border-white/10 my-[20px] mx-0 w-full" />

      {/* Threat list */}
      {threats.map((threat) => (
        <Section
          key={threat.chromeExtensionId}
          className="bg-red-950/40 border border-solid border-red-500/30 rounded-md px-[16px] py-[12px] mb-[12px]"
        >
          <Text className="text-white text-[14px] font-semibold m-0 mb-[4px]">
            {threat.extensionName}
          </Text>
          <Text className="text-white/50 text-[11px] m-0 mb-[8px] font-mono">
            {threat.chromeExtensionId}
          </Text>
          <Text className="text-white/70 text-[13px] m-0 mb-[8px] leading-[20px]">
            {threat.flaggedReason ?? "Flagged as malicious by threat intelligence."}
          </Text>
          <Text className="text-white/50 text-[12px] m-0">
            Risk level: <span className="text-red-400 font-semibold capitalize">{threat.riskLevel}</span>
            {" · "}
            Detected on <span className="text-white/70">{threat.deviceCount}</span> device{threat.deviceCount !== 1 ? "s" : ""}
          </Text>
        </Section>
      ))}

      <Hr className="border border-solid border-white/10 my-[20px] mx-0 w-full" />

      <Section className="text-center mt-[24px] mb-[8px]">
        <Button
          className="bg-white rounded-md text-black text-[13px] font-semibold no-underline text-center px-[24px] py-[12px]"
          href={`${appUrl}/dashboard`}
        >
          View affected devices →
        </Button>
      </Section>
    </EmailLayout>
  );
}

export default ThreatDetectedEmail;
