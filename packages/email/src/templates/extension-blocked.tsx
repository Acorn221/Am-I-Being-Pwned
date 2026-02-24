import {
  Button,
  Heading,
  Hr,
  Section,
  Text,
} from "@react-email/components";
import * as React from "react";
import { EmailLayout } from "./shared/layout";

export interface ExtensionBlockedProps {
  orgName: string;
  appUrl: string;
  extensionName: string;
  chromeExtensionId: string;
  riskScore: number;
  reason: string;
  deviceCount: number;
}

export function ExtensionBlockedEmail({
  orgName: _orgName,
  appUrl,
  extensionName,
  chromeExtensionId,
  riskScore,
  reason,
  deviceCount,
}: ExtensionBlockedProps) {
  const previewText = `${extensionName} has been blocked across your fleet`;

  return (
    <EmailLayout previewText={previewText} appUrl={appUrl}>
      <Section className="mb-[8px]">
        <Text className="text-[11px] font-semibold uppercase tracking-widest text-orange-400 m-0">
          Extension Blocked
        </Text>
      </Section>
      <Heading className="text-white text-[22px] font-bold p-0 mt-[8px] mb-[12px] mx-0">
        {extensionName} has been blocked
      </Heading>
      <Text className="text-white/70 text-[14px] leading-[22px] mt-0">
        Am I Being Pwned has automatically disabled this extension on{" "}
        <strong className="text-white">{deviceCount}</strong> device{deviceCount !== 1 ? "s" : ""} in your fleet.
      </Text>

      <Hr className="border border-solid border-white/10 my-[20px] mx-0 w-full" />

      <Section className="bg-[#1a1a1a] border border-solid border-white/10 rounded-md px-[16px] py-[14px]">
        <Text className="text-white/50 text-[11px] uppercase tracking-widest m-0 mb-[12px]">
          Details
        </Text>

        <Text className="text-white/50 text-[12px] m-0 mb-[2px]">Extension</Text>
        <Text className="text-white text-[14px] font-medium m-0 mb-[12px]">
          {extensionName}
        </Text>

        <Text className="text-white/50 text-[12px] m-0 mb-[2px]">Extension ID</Text>
        <Text className="text-white/70 text-[12px] font-mono m-0 mb-[12px]">
          {chromeExtensionId}
        </Text>

        <Text className="text-white/50 text-[12px] m-0 mb-[2px]">Risk score</Text>
        <Text className="text-orange-400 text-[14px] font-semibold m-0 mb-[12px]">
          {riskScore}/100
        </Text>

        <Text className="text-white/50 text-[12px] m-0 mb-[2px]">Reason</Text>
        <Text className="text-white/70 text-[13px] leading-[20px] m-0">
          {reason}
        </Text>
      </Section>

      <Hr className="border border-solid border-white/10 my-[20px] mx-0 w-full" />

      <Section className="text-center mt-[24px] mb-[8px]">
        <Button
          className="bg-white rounded-md text-black text-[13px] font-semibold no-underline text-center px-[24px] py-[12px]"
          href={`${appUrl}/dashboard`}
        >
          Review in dashboard →
        </Button>
      </Section>
    </EmailLayout>
  );
}

export default ExtensionBlockedEmail;
