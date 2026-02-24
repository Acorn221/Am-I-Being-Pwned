import {
  Button,
  Heading,
  Hr,
  Section,
  Text,
} from "@react-email/components";
import * as React from "react";
import { EmailLayout } from "./shared/layout";

export interface WeeklyDigestProps {
  orgName: string;
  appUrl: string;
  weekOf: string;
  stats: {
    deviceCount: number;
    extensionCount: number;
    newThreats: number;
    blockedCount: number;
    cleanDevices: number;
  };
  newThreats: Array<{
    extensionName: string;
    riskScore: number;
    deviceCount: number;
  }>;
}

export function WeeklyDigestEmail({
  orgName,
  appUrl,
  weekOf,
  stats,
  newThreats,
}: WeeklyDigestProps) {
  const isClean = stats.newThreats === 0;
  const previewText = isClean
    ? `${orgName} fleet report: all clear this week`
    : `${orgName} fleet report: ${stats.newThreats} new threat${stats.newThreats !== 1 ? "s" : ""} detected`;

  return (
    <EmailLayout previewText={previewText} appUrl={appUrl}>
      <Section className="mb-[8px]">
        <Text className="text-[11px] font-semibold uppercase tracking-widest text-white/40 m-0">
          Weekly Fleet Report · {weekOf}
        </Text>
      </Section>
      <Heading className="text-white text-[22px] font-bold p-0 mt-[8px] mb-[12px] mx-0">
        {isClean ? "✓ All clear this week" : `${stats.newThreats} new threat${stats.newThreats !== 1 ? "s" : ""} detected`}
      </Heading>
      <Text className="text-white/70 text-[14px] leading-[22px] mt-0">
        Here's a summary of your fleet's security posture for {orgName}.
      </Text>

      <Hr className="border border-solid border-white/10 my-[20px] mx-0 w-full" />

      {/* Stats grid */}
      <Section className="bg-[#1a1a1a] border border-solid border-white/10 rounded-md px-[16px] py-[14px] mb-[16px]">
        <Text className="text-white/50 text-[11px] uppercase tracking-widest m-0 mb-[14px]">
          Fleet overview
        </Text>

        <table width="100%" style={{ borderCollapse: "collapse" }}>
          <tbody>
            <tr>
              <td style={{ paddingBottom: "10px", width: "50%" }}>
                <Text className="text-white/50 text-[12px] m-0 mb-[2px]">Devices monitored</Text>
                <Text className="text-white text-[20px] font-bold m-0">{stats.deviceCount}</Text>
              </td>
              <td style={{ paddingBottom: "10px", width: "50%" }}>
                <Text className="text-white/50 text-[12px] m-0 mb-[2px]">Extensions tracked</Text>
                <Text className="text-white text-[20px] font-bold m-0">{stats.extensionCount}</Text>
              </td>
            </tr>
            <tr>
              <td style={{ paddingTop: "4px", width: "50%" }}>
                <Text className="text-white/50 text-[12px] m-0 mb-[2px]">New threats</Text>
                <Text className={`text-[20px] font-bold m-0 ${stats.newThreats > 0 ? "text-red-400" : "text-emerald-400"}`}>
                  {stats.newThreats}
                </Text>
              </td>
              <td style={{ paddingTop: "4px", width: "50%" }}>
                <Text className="text-white/50 text-[12px] m-0 mb-[2px]">Extensions blocked</Text>
                <Text className={`text-[20px] font-bold m-0 ${stats.blockedCount > 0 ? "text-orange-400" : "text-white"}`}>
                  {stats.blockedCount}
                </Text>
              </td>
            </tr>
          </tbody>
        </table>
      </Section>

      {/* New threats detail */}
      {newThreats.length > 0 && (
        <>
          <Text className="text-white/50 text-[11px] uppercase tracking-widest m-0 mb-[10px]">
            New threats this week
          </Text>
          {newThreats.map((threat, i) => (
            <Section
              key={i}
              className="bg-red-950/30 border border-solid border-red-500/20 rounded-md px-[14px] py-[10px] mb-[8px]"
            >
              <Text className="text-white text-[13px] font-medium m-0 mb-[4px]">
                {threat.extensionName}
              </Text>
              <Text className="text-white/50 text-[12px] m-0">
                Risk <span className="text-red-400 font-semibold">{threat.riskScore}</span>
                {" · "}
                {threat.deviceCount} device{threat.deviceCount !== 1 ? "s" : ""}
              </Text>
            </Section>
          ))}
          <Hr className="border border-solid border-white/10 my-[20px] mx-0 w-full" />
        </>
      )}

      <Section className="text-center mt-[24px] mb-[8px]">
        <Button
          className="bg-white rounded-md text-black text-[13px] font-semibold no-underline text-center px-[24px] py-[12px]"
          href={`${appUrl}/dashboard`}
        >
          View full fleet dashboard →
        </Button>
      </Section>
    </EmailLayout>
  );
}

export default WeeklyDigestEmail;
