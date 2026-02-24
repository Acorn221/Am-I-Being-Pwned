import { Resend } from "resend";

import { ExtensionBlockedEmail, type ExtensionBlockedProps } from "./templates/extension-blocked";
import { ThreatDetectedEmail, type ThreatDetectedProps } from "./templates/threat-detected";
import { WeeklyDigestEmail, type WeeklyDigestProps } from "./templates/weekly-digest";

export type { ExtensionBlockedProps, ThreatDetectedProps, WeeklyDigestProps };

const FROM = "Am I Being Pwned <alerts@amibeingpwned.com>";

export function createEmailClient(apiKey: string) {
  const resend = new Resend(apiKey);

  return {
    sendThreatDetected: async (to: string, props: ThreatDetectedProps) => {
      const count = props.threats.length;
      return resend.emails.send({
        from: FROM,
        to,
        subject: `⚠ ${count} malicious extension${count !== 1 ? "s" : ""} detected on ${props.orgName}'s fleet`,
        react: ThreatDetectedEmail(props),
      });
    },

    sendExtensionBlocked: async (to: string, props: ExtensionBlockedProps) => {
      return resend.emails.send({
        from: FROM,
        to,
        subject: `${props.extensionName} has been blocked across your fleet`,
        react: ExtensionBlockedEmail(props),
      });
    },

    sendWeeklyDigest: async (to: string, props: WeeklyDigestProps) => {
      const { stats } = props;
      const subject =
        stats.newThreats > 0
          ? `Fleet report: ${stats.newThreats} new threat${stats.newThreats !== 1 ? "s" : ""} — ${props.orgName}`
          : `Fleet report: all clear this week — ${props.orgName}`;

      return resend.emails.send({
        from: FROM,
        to,
        subject,
        react: WeeklyDigestEmail(props),
      });
    },
  };
}

// Re-export templates for preview/testing
export { ThreatDetectedEmail, ExtensionBlockedEmail, WeeklyDigestEmail };
