export interface WorkspaceAppData {
  appId: string;
  displayName: string;
  description: string;
  homepageUri: string;
  iconUri: string;
  permissions: string[];
  siteAccess: string[];
  installType: string;
  browserDeviceCount: number;
  osUserCount: number;
}

interface CountInstalledAppsResponse {
  installedApps?: {
    appId?: string;
    appType?: string;
    displayName?: string;
    description?: string;
    homepageUri?: string;
    iconUri?: string;
    permissions?: string[];
    siteAccess?: string[];
    appInstallType?: string;
    browserDeviceCount?: number;
    osUserCount?: number;
  }[];
  nextPageToken?: string;
  totalSize?: number;
}

export interface WorkspaceDevice {
  deviceId: string;
  machine: string;
}

interface FindInstalledAppDevicesResponse {
  devices?: { deviceId?: string; machine?: string }[];
  nextPageToken?: string;
  totalSize?: number;
}

/**
 * Async generator that paginates through all devices with a specific Chrome
 * extension installed, using the Chrome Management Reports API.
 */
export async function* fetchDevicesForApp(
  accessToken: string,
  appId: string,
): AsyncGenerator<WorkspaceDevice> {
  let pageToken: string | undefined;

  do {
    const params = new URLSearchParams({
      appId,
      appType: "EXTENSION",
      pageSize: "100",
    });
    if (pageToken) params.set("pageToken", pageToken);

    const res = await fetch(
      `https://chromemanagement.googleapis.com/v1/customers/my_customer/reports:findInstalledAppDevices?${params.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      },
    );

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(
        `Chrome Management API error ${res.status.toString()} (findInstalledAppDevices): ${errText}`,
      );
    }

    const data = (await res.json()) as FindInstalledAppDevicesResponse;

    for (const device of data.devices ?? []) {
      if (!device.deviceId) continue;
      yield { deviceId: device.deviceId, machine: device.machine ?? "" };
    }

    pageToken = data.nextPageToken;
  } while (pageToken);
}

/**
 * Async generator that paginates through all Chrome extensions installed
 * across a Google Workspace org using the Chrome Management Reports API.
 *
 * Uses `my_customer` to refer to the customer associated with the access token.
 * Caller must have the chrome.management.reports.readonly scope.
 */
export async function* fetchWorkspaceApps(
  accessToken: string,
): AsyncGenerator<WorkspaceAppData> {
  let pageToken: string | undefined;

  do {
    const params = new URLSearchParams({ pageSize: "100" });
    if (pageToken) params.set("pageToken", pageToken);

    const res = await fetch(
      `https://chromemanagement.googleapis.com/v1/customers/my_customer/reports:countInstalledApps?${params.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      },
    );

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(
        `Chrome Management API error ${res.status.toString()}: ${errText}`,
      );
    }

    const data = (await res.json()) as CountInstalledAppsResponse;

    for (const app of data.installedApps ?? []) {
      if (!app.appId) continue;
      yield {
        appId: app.appId,
        displayName: app.displayName ?? "",
        description: app.description ?? "",
        homepageUri: app.homepageUri ?? "",
        iconUri: app.iconUri ?? "",
        permissions: app.permissions ?? [],
        siteAccess: app.siteAccess ?? [],
        installType: app.appInstallType ?? "UNKNOWN",
        browserDeviceCount: app.browserDeviceCount ?? 0,
        osUserCount: app.osUserCount ?? 0,
      };
    }

    pageToken = data.nextPageToken;
  } while (pageToken);
}
