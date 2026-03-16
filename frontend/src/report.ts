import type {
  CheckerMessage,
  PingTarget,
  ReportData,
  RouteEntry,
  Severity,
  WifiInterface,
  WifiNetwork
} from './types';

export const severityRank: Record<Severity, number> = {
  error: 0,
  warning: 1,
  info: 2
};

export const severityLabel: Record<Severity, string> = {
  error: 'Error',
  warning: 'Warning',
  info: 'Info'
};

export const severityTone: Record<Severity, string> = {
  error: 'danger',
  warning: 'warning',
  info: 'neutral'
};

export function parseEmbeddedReport(): ReportData {
  const payloadEl = document.getElementById('netcure-report-data');
  if (!payloadEl?.textContent) {
    throw new Error('Embedded report payload is missing.');
  }

  return JSON.parse(payloadEl.textContent) as ReportData;
}

export function formatText(value: string | number | null | undefined): string {
  if (value === null || value === undefined) {
    return 'N/A';
  }

  const text = String(value).trim();
  return text.length > 0 ? text : 'N/A';
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'N/A';
  }

  return `${Number(value).toFixed(digits)}%`;
}

export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'N/A';
  }

  return `${Number(value).toFixed(Number.isInteger(value) ? 0 : 1)} ms`;
}

export function formatKbpsToMbps(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 'N/A';
  }

  return `${(Number(value) / 1000).toFixed(1)} Mbps`;
}

export function sortMessages(messages: CheckerMessage[]): CheckerMessage[] {
  return [...messages].sort((left, right) => severityRank[left.level] - severityRank[right.level]);
}

export function summarizeHealth(report: ReportData): Array<{ title: string; detail: string; tone: string }> {
  const items: Array<{ title: string; detail: string; tone: string }> = [];

  if (report.summary.errors > 0) {
    items.push({
      title: 'Critical findings detected',
      detail: `${report.summary.errors} error finding(s) were raised during this diagnostic run.`,
      tone: 'danger'
    });
  }

  if (report.summary.defaultGatewayCount === 0) {
    items.push({
      title: 'No default gateway detected',
      detail: 'No active default IPv4 route was found.',
      tone: 'danger'
    });
  }

  if (report.summary.publicPingTotal > 0 && report.summary.publicPingSuccesses === 0) {
    items.push({
      title: 'Public reachability failed',
      detail: 'All configured public ping targets failed.',
      tone: 'danger'
    });
  }

  const connectedWifi = report.wifiInterfaces.find((item) => item.connection.connected);
  if (connectedWifi && connectedWifi.connection.signalQuality < 40) {
    items.push({
      title: 'Weak active Wi-Fi signal',
      detail: `${formatText(connectedWifi.connection.ssid)} is connected at ${connectedWifi.connection.signalQuality}% quality.`,
      tone: 'warning'
    });
  }

  if (items.length === 0) {
    items.push({
      title: 'No critical blockers surfaced',
      detail: 'Review the detailed sections for lower-priority findings and path quality.',
      tone: 'good'
    });
  }

  return items.slice(0, 4);
}

export function collectTopWifiNetworks(wifiInterfaces: WifiInterface[]): WifiNetwork[] {
  return wifiInterfaces
    .flatMap((item) => item.nearbyNetworks)
    .sort((left, right) => Number(right.signalQuality || 0) - Number(left.signalQuality || 0))
    .slice(0, 6);
}

export function publicPingTargets(report: ReportData): PingTarget[] {
  return report.pingTargets.filter((target) => target.category === 'public');
}

export function primaryPingTargets(report: ReportData): PingTarget[] {
  return report.pingTargets.filter((target) => target.category === 'gateway' || target.category === 'public');
}

export function defaultRoutes(routes: RouteEntry[]): RouteEntry[] {
  return routes.filter((route) => route.destination.endsWith('/0'));
}
