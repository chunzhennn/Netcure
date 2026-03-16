<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import SeverityPill from './components/SeverityPill.vue';
import WifiChannelChart from './components/WifiChannelChart.vue';
import {
  defaultRoutes,
  formatKbpsToMbps,
  formatMs,
  formatPercent,
  formatText,
  primaryPingTargets,
  sortMessages,
  summarizeHealth
} from './report';
import type { CheckerMessage, PingTarget, ReportData, Severity, WifiBandGroup } from './types';

const props = defineProps<{
  report: ReportData;
}>();

const activeSeverity = ref<'all' | Severity>('all');
const routeVersion = ref<'ipv4' | 'ipv6'>('ipv4');
const selectedFindingId = ref('');
const selectedPingTargetId = ref('');
const wifiBandSelection = ref<Record<string, WifiBandGroup>>({});

const activeRoutes = computed(() => (
  routeVersion.value === 'ipv4' ? props.report.route4Table : props.report.route6Table
));
const highlightedDefaultRoutes = computed(() => defaultRoutes(activeRoutes.value));
const healthNotes = computed(() => summarizeHealth(props.report));
const primaryTargets = computed(() => primaryPingTargets(props.report));

const reachabilitySummary = computed(() => {
  const targets = primaryTargets.value;
  return {
    reachable: targets.filter((target) => target.replies > 0).length,
    total: targets.length
  };
});

const findingCounts = computed(() => ({
  all: props.report.messages.length,
  error: props.report.messages.filter((message) => message.level === 'error').length,
  warning: props.report.messages.filter((message) => message.level === 'warning').length,
  info: props.report.messages.filter((message) => message.level === 'info').length
}));

function findingId(message: CheckerMessage): string {
  return `${message.level}:${message.title}:${message.description}`;
}

function pingTargetId(target: PingTarget): string {
  return `${target.category}:${target.targetName}:${target.address}`;
}

const filteredMessages = computed(() => {
  return sortMessages(props.report.messages).filter((message) => {
    return activeSeverity.value === 'all' || message.level === activeSeverity.value;
  });
});

watch(
  filteredMessages,
  (messages) => {
    if (messages.some((message) => findingId(message) === selectedFindingId.value)) {
      return;
    }

    selectedFindingId.value = messages.length > 0 ? findingId(messages[0]) : '';
  },
  { immediate: true }
);

watch(
  primaryTargets,
  (targets) => {
    if (targets.some((target) => pingTargetId(target) === selectedPingTargetId.value)) {
      return;
    }

    selectedPingTargetId.value = targets.length > 0 ? pingTargetId(targets[0]) : '';
  },
  { immediate: true }
);

const selectedFinding = computed(() => (
  filteredMessages.value.find((message) => findingId(message) === selectedFindingId.value) ?? null
));

const selectedPingTarget = computed(() => (
  primaryTargets.value.find((target) => pingTargetId(target) === selectedPingTargetId.value) ?? null
));

const summaryItems = computed(() => [
  {
    label: 'Critical findings',
    value: props.report.summary.errors,
    tone: props.report.summary.errors > 0 ? 'danger' : 'neutral'
  },
  {
    label: 'Reachability',
    value: `${reachabilitySummary.value.reachable}/${reachabilitySummary.value.total}`,
    tone: reachabilitySummary.value.total > 0 && reachabilitySummary.value.reachable === 0 ? 'danger' : 'good'
  },
  {
    label: 'Default gateways',
    value: props.report.summary.defaultGatewayCount,
    tone: props.report.summary.defaultGatewayCount > 0 ? 'good' : 'danger'
  },
  {
    label: 'Active Wi-Fi',
    value: props.report.summary.connectedWifiCount,
    tone: props.report.summary.connectedWifiCount > 0 ? 'good' : 'neutral'
  },
  {
    label: 'Warnings',
    value: props.report.summary.warnings,
    tone: props.report.summary.warnings > 0 ? 'warning' : 'neutral'
  },
  {
    label: 'Ping targets',
    value: props.report.summary.pingTargetCount,
    tone: 'neutral'
  }
]);

const latencyChart = computed(() => buildLatencyChart(selectedPingTarget.value));

function buildLatencyChart(target: PingTarget | null): {
  width: number;
  height: number;
  maxRtt: number;
  segments: string[];
  markers: Array<{ key: string; x: number; y: number; success: boolean; timedOut: boolean; label: string }>;
  guides: number[];
  labels: Array<{ text: string; x: number }>;
} {
  const width = 620;
  const height = 220;
  const left = 24;
  const right = 18;
  const top = 18;
  const bottom = 32;

  if (!target || target.attemptDetails.length === 0) {
    return {
      width,
      height,
      maxRtt: 0,
      segments: [],
      markers: [],
      guides: [],
      labels: []
    };
  }

  const successValues = target.attemptDetails
    .map((attempt) => attempt.rttMs)
    .filter((value): value is number => value !== null && value !== undefined);
  const maxRtt = Math.max(...successValues, 1);
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;

  const xFor = (index: number) => (
    left + (target.attemptDetails.length === 1 ? plotWidth / 2 : (index * plotWidth) / (target.attemptDetails.length - 1))
  );
  const yFor = (value: number) => top + plotHeight - (value / maxRtt) * plotHeight;

  const segments: string[] = [];
  let currentSegment: string[] = [];
  const markers = target.attemptDetails.map((attempt, index) => {
    const x = xFor(index);
    const y = attempt.rttMs !== null && attempt.rttMs !== undefined
      ? yFor(Number(attempt.rttMs))
      : top + plotHeight;

    if (attempt.rttMs !== null && attempt.rttMs !== undefined) {
      currentSegment.push(`${x},${y}`);
    } else if (currentSegment.length > 0) {
      segments.push(currentSegment.join(' '));
      currentSegment = [];
    }

    return {
      key: `${attempt.sequence}-${attempt.status}`,
      x,
      y,
      success: attempt.success,
      timedOut: attempt.timedOut,
      label: attempt.rttMs !== null && attempt.rttMs !== undefined ? `${attempt.rttMs} ms` : attempt.status
    };
  });

  if (currentSegment.length > 0) {
    segments.push(currentSegment.join(' '));
  }

  const labels = target.attemptDetails.map((attempt, index) => ({
    text: String(attempt.sequence),
    x: xFor(index)
  }));

  return {
    width,
    height,
    maxRtt,
    segments,
    markers,
    guides: [0.25, 0.5, 0.75].map((factor) => top + plotHeight * factor),
    labels
  };
}

function selectFinding(message: CheckerMessage): void {
  selectedFindingId.value = findingId(message);
}

function selectPingTarget(target: PingTarget): void {
  selectedPingTargetId.value = pingTargetId(target);
}

function resetFilters(): void {
  activeSeverity.value = 'all';
}

function pingTone(target: PingTarget): 'danger' | 'warning' | 'good' {
  if (target.replies === 0 || target.lossRate >= 50) {
    return 'danger';
  }

  if (target.lossRate > 0 || Number(target.avgRttMs ?? 0) >= 100) {
    return 'warning';
  }

  return 'good';
}

function bandGroupLabel(band: '2.4GHz' | '5GHz'): string {
  return band === '2.4GHz' ? '2.4 GHz' : '5 GHz';
}

function normalizeBandLabel(value: string | null | undefined): '2.4GHz' | '5GHz' | 'other' {
  const text = String(value ?? '').toLowerCase();

  if (text.includes('2.4')) {
    return '2.4GHz';
  }

  if (text.includes('5')) {
    return '5GHz';
  }

  return 'other';
}

function wifiNetworksByBand(networks: ReportData['wifiInterfaces'][number]['nearbyNetworks']) {
  return {
    band24: networks.filter((network) => normalizeBandLabel(network.band) === '2.4GHz'),
    band5: networks.filter((network) => normalizeBandLabel(network.band) === '5GHz'),
    other: networks.filter((network) => normalizeBandLabel(network.band) === 'other')
  };
}

function currentWifiBand(
  interfaceName: string,
  groups: ReturnType<typeof wifiNetworksByBand>
): '2.4GHz' | '5GHz' {
  const selected = wifiBandSelection.value[interfaceName];
  if (selected === '2.4GHz' && groups.band24.length > 0) {
    return selected;
  }

  if (selected === '5GHz' && groups.band5.length > 0) {
    return selected;
  }

  if (groups.band5.length > 0) {
    return '5GHz';
  }

  return '2.4GHz';
}

function setWifiBand(interfaceName: string, band: '2.4GHz' | '5GHz'): void {
  wifiBandSelection.value = {
    ...wifiBandSelection.value,
    [interfaceName]: band
  };
}

function inferBand(
  band: string | null | undefined,
  channel: number | null | undefined,
  centerFrequencyMhz: number | null | undefined
): WifiBandGroup | 'other' {
  const normalized = normalizeBandLabel(band);
  if (normalized !== 'other') {
    return normalized;
  }

  if (centerFrequencyMhz !== null && centerFrequencyMhz !== undefined) {
    if (centerFrequencyMhz >= 2400 && centerFrequencyMhz < 2500) {
      return '2.4GHz';
    }

    if (centerFrequencyMhz >= 4900 && centerFrequencyMhz < 5900) {
      return '5GHz';
    }
  }

  if (channel !== null && channel !== undefined) {
    if (channel >= 1 && channel <= 14) {
      return '2.4GHz';
    }

    if (channel > 14) {
      return '5GHz';
    }
  }

  return 'other';
}

function currentWifiGroups(wifi: ReportData['wifiInterfaces'][number]) {
  return wifiNetworksByBand(wifi.nearbyNetworks);
}

function selectedWifiBand(wifi: ReportData['wifiInterfaces'][number]): WifiBandGroup {
  return currentWifiBand(wifi.interfaceName, currentWifiGroups(wifi));
}
</script>

<template>
  <div class="report-shell">
    <header class="masthead">
      <div class="masthead__title">
        <p class="eyebrow">Netcure Report</p>
        <h1>Network Diagnostic Report</h1>
      </div>

      <div class="masthead__meta">
        <div class="masthead__meta-block">
          <span>Generated</span>
          <strong>{{ report.generatedAt }}</strong>
        </div>
        <div class="masthead__meta-block">
          <span>Verdict</span>
          <strong>{{ report.summary.verdict }}</strong>
        </div>
        <nav class="masthead__nav" aria-label="Report sections">
          <a href="#findings">Findings</a>
          <a href="#connectivity">Connectivity</a>
          <a href="#environment">Environment</a>
          <a href="#adapters">Adapters</a>
          <a href="#wifi">Wi-Fi</a>
          <a href="#routes">Routes</a>
        </nav>
      </div>
    </header>

    <section class="summary-rail" aria-label="Report summary">
      <article
        v-for="item in summaryItems"
        :key="item.label"
        class="summary-rail__item"
        :data-tone="item.tone">
        <span>{{ item.label }}</span>
        <strong>{{ item.value }}</strong>
      </article>
    </section>

    <section id="findings" class="report-section report-section--primary">
      <header class="section-header">
        <div>
          <p class="eyebrow">Priority Review</p>
          <h2>Top Findings</h2>
        </div>
      </header>

      <div class="findings-toolbar">
        <div class="filter-row" role="tablist" aria-label="Filter findings by severity">
          <button
            class="filter-pill"
            :data-active="activeSeverity === 'all'"
            type="button"
            @click="activeSeverity = 'all'">
            All
            <span>{{ findingCounts.all }}</span>
          </button>
          <button
            class="filter-pill"
            :data-active="activeSeverity === 'error'"
            type="button"
            @click="activeSeverity = 'error'">
            Errors
            <span>{{ findingCounts.error }}</span>
          </button>
          <button
            class="filter-pill"
            :data-active="activeSeverity === 'warning'"
            type="button"
            @click="activeSeverity = 'warning'">
            Warnings
            <span>{{ findingCounts.warning }}</span>
          </button>
          <button
            class="filter-pill"
            :data-active="activeSeverity === 'info'"
            type="button"
            @click="activeSeverity = 'info'">
            Info
            <span>{{ findingCounts.info }}</span>
          </button>
        </div>

        <button
          v-if="activeSeverity !== 'all'"
          class="text-action"
          type="button"
          @click="resetFilters">
          Reset filters
        </button>
      </div>

      <div v-if="filteredMessages.length > 0" class="findings-workspace">
        <div class="findings-list" role="list">
          <button
            v-for="message in filteredMessages"
            :key="findingId(message)"
            class="findings-list__item"
            :data-active="selectedFinding && findingId(selectedFinding) === findingId(message)"
            :data-tone="message.level"
            type="button"
            @click="selectFinding(message)">
            <div class="findings-list__item-head">
              <SeverityPill :level="message.level" />
            </div>
            <h3>{{ formatText(message.title) }}</h3>
            <p>{{ formatText(message.description) }}</p>
          </button>
        </div>

        <aside class="finding-detail" aria-live="polite">
          <template v-if="selectedFinding">
            <SeverityPill :level="selectedFinding.level" />
            <h3>{{ formatText(selectedFinding.title) }}</h3>
            <p class="finding-detail__description">{{ formatText(selectedFinding.description) }}</p>
          </template>

          <div v-else class="empty-state empty-state--compact">
            <h3>No findings available</h3>
          </div>
        </aside>
      </div>

      <div v-else class="empty-state">
        <h3>No findings match the current filters</h3>
        <p>Clear the current search or switch severity filters to broaden the result set.</p>
      </div>
    </section>

    <section id="connectivity" class="report-section">
      <header class="section-header">
        <div>
          <p class="eyebrow">Connectivity</p>
          <h2>Reachability</h2>
        </div>
      </header>

      <div class="overview-grid">
        <div class="overview-grid__main">
          <div v-if="primaryTargets.length > 0" class="table-frame">
            <table class="flat-table flat-table--interactive">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Address</th>
                  <th>Replies</th>
                  <th>Loss</th>
                  <th>Avg RTT</th>
                  <th>Jitter</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="target in primaryTargets"
                  :key="pingTargetId(target)"
                  :data-tone="pingTone(target)"
                  :data-active="selectedPingTarget && pingTargetId(selectedPingTarget) === pingTargetId(target)"
                  @click="selectPingTarget(target)">
                  <td>
                    <strong>{{ formatText(target.targetName) }}</strong>
                    <small>{{ formatText(target.category) }}</small>
                  </td>
                  <td class="mono">{{ formatText(target.address) }}</td>
                  <td>{{ target.replies }}/{{ target.attempts }}</td>
                  <td>{{ formatPercent(target.lossRate, 1) }}</td>
                  <td>{{ formatMs(target.avgRttMs) }}</td>
                  <td>{{ formatMs(target.jitterMs) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="empty-state">
            <h3>No gateway or public ping targets captured</h3>
          </div>
        </div>

        <aside class="overview-grid__side">
          <section class="compact-panel">
            <h3>Latency timeline</h3>
            <template v-if="selectedPingTarget">
              <p class="compact-panel__lead">
                {{ formatText(selectedPingTarget.targetName) }} · {{ formatText(selectedPingTarget.address) }}
              </p>
              <svg
                class="latency-chart"
                :viewBox="`0 0 ${latencyChart.width} ${latencyChart.height}`"
                aria-label="Ping latency chart">
                <line
                  x1="24"
                  :y1="latencyChart.height - 32"
                  :x2="latencyChart.width - 18"
                  :y2="latencyChart.height - 32"
                  class="latency-chart__axis" />
                <line
                  x1="24"
                  y1="18"
                  x2="24"
                  :y2="latencyChart.height - 32"
                  class="latency-chart__axis" />
                <line
                  v-for="guide in latencyChart.guides"
                  :key="`guide-${guide}`"
                  x1="24"
                  :y1="guide"
                  :x2="latencyChart.width - 18"
                  :y2="guide"
                  class="latency-chart__guide" />
                <polyline
                  v-for="segment in latencyChart.segments"
                  :key="segment"
                  :points="segment"
                  class="latency-chart__line" />
                <g
                  v-for="marker in latencyChart.markers"
                  :key="marker.key">
                  <circle
                    v-if="marker.success"
                    :cx="marker.x"
                    :cy="marker.y"
                    r="4.5"
                    class="latency-chart__point">
                    <title>{{ marker.label }}</title>
                  </circle>
                  <rect
                    v-else
                    :x="marker.x - 4"
                    :y="marker.y - 4"
                    width="8"
                    height="8"
                    :class="marker.timedOut ? 'latency-chart__point latency-chart__point--timeout' : 'latency-chart__point latency-chart__point--fail'">
                    <title>{{ marker.label }}</title>
                  </rect>
                </g>
                <text x="24" y="14" class="latency-chart__label">
                  {{ latencyChart.maxRtt }} ms
                </text>
                <text
                  v-for="label in latencyChart.labels"
                  :key="`label-${label.text}`"
                  :x="label.x"
                  :y="latencyChart.height - 10"
                  text-anchor="middle"
                  class="latency-chart__label">
                  {{ label.text }}
                </text>
              </svg>
              <dl class="compact-stats">
                <div>
                  <dt>Replies</dt>
                  <dd>{{ selectedPingTarget.replies }}/{{ selectedPingTarget.attempts }}</dd>
                </div>
                <div>
                  <dt>Loss</dt>
                  <dd>{{ formatPercent(selectedPingTarget.lossRate, 1) }}</dd>
                </div>
                <div>
                  <dt>Average</dt>
                  <dd>{{ formatMs(selectedPingTarget.avgRttMs) }}</dd>
                </div>
                <div>
                  <dt>Jitter</dt>
                  <dd>{{ formatMs(selectedPingTarget.jitterMs) }}</dd>
                </div>
              </dl>
            </template>
            <div v-else class="empty-state empty-state--compact">
              <h3>No ping target selected</h3>
            </div>
          </section>

          <section class="note-stack">
            <article
              v-for="item in healthNotes"
              :key="item.title"
              class="note-stack__item"
              :data-tone="item.tone">
              <h3>{{ item.title }}</h3>
              <p>{{ item.detail }}</p>
            </article>
          </section>
        </aside>
      </div>
    </section>

    <section id="environment" class="report-section">
      <header class="section-header">
        <div>
          <p class="eyebrow">Host</p>
          <h2>Environment</h2>
        </div>
      </header>

      <div class="environment-grid">
        <section class="compact-panel">
          <h3>System</h3>
          <dl class="compact-stats compact-stats--single">
            <div>
              <dt>Computer name</dt>
              <dd>{{ formatText(report.hostEnvironment.computerName) }}</dd>
            </div>
            <div>
              <dt>Manufacturer</dt>
              <dd>{{ formatText(report.hostEnvironment.systemManufacturer) }}</dd>
            </div>
            <div>
              <dt>Model</dt>
              <dd>{{ formatText(report.hostEnvironment.systemModel) }}</dd>
            </div>
            <div>
              <dt>Architecture</dt>
              <dd>{{ formatText(report.hostEnvironment.architecture) }}</dd>
            </div>
          </dl>
        </section>

        <section class="compact-panel">
          <h3>Operating system</h3>
          <dl class="compact-stats compact-stats--single">
            <div>
              <dt>Edition</dt>
              <dd>{{ formatText(report.hostEnvironment.osName) }}</dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{{ formatText(report.hostEnvironment.osVersion) }}</dd>
            </div>
            <div>
              <dt>Display version</dt>
              <dd>{{ formatText(report.hostEnvironment.osDisplayVersion) }}</dd>
            </div>
            <div>
              <dt>Build</dt>
              <dd>{{ formatText(report.hostEnvironment.osBuild) }}</dd>
            </div>
          </dl>
        </section>

        <section class="compact-panel">
          <h3>Network adapter models</h3>
          <div class="token-list token-list--stacked">
            <span
              v-for="model in report.hostEnvironment.networkAdapterModels"
              :key="model"
              class="token">
              {{ model }}
            </span>
            <span v-if="report.hostEnvironment.networkAdapterModels.length === 0" class="token token--muted">N/A</span>
          </div>
        </section>
      </div>
    </section>

    <section id="adapters" class="report-section">
      <header class="section-header">
        <div>
          <p class="eyebrow">Interfaces</p>
          <h2>Adapter Inventory</h2>
        </div>
      </header>

      <div v-if="report.networkInterfaces.length > 0" class="table-frame">
        <table class="flat-table">
          <thead>
            <tr>
              <th>Adapter</th>
              <th>State</th>
              <th>MAC</th>
              <th>IP addresses</th>
              <th>Gateways</th>
              <th>DNS</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="adapter in report.networkInterfaces"
              :key="adapter.name">
              <td>
                <strong>{{ formatText(adapter.name) }}</strong>
                <small>{{ adapter.virtual ? 'Virtual' : 'Physical' }}</small>
              </td>
              <td>
                <span class="status-pill" :data-tone="adapter.up ? 'good' : 'danger'">
                  {{ adapter.up ? 'Online' : 'Offline' }}
                </span>
              </td>
              <td class="mono">{{ formatText(adapter.mac) }}</td>
              <td>
                <div class="token-list">
                  <span
                    v-for="value in [...adapter.ipv4, ...adapter.ipv6]"
                    :key="`${adapter.name}-ip-${value}`"
                    class="token">
                    {{ value }}
                  </span>
                  <span v-if="adapter.ipv4.length === 0 && adapter.ipv6.length === 0" class="token token--muted">N/A</span>
                </div>
              </td>
              <td>
                <div class="token-list">
                  <span
                    v-for="value in [...adapter.ipv4Gateway, ...adapter.ipv6Gateway]"
                    :key="`${adapter.name}-gateway-${value}`"
                    class="token">
                    {{ value }}
                  </span>
                  <span v-if="adapter.ipv4Gateway.length === 0 && adapter.ipv6Gateway.length === 0" class="token token--muted">N/A</span>
                </div>
              </td>
              <td>
                <div class="token-list">
                  <span
                    v-for="value in [...adapter.ipv4Dns, ...adapter.ipv6Dns]"
                    :key="`${adapter.name}-dns-${value}`"
                    class="token">
                    {{ value }}
                  </span>
                  <span v-if="adapter.ipv4Dns.length === 0 && adapter.ipv6Dns.length === 0" class="token token--muted">N/A</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state">
        <h3>No adapters reported</h3>
      </div>
    </section>

    <section id="wifi" class="report-section">
      <header class="section-header">
        <div>
          <p class="eyebrow">Wireless</p>
          <h2>Wi-Fi Condition</h2>
        </div>
      </header>

      <div v-if="report.wifiInterfaces.length > 0" class="wifi-layout">
        <div class="wifi-layout__main">
          <article
            v-for="wifi in report.wifiInterfaces"
            :key="wifi.interfaceName"
            class="wifi-block">
            <div class="wifi-block__header">
              <div>
                <h3>{{ formatText(wifi.interfaceName) }}</h3>
                <p>{{ formatText(wifi.description) }}</p>
              </div>
              <span class="status-pill" :data-tone="wifi.connection.connected ? 'good' : 'neutral'">
                {{ wifi.connection.connected ? 'Connected' : formatText(wifi.connection.state) }}
              </span>
            </div>

            <dl class="inline-stats">
              <div>
                <dt>SSID</dt>
                <dd>{{ formatText(wifi.connection.ssid) }}</dd>
              </div>
              <div>
                <dt>BSSID</dt>
                <dd class="mono">{{ formatText(wifi.connection.bssid) }}</dd>
              </div>
              <div>
                <dt>RSSI</dt>
                <dd>{{ formatText(wifi.connection.rssiDbm) }} dBm</dd>
              </div>
              <div>
                <dt>Signal</dt>
                <dd>{{ formatPercent(wifi.connection.signalQuality) }}</dd>
              </div>
              <div>
                <dt>Profile</dt>
                <dd>{{ formatText(wifi.connection.profileName) }}</dd>
              </div>
              <div>
                <dt>Channel</dt>
                <dd>{{ formatText(wifi.connection.channel) }}</dd>
              </div>
              <div>
                <dt>Width</dt>
                <dd>{{ formatText(wifi.connection.channelWidthMhz) }} MHz</dd>
              </div>
              <div>
                <dt>Center freq</dt>
                <dd>{{ formatText(wifi.connection.centerFrequencyMhz) }} MHz</dd>
              </div>
              <div>
                <dt>PHY</dt>
                <dd>{{ formatText(wifi.connection.phyType) }}</dd>
              </div>
              <div>
                <dt>Authentication</dt>
                <dd>{{ formatText(wifi.connection.authAlgorithm) }}</dd>
              </div>
              <div>
                <dt>Cipher</dt>
                <dd>{{ formatText(wifi.connection.cipherAlgorithm) }}</dd>
              </div>
              <div>
                <dt>TX / RX</dt>
                <dd>{{ formatKbpsToMbps(wifi.connection.txRateKbps) }} / {{ formatKbpsToMbps(wifi.connection.rxRateKbps) }}</dd>
              </div>
            </dl>

            <div class="band-switcher">
              <div class="compact-panel compact-panel--chart">
                <h3>Channel Map</h3>
                <WifiChannelChart :wifi="wifi" :band="selectedWifiBand(wifi)" />
              </div>

              <div class="band-tabs" role="tablist" aria-label="Wi-Fi band selector">
                <button
                  class="band-tab"
                  :data-active="selectedWifiBand(wifi) === '2.4GHz'"
                  :disabled="currentWifiGroups(wifi).band24.length === 0"
                  type="button"
                  @click="setWifiBand(wifi.interfaceName, '2.4GHz')">
                  <span>{{ bandGroupLabel('2.4GHz') }}</span>
                  <strong>{{ currentWifiGroups(wifi).band24.length }}</strong>
                </button>
                <button
                  class="band-tab"
                  :data-active="selectedWifiBand(wifi) === '5GHz'"
                  :disabled="currentWifiGroups(wifi).band5.length === 0"
                  type="button"
                  @click="setWifiBand(wifi.interfaceName, '5GHz')">
                  <span>{{ bandGroupLabel('5GHz') }}</span>
                  <strong>{{ currentWifiGroups(wifi).band5.length }}</strong>
                </button>
              </div>

              <div
                v-if="selectedWifiBand(wifi) === '2.4GHz'"
                class="band-panel">
                <div v-if="currentWifiGroups(wifi).band24.length > 0" class="ssid-list">
                  <article
                    v-for="network in currentWifiGroups(wifi).band24"
                    :key="`${wifi.interfaceName}-24-${network.bssid}-${network.ssid}`"
                    class="ssid-list__item">
                    <div>
                      <strong>{{ formatText(network.ssid) }}</strong>
                      <p class="mono">{{ formatText(network.bssid) }}</p>
                    </div>
                    <dl>
                      <div>
                        <dt>Signal</dt>
                        <dd>{{ formatPercent(network.signalQuality) }}</dd>
                      </div>
                      <div>
                        <dt>RSSI</dt>
                        <dd>{{ formatText(network.rssiDbm) }} dBm</dd>
                      </div>
                      <div>
                        <dt>Channel</dt>
                        <dd>{{ formatText(network.channel) }}</dd>
                      </div>
                      <div>
                        <dt>Width</dt>
                        <dd>{{ formatText(network.channelWidthMhz) }} MHz</dd>
                      </div>
                      <div>
                        <dt>Security</dt>
                        <dd>{{ network.securityEnabled ? 'Secured' : 'Open' }}</dd>
                      </div>
                    </dl>
                  </article>
                </div>
                <div v-else class="empty-state empty-state--compact">
                  <h3>No 2.4 GHz networks</h3>
                </div>
              </div>

              <div
                v-else
                class="band-panel">
                <div v-if="currentWifiGroups(wifi).band5.length > 0" class="ssid-list">
                  <article
                    v-for="network in currentWifiGroups(wifi).band5"
                    :key="`${wifi.interfaceName}-5-${network.bssid}-${network.ssid}`"
                    class="ssid-list__item">
                    <div>
                      <strong>{{ formatText(network.ssid) }}</strong>
                      <p class="mono">{{ formatText(network.bssid) }}</p>
                    </div>
                    <dl>
                      <div>
                        <dt>Signal</dt>
                        <dd>{{ formatPercent(network.signalQuality) }}</dd>
                      </div>
                      <div>
                        <dt>RSSI</dt>
                        <dd>{{ formatText(network.rssiDbm) }} dBm</dd>
                      </div>
                      <div>
                        <dt>Channel</dt>
                        <dd>{{ formatText(network.channel) }}</dd>
                      </div>
                      <div>
                        <dt>Width</dt>
                        <dd>{{ formatText(network.channelWidthMhz) }} MHz</dd>
                      </div>
                      <div>
                        <dt>Security</dt>
                        <dd>{{ network.securityEnabled ? 'Secured' : 'Open' }}</dd>
                      </div>
                    </dl>
                  </article>
                </div>
                <div v-else class="empty-state empty-state--compact">
                  <h3>No 5 GHz networks</h3>
                </div>
              </div>
            </div>

            <div v-if="currentWifiGroups(wifi).other.length > 0" class="disclosure-block">
              <details class="band-panel">
                <summary>
                  <span>Other bands</span>
                  <strong>{{ currentWifiGroups(wifi).other.length }}</strong>
                </summary>
                <div class="ssid-list">
                  <article
                    v-for="network in currentWifiGroups(wifi).other"
                    :key="`${wifi.interfaceName}-other-${network.bssid}-${network.ssid}`"
                    class="ssid-list__item">
                    <div>
                      <strong>{{ formatText(network.ssid) }}</strong>
                      <p class="mono">{{ formatText(network.bssid) }}</p>
                    </div>
                    <dl>
                      <div>
                        <dt>Band</dt>
                        <dd>{{ formatText(network.band) }}</dd>
                      </div>
                      <div>
                        <dt>Signal</dt>
                        <dd>{{ formatPercent(network.signalQuality) }}</dd>
                      </div>
                      <div>
                        <dt>Width</dt>
                        <dd>{{ formatText(network.channelWidthMhz) }} MHz</dd>
                      </div>
                      <div>
                        <dt>Channel</dt>
                        <dd>{{ formatText(network.channel) }}</dd>
                      </div>
                    </dl>
                  </article>
                </div>
              </details>
            </div>
          </article>
        </div>

      </div>
      <div v-else class="empty-state">
        <h3>No Wi-Fi interfaces reported</h3>
      </div>
    </section>

    <section id="routes" class="report-section">
      <header class="section-header">
        <div>
          <p class="eyebrow">Routing</p>
          <h2>Route Table</h2>
        </div>
        <div class="filter-row" role="tablist" aria-label="Route version">
          <button
            class="filter-pill"
            :data-active="routeVersion === 'ipv4'"
            type="button"
            @click="routeVersion = 'ipv4'">
            IPv4
          </button>
          <button
            class="filter-pill"
            :data-active="routeVersion === 'ipv6'"
            type="button"
            @click="routeVersion = 'ipv6'">
            IPv6
          </button>
        </div>
      </header>

      <div v-if="highlightedDefaultRoutes.length > 0" class="default-route-strip">
        <article
          v-for="route in highlightedDefaultRoutes"
          :key="`default-${route.destination}-${route.nextHop}-${route.interface}`"
          class="default-route-strip__item">
          <span class="status-pill" data-tone="good">Default route</span>
          <strong>{{ route.destination }} via {{ route.nextHop }}</strong>
          <p>{{ formatText(route.interface) }} · metric {{ route.metric }}</p>
        </article>
      </div>

      <div class="table-frame">
        <table class="flat-table">
          <thead>
            <tr>
              <th>Destination</th>
              <th>Next hop</th>
              <th>Interface</th>
              <th>Metric</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="route in activeRoutes"
              :key="`${route.destination}-${route.nextHop}-${route.interface}-${route.metric}`">
              <td class="mono">{{ route.destination }}</td>
              <td class="mono">{{ route.nextHop }}</td>
              <td>{{ formatText(route.interface) }}</td>
              <td>{{ route.metric }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>
