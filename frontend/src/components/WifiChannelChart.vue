<script setup lang="ts">
import { computed } from 'vue';
import VChart from 'vue-echarts';
import { use } from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { SVGRenderer } from 'echarts/renderers';
import type { WifiBandGroup, WifiInterface, WifiNetwork } from '../types';

use([LineChart, GridComponent, LegendComponent, TooltipComponent, SVGRenderer]);

const props = defineProps<{
  wifi: WifiInterface;
  band: WifiBandGroup;
}>();

type ChannelSeries = {
  name: string;
  connected: boolean;
  centerChannel: number;
  widthMhz: number;
  rssiDbm: number;
  data: Array<[number, number]>;
};

function normalizeBandLabel(value: string | null | undefined): WifiBandGroup | 'other' {
  const text = String(value ?? '').toLowerCase();

  if (text.includes('2.4')) {
    return '2.4GHz';
  }

  if (text.includes('5')) {
    return '5GHz';
  }

  return 'other';
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

function buildRaisedCurve(
  centerChannel: number,
  widthMhz: number,
  rssiDbm: number,
  band: WifiBandGroup
): Array<[number, number]> {
  const span = Math.max(widthMhz / 5, band === '2.4GHz' ? 4 : 4);
  const halfSpan = span / 2;
  const minX = centerChannel - halfSpan;
  const maxX = centerChannel + halfSpan;
  const baseline = -100;
  const peak = Math.max(-92, Math.min(-30, rssiDbm));
  const steps = 36;
  const data: Array<[number, number]> = [];

  for (let index = 0; index <= steps; index += 1) {
    const x = minX + ((maxX - minX) * index) / steps;
    const normalizedDistance = Math.abs((x - centerChannel) / halfSpan);
    const raisedCosine = Math.max(0, Math.cos((normalizedDistance * Math.PI) / 2));
    const shape = Math.pow(raisedCosine, band === '2.4GHz' ? 0.72 : 0.8);
    const y = baseline + (peak - baseline) * shape;
    data.push([Number(x.toFixed(2)), Number(y.toFixed(2))]);
  }

  return data;
}

function toSeries(network: WifiNetwork, band: WifiBandGroup): ChannelSeries | null {
  if (network.channel === null || network.channel === undefined || network.rssiDbm === null || network.rssiDbm === undefined) {
    return null;
  }

  return {
    name: network.ssid?.trim() || network.bssid || 'Unknown network',
    connected: network.connected,
    centerChannel: Number(network.channel),
    widthMhz: Number(network.channelWidthMhz ?? (band === '2.4GHz' ? 20 : 40)),
    rssiDbm: Number(network.rssiDbm),
    data: buildRaisedCurve(
      Number(network.channel),
      Number(network.channelWidthMhz ?? (band === '2.4GHz' ? 20 : 40)),
      Number(network.rssiDbm),
      band
    )
  };
}

const bandNetworks = computed(() => props.wifi.nearbyNetworks
  .filter((network) => inferBand(network.band, network.channel, network.centerFrequencyMhz) === props.band));

const chartSeries = computed<ChannelSeries[]>(() => {
  const series = bandNetworks.value
    .map((network) => toSeries(network, props.band))
    .filter((value): value is ChannelSeries => value !== null)
    .sort((left, right) => right.rssiDbm - left.rssiDbm);

  const connectionBand = inferBand(
    null,
    props.wifi.connection.channel,
    props.wifi.connection.centerFrequencyMhz
  );
  const connectionVisible =
    props.wifi.connection.connected &&
    connectionBand === props.band &&
    props.wifi.connection.channel !== null &&
    props.wifi.connection.channel !== undefined &&
    props.wifi.connection.rssiDbm !== null &&
    props.wifi.connection.rssiDbm !== undefined;

  if (connectionVisible) {
    const connectionBssid = props.wifi.connection.bssid?.trim();
    const exists = bandNetworks.value.some((network) => network.bssid?.trim() === connectionBssid);

    if (!exists) {
      series.unshift({
        name: props.wifi.connection.ssid?.trim() || 'Current connection',
        connected: true,
        centerChannel: Number(props.wifi.connection.channel),
        widthMhz: Number(props.wifi.connection.channelWidthMhz ?? (props.band === '2.4GHz' ? 20 : 40)),
        rssiDbm: Number(props.wifi.connection.rssiDbm),
        data: buildRaisedCurve(
          Number(props.wifi.connection.channel),
          Number(props.wifi.connection.channelWidthMhz ?? (props.band === '2.4GHz' ? 20 : 40)),
          Number(props.wifi.connection.rssiDbm),
          props.band
        )
      });
    }
  }

  return series;
});

const xAxisBounds = computed(() => {
  const fallback = props.band === '2.4GHz' ? [1, 13] as const : [36, 165] as const;
  if (chartSeries.value.length === 0) {
    return { min: fallback[0], max: fallback[1] };
  }

  const channels = chartSeries.value.map((series) => series.centerChannel);
  const min = Math.min(...channels);
  const max = Math.max(...channels);
  return {
    min: props.band === '2.4GHz' ? Math.max(1, min - 3) : Math.max(32, min - 8),
    max: props.band === '2.4GHz' ? Math.min(13, max + 3) : Math.min(173, max + 8)
  };
});

const option = computed(() => ({
  animation: false,
  grid: {
    left: 44,
    right: 20,
    top: 26,
    bottom: 34
  },
  tooltip: {
    trigger: 'item',
    backgroundColor: 'rgba(20, 24, 31, 0.94)',
    borderColor: 'rgba(255,255,255,0.14)',
    textStyle: {
      color: '#f2f5f8'
    },
    formatter: (params: { seriesName: string; seriesIndex: number }) => {
      const series = chartSeries.value[params.seriesIndex];
      if (!series) {
        return params.seriesName;
      }

      return [
        `<strong>${series.name}</strong>`,
        `Channel ${series.centerChannel}`,
        `${series.widthMhz} MHz`,
        `${series.rssiDbm} dBm`
      ].join('<br>');
    }
  },
  xAxis: {
    type: 'value',
    min: xAxisBounds.value.min,
    max: xAxisBounds.value.max,
    interval: props.band === '2.4GHz' ? 1 : 4,
    axisLine: {
      lineStyle: {
        color: 'rgba(127, 145, 161, 0.55)'
      }
    },
    axisLabel: {
      color: 'rgba(127, 145, 161, 0.92)'
    },
    splitLine: {
      lineStyle: {
        color: 'rgba(127, 145, 161, 0.12)'
      }
    }
  },
  yAxis: {
    type: 'value',
    min: -100,
    max: -20,
    interval: 10,
    axisLine: {
      lineStyle: {
        color: 'rgba(127, 145, 161, 0.55)'
      }
    },
    axisLabel: {
      color: 'rgba(127, 145, 161, 0.92)',
      formatter: '{value} dBm'
    },
    splitLine: {
      lineStyle: {
        color: 'rgba(127, 145, 161, 0.12)'
      }
    }
  },
  series: chartSeries.value.map((series) => ({
    name: series.name,
    type: 'line',
    smooth: 0.22,
    showSymbol: false,
    data: series.data,
    lineStyle: {
      width: series.connected ? 2.5 : 1.4,
      color: series.connected ? '#2f855a' : '#62758c'
    },
    areaStyle: {
      color: series.connected ? 'rgba(47, 133, 90, 0.24)' : 'rgba(98, 117, 140, 0.14)'
    },
    emphasis: {
      focus: 'series'
    },
    z: series.connected ? 4 : 2
  }))
}));
</script>

<template>
  <div class="wifi-channel-chart">
    <VChart
      v-if="chartSeries.length > 0"
      :option="option"
      autoresize
      class="wifi-channel-chart__canvas" />
    <div v-else class="empty-state empty-state--compact">
      <h3>No channel plot data</h3>
    </div>
  </div>
</template>
