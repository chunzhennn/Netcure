export type Severity = 'error' | 'warning' | 'info';
export type WifiBandGroup = '2.4GHz' | '5GHz';

export interface Summary {
  verdict: string;
  errors: number;
  warnings: number;
  infos: number;
  adaptersUp: number;
  adaptersTotal: number;
  connectedWifiCount: number;
  publicPingSuccesses: number;
  publicPingTotal: number;
  defaultGatewayCount: number;
  pingTargetCount: number;
}

export interface CheckerMessage {
  level: Severity;
  title: string;
  description: string;
}

export interface NetworkInterface {
  name: string;
  up: boolean;
  virtual: boolean;
  mac: string;
  ipv4: string[];
  ipv4Gateway: string[];
  ipv4Dns: string[];
  ipv6: string[];
  ipv6Gateway: string[];
  ipv6Dns: string[];
}

export interface WifiConnection {
  connected: boolean;
  radioOn: boolean;
  state: string;
  profileName: string;
  ssid: string;
  bssid: string;
  phyType: string;
  bssType: string;
  authAlgorithm: string;
  cipherAlgorithm: string;
  signalQuality: number;
  rssiDbm: number | null;
  centerFrequencyMhz: number | null;
  channel: number | null;
  channelWidthMhz: number | null;
  rxRateKbps: number;
  txRateKbps: number;
  unicastRxPackets: number;
  unicastTxPackets: number;
  failedTxPackets: number;
  nearbyBssCount: number;
  sameChannelBssCount: number;
  overlappingChannelBssCount: number;
}

export interface WifiNetwork {
  ssid: string;
  bssid: string;
  profileName: string;
  phyType: string;
  bssType: string;
  authAlgorithm: string;
  cipherAlgorithm: string;
  band: string;
  securityEnabled: boolean;
  connectable: boolean;
  connected: boolean;
  signalQuality: number;
  rssiDbm: number | null;
  centerFrequencyMhz: number | null;
  channel: number | null;
  channelWidthMhz: number | null;
}

export interface WifiInterface {
  interfaceName: string;
  description: string;
  scanRequested: boolean;
  scanCompleted: boolean;
  connection: WifiConnection;
  nearbyNetworks: WifiNetwork[];
}

export interface PingAttempt {
  sequence: number;
  success: boolean;
  timedOut: boolean;
  rttMs: number | null;
  ttl: number | null;
  statusCode: number;
  status: string;
}

export interface PingTarget {
  category: string;
  targetName: string;
  address: string;
  attempts: number;
  timeoutMs: number;
  intervalMs: number;
  replies: number;
  losses: number;
  timeoutCount: number;
  lossRate: number;
  minRttMs: number | null;
  maxRttMs: number | null;
  avgRttMs: number | null;
  jitterMs: number | null;
  lastError: string;
  attemptDetails: PingAttempt[];
}

export interface HostEnvironment {
  computerName: string;
  systemManufacturer: string;
  systemModel: string;
  osName: string;
  osVersion: string;
  osBuild: string;
  osDisplayVersion: string;
  architecture: string;
  networkAdapterModels: string[];
}

export interface RouteEntry {
  destination: string;
  nextHop: string;
  interface: string;
  metric: number;
}

export interface ReportData {
  generatedAt: string;
  summary: Summary;
  messages: CheckerMessage[];
  networkInterfaces: NetworkInterface[];
  wifiInterfaces: WifiInterface[];
  pingTargets: PingTarget[];
  hostEnvironment: HostEnvironment;
  route4Table: RouteEntry[];
  route6Table: RouteEntry[];
}
