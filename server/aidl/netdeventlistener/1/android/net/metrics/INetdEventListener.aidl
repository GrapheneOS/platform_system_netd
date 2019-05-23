package android.net.metrics;
interface INetdEventListener {
  oneway void onDnsEvent(int netId, int eventType, int returnCode, int latencyMs, @utf8InCpp String hostname, in @utf8InCpp String[] ipAddresses, int ipAddressesCount, int uid);
  oneway void onPrivateDnsValidationEvent(int netId, String ipAddress, String hostname, boolean validated);
  oneway void onConnectEvent(int netId, int error, int latencyMs, String ipAddr, int port, int uid);
  oneway void onWakeupEvent(String prefix, int uid, int ethertype, int ipNextHeader, in byte[] dstHw, String srcIp, String dstIp, int srcPort, int dstPort, long timestampNs);
  oneway void onTcpSocketStatsEvent(in int[] networkIds, in int[] sentPackets, in int[] lostPackets, in int[] rttUs, in int[] sentAckDiffMs);
  oneway void onNat64PrefixEvent(int netId, boolean added, @utf8InCpp String prefixString, int prefixLength);
  const int EVENT_GETADDRINFO = 1;
  const int EVENT_GETHOSTBYNAME = 2;
  const int EVENT_GETHOSTBYADDR = 3;
  const int EVENT_RES_NSEND = 4;
  const int REPORTING_LEVEL_NONE = 0;
  const int REPORTING_LEVEL_METRICS = 1;
  const int REPORTING_LEVEL_FULL = 2;
  const int DNS_REPORTED_IP_ADDRESSES_LIMIT = 10;
}
