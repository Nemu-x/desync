package desync

// Android denies apps SIOCOUTQNSD (AOSP system/sepolicy lists it in
// priv_sock_ioctls, never granted to untrusted apps), so unsent bytes come
// from TCP_INFO, which older kernels lack. The methods that need them are
// therefore not reported as guaranteed; ProbeCapabilities decides them on a
// live socket.
const sentPerSocket = true

const sentPerSocketReason = "Android does not let apps read SIOCOUTQNSD; unsent bytes are read from TCP_INFO tcpi_notsent_bytes (Linux 4.6+) when the socket provides it, so this is decided per socket: see ProbeCapabilities"
