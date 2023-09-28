use super::*;

/// Returns an iterator over IPv4 TCP connections of all processes.
pub fn all_tcp_v4_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV4>>> {
    let pids = crate::proc::ids()?;
    Ok(pids.flat_map(|pid| crate::net::tcp_v4_connections(pid?)).flatten())
}

/// Returns an iterator over IPv6 TCP connections of all processes.
pub fn all_tcp_v6_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV6>>> {
    let pids = crate::proc::ids()?;
    Ok(pids.flat_map(|pid| crate::net::tcp_v6_connections(pid?)).flatten())
}

/// Returns an iterator over IPv4 UDP connections of all processes.
pub fn all_udp_v4_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnectionV4>>> {
    let pids = crate::proc::ids()?;
    Ok(pids.flat_map(|pid| crate::net::udp_v4_connections(pid?)).flatten())
}

/// Returns an iterator over IPv6 UDP connections of all processes.
pub fn all_udp_v6_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnectionV6>>> {
    let pids = crate::proc::ids()?;
    Ok(pids.flat_map(|pid| crate::net::udp_v6_connections(pid?)).flatten())
}
