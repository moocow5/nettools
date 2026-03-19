use std::net::IpAddr;

/// Perform a reverse DNS lookup. Returns hostname if found.
pub async fn reverse_dns(ip: IpAddr) -> Option<String> {
    let ip = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return None,
    };

    tokio::task::spawn_blocking(move || reverse_dns_blocking(ip))
        .await
        .ok()
        .flatten()
}

fn reverse_dns_blocking(ip: std::net::Ipv4Addr) -> Option<String> {
    use std::ffi::CStr;

    let octets = ip.octets();
    let addr = u32::from_be_bytes(octets);

    #[cfg(target_os = "macos")]
    let sa = libc::sockaddr_in {
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: addr.to_be(),
        },
        sin_zero: [0; 8],
    };

    #[cfg(not(target_os = "macos"))]
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: addr.to_be(),
        },
        sin_zero: [0; 8],
    };

    let mut host_buf = [0u8; 256];

    let ret = unsafe {
        libc::getnameinfo(
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host_buf.as_mut_ptr() as *mut libc::c_char,
            host_buf.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            0,
        )
    };

    if ret != 0 {
        return None;
    }

    let c_str = unsafe { CStr::from_ptr(host_buf.as_ptr() as *const libc::c_char) };
    let hostname = c_str.to_string_lossy().to_string();

    if hostname == ip.to_string() {
        return None;
    }

    Some(hostname)
}
