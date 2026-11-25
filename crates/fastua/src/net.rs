//! Socket helpers for the latency-sensitive receive path.

use std::io;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::Duration;

/// Non-blocking receive into `buf`: `Ok(None)` when no data is waiting.
#[inline]
pub fn try_recv(stream: &TcpStream, buf: &mut [u8]) -> io::Result<Option<usize>> {
    recv_flags(stream, buf, libc::MSG_DONTWAIT)
}

/// Like [`try_recv`] but leaves the data in the socket.
#[inline]
pub fn try_peek(stream: &TcpStream, buf: &mut [u8]) -> io::Result<Option<usize>> {
    recv_flags(stream, buf, libc::MSG_DONTWAIT | libc::MSG_PEEK)
}

#[inline]
fn recv_flags(stream: &TcpStream, buf: &mut [u8], flags: libc::c_int) -> io::Result<Option<usize>> {
    loop {
        // SAFETY: `buf` is valid for `buf.len()` writable bytes.
        let n = unsafe { libc::recv(stream.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), flags) };
        if n >= 0 {
            return Ok(Some(n as usize));
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::WouldBlock => return Ok(None),
            io::ErrorKind::Interrupted => continue,
            _ => return Err(e),
        }
    }
}

/// Asks the kernel to busy-poll the NIC queue of this socket (SO_BUSY_POLL).
/// Only real network devices with NAPI benefit; raising it above
/// `net.core.busy_read` needs CAP_NET_ADMIN, so failure is ignored.
pub fn set_kernel_busy_poll(stream: &TcpStream, spin: Duration) {
    let us = spin.as_micros().min(i32::MAX as u128) as libc::c_int;
    // SAFETY: valid fd and option pointer/length.
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            (&us as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Waits until the socket is readable or `timeout_ns` elapsed (nanosecond
/// precision with `ppoll`). Returns true when readable.
pub fn wait_readable(stream: &TcpStream, timeout_ns: u64) -> io::Result<bool> {
    let mut fd = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let ts = libc::timespec {
        tv_sec: (timeout_ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (timeout_ns % 1_000_000_000) as libc::c_long,
    };
    loop {
        // SAFETY: one valid pollfd, valid timespec, no signal mask change.
        let n = unsafe { libc::ppoll(&mut fd, 1, &ts, std::ptr::null()) };
        if n >= 0 {
            return Ok(n > 0);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Lets timers of the calling thread fire within `ns` of their deadline
/// (Linux default: 50 µs). Used by connections that drive subscriptions.
pub fn set_timer_slack(ns: u64) {
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_TIMERSLACK takes an unsigned long and affects only this thread.
    unsafe {
        libc::prctl(libc::PR_SET_TIMERSLACK, ns as libc::c_ulong, 0, 0, 0);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = ns;
}
