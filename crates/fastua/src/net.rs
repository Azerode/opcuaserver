//! Socket helpers for the latency-sensitive receive path.

use std::io;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

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

/// Receives at least one byte into `buf`. With a non-zero `spin`, polls the
/// socket without sleeping for up to that long first: the thread is already
/// running when the request lands, which saves the scheduler wake-up (several
/// microseconds) at the price of a busy core while the client is idle.
#[inline]
pub fn recv(stream: &mut TcpStream, buf: &mut [u8], spin: Duration) -> io::Result<usize> {
    use std::io::Read;
    if !spin.is_zero() {
        let deadline = Instant::now() + spin;
        loop {
            if let Some(n) = try_recv(stream, buf)? {
                return Ok(n);
            }
            std::hint::spin_loop();
            if Instant::now() >= deadline {
                break;
            }
        }
    }
    stream.read(buf)
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
