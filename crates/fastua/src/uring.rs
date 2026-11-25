//! Optional io_uring transport with a kernel submission-polling thread
//! (SQPOLL), Linux only.
//!
//! One kernel thread, created with the server, polls the submission queues of
//! every connection (`IORING_SETUP_ATTACH_WQ`): a connection posts its `recv`
//! and `send` requests to shared memory and watches its completion queue, so
//! a request / response cycle costs no system call at all while that thread
//! is awake. It falls asleep after [`SQ_IDLE_MS`] of silence and is woken by
//! the next submission.
//!
//! Every failure (old kernel, `kernel.io_uring_disabled`, seccomp filter of a
//! container, missing privileges) makes the caller fall back to plain
//! blocking sockets, so the server runs everywhere.

use io_uring::{opcode, types, IoUring};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

/// Idle time after which the shared kernel polling thread sleeps.
pub const SQ_IDLE_MS: u32 = 50;
const ENTRIES: u32 = 8;

/// Owner of the shared kernel polling thread.
pub struct Shared {
    ring: IoUring,
}

impl Shared {
    pub fn new() -> io::Result<Shared> {
        let ring = IoUring::builder().setup_sqpoll(SQ_IDLE_MS).build(ENTRIES)?;
        // A kernel that ignored the flag would make every connection pay a
        // system call per operation: refuse rather than silently degrade.
        if !ring.params().is_setup_sqpoll() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "SQPOLL not available"));
        }
        Ok(Shared { ring })
    }

    fn fd(&self) -> RawFd {
        self.ring.as_raw_fd()
    }
}

/// io_uring transport of one connection.
pub struct Conn {
    ring: IoUring,
    fd: RawFd,
}

impl Conn {
    pub fn new(shared: &Shared, socket: RawFd) -> io::Result<Conn> {
        let ring = IoUring::builder().setup_sqpoll(SQ_IDLE_MS).setup_attach_wq(shared.fd()).build(ENTRIES)?;
        Ok(Conn { ring, fd: socket })
    }

    /// Submits one request and waits for its completion: spins on the
    /// completion queue for up to `spin`, then sleeps in the kernel.
    fn run(&mut self, entry: io_uring::squeue::Entry, spin: Duration) -> io::Result<i32> {
        // SAFETY: the buffers referenced by `entry` outlive this call, which
        // does not return before the kernel has completed the request.
        unsafe { self.ring.submission().push(&entry).map_err(|_| io::Error::other("submission queue full"))? };
        self.ring.submit()?;
        if !spin.is_zero() {
            let deadline = Instant::now() + spin;
            loop {
                if let Some(c) = self.ring.completion().next() {
                    return Ok(c.result());
                }
                std::hint::spin_loop();
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
        loop {
            if let Some(c) = self.ring.completion().next() {
                return Ok(c.result());
            }
            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn result(res: i32) -> io::Result<usize> {
        if res < 0 {
            Err(io::Error::from_raw_os_error(-res))
        } else {
            Ok(res as usize)
        }
    }

    /// Receives at least one byte (0 = peer closed).
    pub fn recv(&mut self, buf: &mut [u8], spin: Duration) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        loop {
            let e = opcode::Recv::new(types::Fd(self.fd), buf.as_mut_ptr(), len).build();
            match Self::result(self.run(e, spin)?) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => return r,
            }
        }
    }

    pub fn send_all(&mut self, mut buf: &[u8], spin: Duration) -> io::Result<()> {
        while !buf.is_empty() {
            let len = buf.len().min(u32::MAX as usize) as u32;
            let e = opcode::Send::new(types::Fd(self.fd), buf.as_ptr(), len).flags(libc::MSG_NOSIGNAL).build();
            match Self::result(self.run(e, spin)?) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => buf = &buf[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
