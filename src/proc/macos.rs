// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns an iterator yielding identifiers of all processes on the system.
pub fn ids() -> std::io::Result<impl Iterator<Item = std::io::Result<u32>>> {
    // TOOD(@panhania): Implement this method.
    Err::<std::iter::Empty<_>, _>(std::io::ErrorKind::Unsupported.into())
}

/// A macOS-specific implementation of the iterator over process identifiers.
struct Ids {
    /// An iterator over the process metadata returned by a `sysctl` call.
    iter: std::vec::IntoIter<kinfo_proc>,
}

impl Ids {

    /// Creates a new iterator over system process identifiers.
    fn new() -> std::io::Result<Ids> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC_ALL];

        let mut buf_size = std::mem::MaybeUninit::uninit();

        // SAFETY: We call the `sysctl` function as described in the FreeBSD
        // documentation [1] (macOS's kernel derives from FreeBSD). We check for
        // errors afterwards.
        //
        // This is the first call where we don't pass any buffer and we just
        // want to estimate the size of the buffer to hold the data. It should
        // be returned thought the fourth (`oldlenp`) argument.
        //
        // Note that the `namelen` parameter (second argument) is the _length_
        // of the array passed as the `name` argument (not size in bytes), while
        // the remaining two expect size in bytes.
        //
        // [1]: https://man.freebsd.org/cgi/man.cgi?sysctl(3)
        let code = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(), mib.len() as libc::c_uint,
                std::ptr::null_mut(), buf_size.as_mut_ptr(),
                std::ptr::null_mut(), 0,
            )
        };
        if code != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: If the call to `sysctl` succeeded, we can assume that the
        // `buf_size` no is filled with the expected size of the buffer.
        let mut buf_size = unsafe {
            buf_size.assume_init()
        } as usize;

        let mut buf_len = buf_size / KINFO_PROC_SIZE;
        if buf_size % KINFO_PROC_SIZE != 0 {
            buf_len += 1;
        }

        let mut buf = Vec::<kinfo_proc>::with_capacity(buf_len);

        // SAFETY: We create a buffer of the size specified by the previous call
        // to `sysctl`. Note that between the two calls the required buffer size
        // might have changed in which case `ENOMEM` ought to be returned. The
        // operating system should round up the required buffer size to handle
        // such cases. We verify whether the call succeeded below.
        //
        // The rest is as with the `sysctl` call above (not the comment about
        // the length parameters).
        let code = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(), mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast::<libc::c_void>(), &mut buf_size,
                std::ptr::null_mut(), 0,
            )
        };
        if code != 0 {
            return Err(std::io::Error::last_os_error());
        }

        if buf_size % KINFO_PROC_SIZE != 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        let buf_len = buf_size / KINFO_PROC_SIZE;

        // SAFETY: The `syctl` call succeeded and we calculated the length of
        // the buffer above.
        unsafe {
            buf.set_len(buf_len);
        }

        Ok(Ids {
            iter: buf.into_iter(),
        })
    }
}

// TODO(@panhania): Move the following definitions to the `libc` module (or
// ideally: to the `libc` crate).

#[derive(Clone, Copy)]
#[repr(C)]
struct __c_anonymous_p_st1 {
    __p_forw: *mut libc::c_void,
    __p_back: *mut libc::c_void,
}

#[derive(Clone, Copy)]
#[repr(C)]
union __c_anonymous_p_un {
    p_st1: __c_anonymous_p_st1,
    __p_starttime: libc::timeval,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct extern_proc {
    p_un: __c_anonymous_p_un,
    p_vmspace: *mut vmspace,
	p_sigacts: *mut libc::c_void,
	p_flag: libc::c_int,
	p_stat: libc::c_char,
	p_pid: libc::pid_t,
	p_oppid: libc::pid_t,
	p_dupfd: libc::c_int,
	user_stack: caddr_t,
	exit_thread: *mut libc::c_void,
	p_debugger: libc::c_int,
	sigwait: libc::boolean_t,
	p_estcpu: libc::c_uint,
	p_cpticks: libc::c_int,
	p_pctcpu: fixpt_t,
	p_wchan: *mut libc::c_void,
	p_wmesg: *mut libc::c_char,
	p_swtime: libc::c_uint,
	p_slptime: libc::c_uint,
	p_realtimer: libc::itimerval,
	p_rtime: libc::timeval,
	p_uticks: u_quad_t,
	p_sticks: u_quad_t,
	p_iticks: u_quad_t,
	p_traceflag: libc::c_int,
	p_tracep: *mut libc::c_void,
	p_siglist: libc::c_int,
	p_textvp: *mut libc::c_void,
	p_holdcnt: libc::c_int,
	p_sigmask: libc::sigset_t,
	p_sigignore: libc::sigset_t,
	p_sigcatch: libc::sigset_t,
	p_priority: libc::c_uchar,
	p_usrpri: libc::c_uchar,
	p_nice: libc::c_char,
	p_comm: [libc::c_char; libc::MAXCOMLEN + 1],
	p_pgrp: *mut libc::c_void,
	p_addr: *mut libc::c_void,
	p_xstat: libc::c_ushort,
	p_acflag: libc::c_ushort,
	p_ru: *mut libc::c_void,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct _pcred {
    /// Opaque content.
	pc_lock: [libc::c_char; 72],
    /// Current credentials.
	pc_ucred: *mut libc::c_void,
    /// Real user identifier.
	p_ruid: libc::uid_t,
    /// Saved effective user identifier.
	p_svuid: libc::uid_t,
    /// Real group identifier.
	p_rgid: libc::gid_t,
    /// Saved effective group identifier.
	p_svgid: libc::gid_t,
    /// Reference count.
	p_refcnt: libc::c_int,
}

const NGROUPS_MAX: libc::c_int = 16;
const NGROUPS: libc::c_int = NGROUPS_MAX;

const WMESGLEN: libc::c_int = 7;

const COMAPT_MAXLOGNAME: libc::c_int = 12;

type caddr_t = *mut libc::c_void;
type segsz_t = i32;
type fixpt_t = u32;
type u_quad_t = u64;

#[derive(Clone, Copy)]
#[repr(C)]
struct _ucred {
    /// Reference count.
	cr_ref: i32,
    /// Effective user identifier.
	cr_uid: libc::uid_t,
    /// Group count.
	cr_ngroups: libc::c_short,
    /// Group identifiers.
	cr_groups: [libc::gid_t; NGROUPS as usize],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct vmspace {
    // `dummy*` is literally what is used in the original header.
	dummy: i32,
	dummy2: caddr_t,
	dummy3: [i32; 5],
	dummy4: [caddr_t; 3],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct eproc {
    /// Process address.
    e_paddr: *mut libc::c_void,
    /// Session pointer.
    e_sess: *mut libc::c_void,
    /// Process credentials.
    e_pcred: _pcred,
    /// Current credentials.
    e_ucred: _ucred,
    /// Address space.
    e_vm: vmspace,
    /// Parent process identifier.
    e_ppid: libc::pid_t,
    /// Process group identifier.
    e_pgid: libc::pid_t,
    /// Job control counter.
    e_jobc: libc::c_short,
    /// Controlling TTY device identifier.
    e_tdev: libc::dev_t,
    /// Controlling TTY process group identifier.
    e_tpgid: libc::pid_t,
    /// Controlling TTY session pointer.
    e_tsess: *mut libc::c_void,
    /// Waiting channel message.
    e_wmesg: [libc::c_char; WMESGLEN as usize + 1],
    /// Text size.
    e_xsize: segsz_t,
    /// Text resident set size.
    e_xrssize: libc::c_short,
    /// Text reference count.
    e_xccount: libc::c_short,
    e_xswrss: libc::c_short,
    e_flag: i32,
    e_login: [libc::c_char; COMAPT_MAXLOGNAME as usize],
    e_spare: [i32; 4],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct kinfo_proc {
	pub kp_proc: extern_proc,
    pub kp_eproc: eproc,
}

const KINFO_PROC_SIZE: usize = std::mem::size_of::<kinfo_proc>();
