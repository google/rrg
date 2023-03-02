// TODO(@panhania): All definitions in this module should be added to the `libc`
// crate.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
mod macos {

    // TODO(@panhania): Check whether `vst_*timensec` fields correspond to only
    // the nanoseconds part or it is more precise representation of the time.
    //
    // TODO(@panhania): Document the unit of time of `vst_*time` fields.
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct vinfo_stat {
        /// Identifier of the device containing the file.
        pub vst_dev: u32,
        /// Mode of the file.
        pub vst_mode: u16,
        /// Number of hard links.
        pub vst_nlink: u16,
        /// Serial number.
        pub vst_ino: u64,
        /// Identifier of the user that owns the file.
        pub vst_uid: libc::uid_t,
        /// Identifier of the group that owns the file.
        pub vst_gid: libc::gid_t,
        /// Last access time.
        pub vst_atime: i64,
        /// Nanoseconds of last access time.
        pub vst_atimensec: i64,
        /// Last data modification time.
        pub vst_mtime: i64,
        /// Nanoseconds of last data modification time.
        pub vst_mtimensec: i64,
        /// Last status change time.
        pub vst_ctime: i64,
        /// Nanoseconds of last status change time.
        pub vst_ctimensec: i64,
        /// Creation time.
        pub vst_birthtime: i64,
        /// Nanoseconds of creation time.
        pub vst_birthtimensec: i64,
        /// Size of the file (in bytes).
        pub vst_size: libc::off_t,
        /// Number of allocated blocks.
        pub vst_blocks: i64,
        /// Optimal block size.
        pub vst_blksize: i32,
        /// User-defined flags.
        pub vst_flags: u32,
        /// Generation number.
        pub vst_gen: u32,
        /// Identifier of the device this file represents.
        pub vst_rdev: u32,
        /// Reserved, should not be used.
        pub vst_qspare: [i64; 2],
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    pub const PROX_FDTYPE_ATALK: libc::c_int = 0;
    pub const PROX_FDTYPE_VNODE: libc::c_int = 1;
    pub const PROX_FDTYPE_SOCKET: libc::c_int = 2;
    pub const PROX_FDTYPE_PSHM: libc::c_int = 3;
    pub const PROX_FDTYPE_PSEM: libc::c_int = 4;
    pub const PROX_FDTYPE_KQUEUE: libc::c_int = 5;
    pub const PROX_FDTYPE_PIPE: libc::c_int = 6;
    pub const PROX_FDTYPE_FSEVENTS: libc::c_int = 7;

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    pub const PROC_PIDLISTFDS: libc::c_int = 1;
    pub const PROC_PIDTASKALLINFO: libc::c_int = 2;
    pub const PROC_PIDTBSDINFO: libc::c_int = 3;
    pub const PROC_PIDTASKINFO: libc::c_int = 4;
    pub const PROC_PIDTHREADINFO: libc::c_int = 5;
    pub const PROC_PIDLISTTHREADS: libc::c_int = 6;

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    pub const SOCKINFO_GENERIC: libc::c_int= 0;
    pub const SOCKINFO_IN: libc::c_int = 1;
    pub const SOCKINFO_TCP: libc::c_int = 2;
    pub const SOCKINFO_UN: libc::c_int = 3;
    pub const SOCKINFO_NDRV: libc::c_int = 4;
    pub const SOCKINFO_KERN_EVENT: libc::c_int = 5;
    pub const SOCKINFO_KERN_CTL: libc::c_int = 6;

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    pub const INI_IPV4: libc::c_int = 0x1;
    pub const INI_IPV6: libc::c_int = 0x2;

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct in4in6_addr {
        pub i46a_pad32: [u32; 3],
        pub i46a_addr4: libc::in_addr,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub union __c_anonymous_insi_faddr {
        pub ina_46: in4in6_addr,
        pub ina_6: libc::in6_addr,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub union __c_anonymous_insi_laddr {
        pub ina_46: in4in6_addr,
        pub ina_6: libc::in6_addr,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct __c_anonymous_insi_v4 {
        /// Type of service.
        pub in4_tos: libc::c_uchar,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct __c_anonymous_insi_v6 {
        pub in6_hlim: u8,
        pub in6_cksum: libc::c_int,
        pub in6_ifindex: libc::c_ushort,
        pub in6_hops: libc::c_short,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    /// IPv4 and IPv6 socket.
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct in_sockinfo {
        /// Foreign port.
        pub insi_fport: libc::c_int,
        /// Local port.
        pub insi_lport: libc::c_int,
        /// Generation count of this instance.
        pub insi_gencnt: u64,
        /// Generic IP/datagram flags.
        pub insi_flags: u32,
        pub insi_flow: u32,
        /// [`INI_IPV4`] or [`INI_IPV6`].
        pub insi_vflag: u8,
        /// Time to live.
        pub insi_ip_ttl: u8,
        pub rfu_1: u32,
        /// Foreign host table entry.
        pub insi_faddr: __c_anonymous_insi_faddr,
        /// Local host table entry.
        pub insi_laddr: __c_anonymous_insi_laddr,
        pub insi_v4: __c_anonymous_insi_v4,
        pub inis_v6: __c_anonymous_insi_v6,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html

    /// Retransmit.
    pub const TSI_T_REXMT: libc::c_int = 0;
    /// Retransmit persistence.
    pub const TSI_T_PERSIST: libc::c_int = 1;
    /// Keep alive.
    pub const TSI_T_KEEP: libc::c_int = 2;
    /// _2 * MSL_ quiet time timer
    pub const TSI_T_2MSL: libc::c_int = 3;
    /// Number of timers.
    pub const TSI_T_NTIMERS: libc::c_int = 4;

    pub const TSI_S_CLOSED: libc::c_int = 0;
    pub const TSI_S_LISTEN: libc::c_int = 1;
    pub const TSI_S_SYN_SENT: libc::c_int = 2;
    pub const TSI_S_SYN_RECEIVED: libc::c_int = 3;
    pub const TSI_S_ESTABLISHED: libc::c_int = 4;
    pub const TSI_S__CLOSE_WAIT: libc::c_int = 5;
    pub const TSI_S_FIN_WAIT_1: libc::c_int = 6;
    pub const TSI_S_CLOSING: libc::c_int = 7;
    pub const TSI_S_LAST_ACK: libc::c_int = 8;
    pub const TSI_S_FIN_WAIT_2: libc::c_int = 9;
    pub const TSI_S_TIME_WAIT: libc::c_int = 10;
    pub const TSI_S_RESERVED: libc::c_int = 11;

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    pub const PROC_PIDFDVNODEINFO: libc::c_int = 1;
    pub const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;
    pub const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    pub const PROC_PIDFDPSEMINFO: libc::c_int = 4;
    pub const PROC_PIDFDPSHMINFO: libc::c_int = 5;
    pub const PROC_PIDFDPIPEINFO: libc::c_int = 6;
    pub const PROC_PIDFDKQUEUEINFO: libc::c_int = 7;
    pub const PROC_PIDFDATALKINFO: libc::c_int = 8;

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    /// TCP socket.
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct tcp_sockinfo {
        pub tcpsi_ini: in_sockinfo,
        pub tcpsi_state: libc::c_int,
        pub tcpsi_timer: [libc::c_int; TSI_T_NTIMERS as usize],
        pub tcpsi_mss: libc::c_int,
        pub tcpsi_flags: u32,
        /// Opaque handle of TCP protocol control block.
        pub tcpsi_tp: u64,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub union __c_anonymous_unsi_addr {
        pub ua_sun: libc::sockaddr_un,
        pub ua_dummy: [libc::c_char; libc::SOCK_MAXADDRLEN as usize],
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub union __c_anonymous_unsi_cddr {
        pub ua_sun: libc::sockaddr_un,
        pub ua_dummy: [libc::c_char; libc::SOCK_MAXADDRLEN as usize],
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    /// Unix domain socket.
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct un_sockinfo {
        /// Opaque handle of connected socket.
        pub unsi_conn_so: u64,
        /// Opaque handle of connected protocol control block.
        pub unsi_conn_pcb: u64,
        /// Bound address.
        pub unsi_addr: __c_anonymous_unsi_addr,
        /// Address of socket connected to.
        pub unsi_caddr: __c_anonymous_unsi_cddr,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    /// Network driver socket.
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct ndrv_info {
        pub ndrvsi_if_family: u32,
        pub ndrvsi_if_unit: u32,
        pub ndrvsi_if_name: [libc::c_char; libc::IF_NAMESIZE],
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    /// Kernel event socket.
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct kern_event_info {
        pub kesi_vendor_code_filter: u32,
        pub kesi_class_filter: u32,
        pub kesi_subclass_filter: u32,
    }

    // https://opensource.apple.com/source/xnu/xnu-3789.70.16/bsd/sys/kern_control.h.auto.html
    pub const MAX_KCTL_NAME: libc::c_int = 96;

    /// Kernel control socket.
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct kern_ctl_info {
        pub kcsi_id: u32,
        pub kcsi_reg_unit: u32,
        pub kcsi_flags: u32,
        pub kcsi_recvbufsize: u32,
        pub kcsi_sendbufsize: u32,
        pub kcsi_unit: u32,
        /// Unique network kernel extension identifier provided by DTS.
        pub kcsi_name: [libc::c_char; MAX_KCTL_NAME as usize],
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct proc_fdinfo {
        pub proc_fd: i32,
        pub proc_fdtype: u32,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct proc_fileinfo {
        pub fi_openflags: u32,
        pub fi_status: u32,
        pub fi_offset: libc::off_t,
        pub fi_type: i32,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct sockbuf_info {
        pub sbi_cc: u32,
        pub sbi_hiwat: u32,
        pub sbi_mbcnt: u32,
        pub sbi_mbmax: u32,
        pub sbi_lowat: u32,
        pub sbi_flags: libc::c_short,
        pub sbi_timeo: libc::c_short,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub union __c_anonymous_soi_proto {
        /// For [`SOCKINFO_IN`].
        pub pri_in: in_sockinfo,
        /// For [`SOCKINFO_TCP`].
        pub pri_tcp: tcp_sockinfo,
        /// For [`SOCKINFO_UN`].
        pub pri_un: un_sockinfo,
        /// For [`SOCKINFO_NDRV`].
        pub pri_ndrv: ndrv_info,
        /// For [`SOCKINFO_KERN_EVENT`].
        pub pri_kern_event: kern_event_info,
        /// For [`SOCKINFO_KERN_CTL`].
        pub pri_kern_ctl: kern_ctl_info,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct socket_info {
        pub soi_stat: vinfo_stat,
        /// Opaque handle of socket.
        pub soi_so: u64,
        /// Opaque handle of protocol control block.
        pub soi_pcb: u64,
        pub soi_type: libc::c_int,
        pub soi_protocol: libc::c_int,
        pub soi_family: libc::c_int,
        pub soi_options: libc::c_short,
        pub soi_linger: libc::c_short,
        pub soi_state: libc::c_short,
        pub soi_qlen: libc::c_short,
        pub soi_incqlen: libc::c_short,
        pub soi_qlimit: libc::c_short,
        pub soi_timeo: libc::c_short,
        pub soi_error: libc::c_ushort,
        pub soi_oobmark: u32,
        pub soi_rcv: sockbuf_info,
        pub soi_snd: sockbuf_info,
        pub soi_kind: libc::c_int,
        pub soi_proto: __c_anonymous_soi_proto,
    }

    // https://opensource.apple.com/source/xnu/xnu-1228.0.2/bsd/sys/proc_info.h.auto.html
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct socket_fdinfo {
        pub pfi: proc_fileinfo,
        pub psi: socket_info,
    }

    // Types used for listing network connections.

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct __c_anonymous_p_st1 {
        pub __p_forw: *mut libc::c_void,
        pub __p_back: *mut libc::c_void,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub union __c_anonymous_p_un {
        pub p_st1: __c_anonymous_p_st1,
        pub __p_starttime: libc::timeval,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct extern_proc {
        pub p_un: __c_anonymous_p_un,
        pub p_vmspace: *mut vmspace,
        pub p_sigacts: *mut libc::c_void,
        pub p_flag: libc::c_int,
        pub p_stat: libc::c_char,
        pub p_pid: libc::pid_t,
        pub p_oppid: libc::pid_t,
        pub p_dupfd: libc::c_int,
        pub user_stack: caddr_t,
        pub exit_thread: *mut libc::c_void,
        pub p_debugger: libc::c_int,
        pub sigwait: libc::boolean_t,
        pub p_estcpu: libc::c_uint,
        pub p_cpticks: libc::c_int,
        pub p_pctcpu: fixpt_t,
        pub p_wchan: *mut libc::c_void,
        pub p_wmesg: *mut libc::c_char,
        pub p_swtime: libc::c_uint,
        pub p_slptime: libc::c_uint,
        pub p_realtimer: libc::itimerval,
        pub p_rtime: libc::timeval,
        pub p_uticks: u_quad_t,
        pub p_sticks: u_quad_t,
        pub p_iticks: u_quad_t,
        pub p_traceflag: libc::c_int,
        pub p_tracep: *mut libc::c_void,
        pub p_siglist: libc::c_int,
        pub p_textvp: *mut libc::c_void,
        pub p_holdcnt: libc::c_int,
        pub p_sigmask: libc::sigset_t,
        pub p_sigignore: libc::sigset_t,
        pub p_sigcatch: libc::sigset_t,
        pub p_priority: libc::c_uchar,
        pub p_usrpri: libc::c_uchar,
        pub p_nice: libc::c_char,
        pub p_comm: [libc::c_char; libc::MAXCOMLEN + 1],
        pub p_pgrp: *mut libc::c_void,
        pub p_addr: *mut libc::c_void,
        pub p_xstat: libc::c_ushort,
        pub p_acflag: libc::c_ushort,
        pub p_ru: *mut libc::c_void,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct _pcred {
        /// Opaque content.
        pub pc_lock: [libc::c_char; 72],
        /// Current credentials.
        pub pc_ucred: *mut libc::c_void,
        /// Real user identifier.
        pub p_ruid: libc::uid_t,
        /// Saved effective user identifier.
        pub p_svuid: libc::uid_t,
        /// Real group identifier.
        pub p_rgid: libc::gid_t,
        /// Saved effective group identifier.
        pub p_svgid: libc::gid_t,
        /// Reference count.
        pub p_refcnt: libc::c_int,
    }

    pub const NGROUPS_MAX: libc::c_int = 16;
    pub const NGROUPS: libc::c_int = NGROUPS_MAX;

    pub const WMESGLEN: libc::c_int = 7;

    pub const COMAPT_MAXLOGNAME: libc::c_int = 12;

    #[allow(non_camel_case_types)]
    pub type caddr_t = *mut libc::c_void;

    #[allow(non_camel_case_types)]
    pub type segsz_t = i32;

    #[allow(non_camel_case_types)]
    pub type fixpt_t = u32;

    #[allow(non_camel_case_types)]
    pub type u_quad_t = u64;

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct _ucred {
        /// Reference count.
        pub cr_ref: i32,
        /// Effective user identifier.
        pub cr_uid: libc::uid_t,
        /// Group count.
        pub cr_ngroups: libc::c_short,
        /// Group identifiers.
        pub cr_groups: [libc::gid_t; NGROUPS as usize],
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct vmspace {
        // `dummy*` is literally what is used in the original header.
        pub dummy: i32,
        pub dummy2: caddr_t,
        pub dummy3: [i32; 5],
        pub dummy4: [caddr_t; 3],
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct eproc {
        /// Process address.
        pub e_paddr: *mut libc::c_void,
        /// Session pointer.
        pub e_sess: *mut libc::c_void,
        /// Process credentials.
        pub e_pcred: _pcred,
        /// Current credentials.
        pub e_ucred: _ucred,
        /// Address space.
        pub e_vm: vmspace,
        /// Parent process identifier.
        pub e_ppid: libc::pid_t,
        /// Process group identifier.
        pub e_pgid: libc::pid_t,
        /// Job control counter.
        pub e_jobc: libc::c_short,
        /// Controlling TTY device identifier.
        pub e_tdev: libc::dev_t,
        /// Controlling TTY process group identifier.
        pub e_tpgid: libc::pid_t,
        /// Controlling TTY session pointer.
        pub e_tsess: *mut libc::c_void,
        /// Waiting channel message.
        pub e_wmesg: [libc::c_char; WMESGLEN as usize + 1],
        /// Text size.
        pub e_xsize: segsz_t,
        /// Text resident set size.
        pub e_xrssize: libc::c_short,
        /// Text reference count.
        pub e_xccount: libc::c_short,
        pub e_xswrss: libc::c_short,
        pub e_flag: i32,
        pub e_login: [libc::c_char; COMAPT_MAXLOGNAME as usize],
        pub e_spare: [i32; 4],
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct kinfo_proc {
        pub kp_proc: extern_proc,
        pub kp_eproc: eproc,
    }
}

#[cfg(target_os = "macos")]
pub use self::macos::*;
