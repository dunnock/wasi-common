pub(crate) mod hostcalls_impl;
pub(crate) mod osfile;

pub(crate) mod fdentry_impl {
    use crate::{sys::host_impl, Result};
    use std::os::unix::prelude::AsRawFd;

    pub(crate) unsafe fn isatty(fd: &impl AsRawFd) -> Result<bool> {
        let res = libc::isatty(fd.as_raw_fd());
        if res == 0 {
            Ok(true)
        } else {
            match nix::errno::Errno::last() {
                nix::errno::Errno::ENOTTY => Ok(false),
                x => Err(host_impl::errno_from_nix(x)),
            }
        }
    }
}

pub(crate) mod host_impl {
    use super::super::host_impl::dirent_filetype_from_host;
    use crate::{host, memory, Result};

    pub(crate) const O_RSYNC: nix::fcntl::OFlag = nix::fcntl::OFlag::O_SYNC;

    pub(crate) fn dirent_from_host(
        host_entry: &nix::libc::dirent,
    ) -> Result<host::__wasi_dirent_t> {
        let mut entry = unsafe { std::mem::zeroed::<host::__wasi_dirent_t>() };
        let d_type = dirent_filetype_from_host(host_entry)?;
        entry.d_ino = memory::enc_inode(host_entry.d_ino);
        entry.d_next = memory::enc_dircookie(host_entry.d_seekoff);
        entry.d_namlen = memory::enc_u32(u32::from(host_entry.d_namlen));
        entry.d_type = memory::enc_filetype(d_type);
        Ok(entry)
    }
}

pub(crate) mod fs_helpers {
    use cfg_if::cfg_if;

    pub(crate) fn utime_now() -> libc::c_long {
        cfg_if! {
            if #[cfg(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "dragonfly"
            ))] {
                -1
            } else if #[cfg(target_os = "openbsd")] {
                // https://github.com/openbsd/src/blob/master/sys/sys/stat.h#L187
                -2
            } else if #[cfg(target_os = "netbsd" )] {
                // http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/sys/stat.h?rev=1.69&content-type=text/x-cvsweb-markup&only_with_tag=MAIN
                1_073_741_823
            }
        }
    }

    pub(crate) fn utime_omit() -> libc::c_long {
        cfg_if! {
            if #[cfg(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "dragonfly"
            ))] {
                -2
            } else if #[cfg(target_os = "openbsd")] {
                // https://github.com/openbsd/src/blob/master/sys/sys/stat.h#L187
                -1
            } else if #[cfg(target_os = "netbsd")] {
                // http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/sys/stat.h?rev=1.69&content-type=text/x-cvsweb-markup&only_with_tag=MAIN
                1_073_741_822
            }
        }
    }
}
