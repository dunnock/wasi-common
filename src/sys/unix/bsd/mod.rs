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

    use std::{
        ffi::{CStr, CString, OsString},
        fmt, fs, io, mem,
        os::unix::prelude::*,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering::SeqCst},
    };

    #[derive(Eq, PartialEq, Ord, PartialOrd, Debug, Copy, Clone, Hash)]
    pub struct FileTime {
        seconds: i64,
        nanos: u32,
    }

    impl FileTime {
        pub fn from_nanoseconds(ns: crate::host::__wasi_timestamp_t) -> Self {
            FileTime {
                seconds: 0,
                nanos: ns as u32,
            }
        }
        pub fn from_last_modification_time(meta: &fs::Metadata) -> FileTime {
            FileTime {
                seconds: meta.mtime(),
                nanos: meta.mtime_nsec() as u32,
            }
        }

        pub fn from_last_access_time(meta: &fs::Metadata) -> FileTime {
            FileTime {
                seconds: meta.atime(),
                nanos: meta.atime_nsec() as u32,
            }
        }

        pub fn seconds(&self) -> i64 {
            self.seconds
        }

        pub fn unix_seconds(&self) -> i64 {
            self.seconds - if cfg!(windows) { 11644473600 } else { 0 }
        }

        pub fn nanoseconds(&self) -> u32 {
            self.nanos
        }
    }

    impl fmt::Display for FileTime {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}.{:09}s", self.seconds, self.nanos)
        }
    }

    fn get_times(
        atime: Option<FileTime>,
        mtime: Option<FileTime>,
        current: impl FnOnce() -> io::Result<fs::Metadata>,
    ) -> io::Result<Option<(FileTime, FileTime)>> {
        let pair = match (atime, mtime) {
            (Some(a), Some(b)) => (a, b),
            (None, None) => return Ok(None),
            (Some(a), None) => {
                let meta = current()?;
                (a, FileTime::from_last_modification_time(&meta))
            }
            (None, Some(b)) => {
                let meta = current()?;
                (FileTime::from_last_access_time(&meta), b)
            }
        };
        Ok(Some(pair))
    }

    fn to_timeval(ft: &FileTime) -> libc::timeval {
        libc::timeval {
            tv_sec: ft.seconds(),
            tv_usec: (ft.nanoseconds() / 1000) as libc::suseconds_t,
        }
    }

    fn to_timespec(ft: &Option<FileTime>) -> libc::timespec {
        if let &Some(ft) = ft {
            libc::timespec {
                tv_sec: ft.seconds(),
                tv_nsec: ft.nanoseconds() as _,
            }
        } else {
            libc::timespec {
                tv_sec: 0,
                tv_nsec: utime_omit(),
            }
        }
    }

    pub fn utimensat(
        fd: &impl AsRawFd,
        path: impl AsRef<Path>,
        atime: Option<FileTime>,
        mtime: Option<FileTime>,
        symlink: bool,
    ) -> io::Result<()> {
        static ADDR: AtomicUsize = AtomicUsize::new(0);
        let func: Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_char,
                *const libc::timespec,
                libc::c_int,
            ) -> libc::c_int,
        > = unsafe {
            fetch(&ADDR, CStr::from_bytes_with_nul_unchecked(b"utimensat\0"))
                .map(|sym| mem::transmute(sym))
        };

        // if let Some(func) = func {
        //     let flags = if symlink {
        //         libc::AT_SYMLINK_NOFOLLOW
        //     } else {
        //         0
        //     };

        //     let p = CString::new(path.as_ref().as_os_str().as_bytes())?;
        //     let times = [to_timespec(&atime), to_timespec(&mtime)];
        //     let rc = unsafe { func(fd.as_raw_fd(), p.as_ptr(), times.as_ptr(), flags) };
        //     if rc == 0 {
        //         Ok(())
        //     } else {
        //         Err(io::Error::last_os_error())
        //     }
        // } else {
        let p = CString::new(path.as_ref().as_os_str().as_bytes())?;
        let fd =
            unsafe { libc::openat(fd.as_raw_fd(), p.as_ptr(), libc::O_NOFOLLOW | libc::O_RDWR) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        let f = unsafe { fs::File::from_raw_fd(fd) };
        let (atime, mtime) = match get_times(atime, mtime, || f.metadata())? {
            Some(pair) => pair,
            None => return Ok(()),
        };
        let times = [to_timeval(&atime), to_timeval(&mtime)];
        let rc = unsafe { libc::futimes(f.as_raw_fd(), times.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
        // }
    }

    fn fetch(cache: &AtomicUsize, name: &CStr) -> Option<usize> {
        match cache.load(SeqCst) {
            0 => {}
            1 => return None,
            n => return Some(n),
        }
        let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr() as *const _) };
        let (val, ret) = if sym.is_null() {
            (1, None)
        } else {
            (sym as usize, Some(sym as usize))
        };
        cache.store(val, SeqCst);
        return ret;
    }
}
