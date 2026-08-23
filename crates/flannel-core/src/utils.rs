//! Port of pkg/utils/utils.go. CONTRACT STUB: atomic write helper is stable;
//! CopyFileAtomic completed in P0.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Atomically write `data` to `path` with the given unix mode, mirroring
/// renameio.WriteFile (temp file in target dir + fsync + rename).
pub fn write_file_atomic(path: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    let path = std::path::Path::new(path);
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let tmp_path = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let mut f = std::fs::File::create(&tmp_path)?;
    f.write_all(data)?;
    f.sync_all()?;
    let perms = std::os::unix::fs::PermissionsExt::from_mode(mode);
    std::fs::set_permissions(&tmp_path, perms)?;
    std::fs::rename(&tmp_path, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp_path);
    })
}

/// Atomically copy `src_file_path` to `dest_dir/dest_file_name` via a temp
/// file that is renamed into place, applying the source file's permission
/// bits to the destination. Port of Go `utils.CopyFileAtomic` (error
/// messages match; Go's `%q` is rendered as plain double quotes).
pub fn copy_file_atomic(
    src_file_path: &str,
    dest_dir: &str,
    temp_file_name: &str,
    dest_file_name: &str,
) -> io::Result<()> {
    let dest_dir_path = Path::new(dest_dir);
    let temp_file_path = dest_dir_path.join(temp_file_name);
    // check temp filepath and remove old file if exists
    if temp_file_path.exists() {
        if let Err(err) = std::fs::remove_file(&temp_file_path) {
            return Err(other_err(format!(
                "cannot remove old temp file {}: {err}",
                quoted_path(&temp_file_path)
            )));
        }
    }

    // create temp file
    let (mut temp_file, temp_path) = create_temp(dest_dir_path, temp_file_name).map_err(|err| {
        other_err(format!(
            "cannot create temp file {} in {}: {err}",
            quoted_str(temp_file_name),
            quoted_str(dest_dir)
        ))
    })?;

    let mut src_file = File::open(src_file_path).map_err(|err| {
        other_err(format!(
            "cannot open file {}: {err}",
            quoted_str(src_file_path)
        ))
    })?;

    // Copy file to tempfile
    if let Err(err) = io::copy(&mut src_file, &mut temp_file) {
        drop(temp_file); // Go: _ = f.Close()
                         // Go (upstream) removes the pattern path here, not the randomized
                         // temp file name; mirrored for identical semantics.
        let _ = std::fs::remove_file(&temp_file_path);
        return Err(other_err(format!(
            "cannot write data to temp file {}: {err}",
            quoted_path(&temp_file_path)
        )));
    }
    if let Err(err) = temp_file.sync_all() {
        return Err(other_err(format!(
            "cannot flush temp file {}: {err}",
            quoted_path(&temp_file_path)
        )));
    }
    // Go checks f.Close() here ("cannot close temp file"); in Rust close
    // happens on drop without a checkable error and sync_all above already
    // flushed the data, so there is nothing extra to verify.
    drop(temp_file);

    // change file mode if different
    let dest_file_path = dest_dir_path.join(dest_file_name);
    match std::fs::metadata(&dest_file_path) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let src_file_stat = std::fs::metadata(src_file_path)?;

    std::fs::set_permissions(&temp_path, src_file_stat.permissions()).map_err(|err| {
        other_err(format!(
            "cannot set stat on temp file {}: {err}",
            quoted_path(&temp_path)
        ))
    })?;

    // replace file with tempfile
    std::fs::rename(&temp_path, &dest_file_path).map_err(|err| {
        other_err(format!(
            "cannot replace {} with temp file {}: {err}",
            quoted_path(&dest_file_path),
            quoted_path(&temp_path)
        ))
    })?;

    Ok(())
}

/// Emulate Go `os.CreateTemp(dir, pattern)`: the last `*` in the pattern is
/// replaced by a random decimal string (appended when there is none) and the
/// file is created with O_EXCL and mode 0600. Returns the file and its
/// actual path.
fn create_temp(dir: &Path, pattern: &str) -> io::Result<(File, PathBuf)> {
    let (prefix, suffix) = match pattern.rfind('*') {
        Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
        None => (pattern, ""),
    };
    // Go retries forever on name collisions; bound attempts defensively.
    for _ in 0..1000 {
        let path = dir.join(format!("{prefix}{}{suffix}", next_random()));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create unique temp file",
    ))
}

/// Go os.CreateTemp names the random part via `strconv.FormatUint(r, 10)`.
fn next_random() -> String {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    u64::from_le_bytes(bytes[..8].try_into().expect("uuid has 16 bytes")).to_string()
}

fn other_err(msg: String) -> io::Error {
    io::Error::other(msg)
}

fn quoted_path(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

fn quoted_str(s: &str) -> String {
    format!("\"{s}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn write_file_atomic_creates_with_mode_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netconf.json");
        write_file_atomic(path.to_str().unwrap(), b"{\"cniVersion\":\"1.0.0\"}", 0o644).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"cniVersion\":\"1.0.0\"}");
        assert_eq!(mode(&path), 0o644);
    }

    #[test]
    fn write_file_atomic_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netconf.json");
        write_file_atomic(path.to_str().unwrap(), b"old", 0o600).unwrap();
        write_file_atomic(path.to_str().unwrap(), b"new-data", 0o644).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new-data");
        assert_eq!(mode(&path), 0o644);
    }

    #[test]
    fn copy_file_atomic_copies_content_and_perms() {
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("src.conf");
        std::fs::write(&src, b"data-123").unwrap();
        std::fs::set_permissions(&src, PermissionsExt::from_mode(0o755)).unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        copy_file_atomic(
            src.to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
            ".tmp-",
            "dest.conf",
        )
        .unwrap();

        let dest = dest_dir.path().join("dest.conf");
        assert_eq!(std::fs::read(&dest).unwrap(), b"data-123");
        assert_eq!(mode(&dest), 0o755);
        // no stray temp files left behind
        assert_eq!(std::fs::read_dir(dest_dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn copy_file_atomic_replaces_existing_dest() {
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("src.conf");
        std::fs::write(&src, b"new").unwrap();
        std::fs::set_permissions(&src, PermissionsExt::from_mode(0o640)).unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let dest = dest_dir.path().join("dest.conf");
        std::fs::write(&dest, b"old-content").unwrap();
        std::fs::set_permissions(&dest, PermissionsExt::from_mode(0o600)).unwrap();

        copy_file_atomic(
            src.to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
            ".tmp-",
            "dest.conf",
        )
        .unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert_eq!(mode(&dest), 0o640);
    }

    #[test]
    fn copy_file_atomic_removes_stale_temp_file() {
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("src.conf");
        std::fs::write(&src, b"data").unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        // stale file at the exact (non-pattern) temp path
        std::fs::write(dest_dir.path().join(".tmp-"), b"stale").unwrap();

        copy_file_atomic(
            src.to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
            ".tmp-",
            "dest.conf",
        )
        .unwrap();

        assert_eq!(
            std::fs::read(dest_dir.path().join("dest.conf")).unwrap(),
            b"data"
        );
    }

    #[test]
    fn copy_file_atomic_pattern_with_star() {
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("src.conf");
        std::fs::write(&src, b"starred").unwrap();
        let dest_dir = tempfile::tempdir().unwrap();

        copy_file_atomic(
            src.to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
            "flannel-*.tmp",
            "dest.conf",
        )
        .unwrap();

        assert_eq!(
            std::fs::read(dest_dir.path().join("dest.conf")).unwrap(),
            b"starred"
        );
        assert_eq!(std::fs::read_dir(dest_dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn copy_file_atomic_missing_src_errors() {
        let dest_dir = tempfile::tempdir().unwrap();
        let err = copy_file_atomic(
            "/nonexistent/src.conf",
            dest_dir.path().to_str().unwrap(),
            ".tmp-",
            "dest.conf",
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot open file"), "{err}");
    }

    #[test]
    fn copy_file_atomic_missing_dest_dir_errors() {
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("src.conf");
        std::fs::write(&src, b"data").unwrap();
        let err = copy_file_atomic(
            src.to_str().unwrap(),
            "/nonexistent/dir",
            ".tmp-",
            "dest.conf",
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot create temp file"), "{err}");
    }
}
