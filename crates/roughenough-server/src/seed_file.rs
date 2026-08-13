use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

use zeroize::Zeroizing;

const MAX_SEED_FILE_BYTES: usize = 64 * 1024;

/// A zeroizing wrapper around a seed file's contents. Deliberately not `Clone` or `Copy`
/// to prevent accidental copies of the seed file's contents.
pub struct SeedFileContents {
    bytes: Zeroizing<Vec<u8>>,
    len: usize,
}

impl SeedFileContents {
    pub fn encoded_value(&self) -> io::Result<&str> {
        let value = std::str::from_utf8(&self.bytes[..self.len]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("seed file is not valid UTF-8: {error}"),
            )
        })?;
        let value = value.trim();
        if value.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "seed file is empty",
            ));
        }

        Ok(value)
    }
}

pub fn read(path: &Path) -> io::Result<SeedFileContents> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }

    let mut file = options.open(path)?;
    validate_metadata(&file)?;

    let mut contents = Zeroizing::new(vec![0; MAX_SEED_FILE_BYTES + 1]);
    let mut bytes_read = 0;
    while bytes_read < contents.len() {
        let count = file.read(&mut contents[bytes_read..])?;
        if count == 0 {
            break;
        }
        bytes_read += count;
    }

    if bytes_read > MAX_SEED_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("seed file exceeds {MAX_SEED_FILE_BYTES} bytes"),
        ));
    }

    Ok(SeedFileContents {
        bytes: contents,
        len: bytes_read,
    })
}

fn validate_metadata(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seed file is not a regular file",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "seed file must not be accessible by group or other users",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let suffix = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "roughenough-seed-file-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn write_seed_file(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn reads_trimmed_seed_value() {
        let dir = temp_dir();
        let path = dir.join("seed");
        write_seed_file(&path, b"  seed://0123\n");

        let contents = read(&path).unwrap();
        assert_eq!(contents.encoded_value().unwrap(), "seed://0123");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_empty_invalid_utf8_and_oversized_files() {
        let dir = temp_dir();

        for (name, value) in [
            ("empty", Vec::new()),
            ("whitespace", b" \n\t".to_vec()),
            ("invalid-utf8", vec![0xff]),
        ] {
            let path = dir.join(name);
            write_seed_file(&path, &value);
            assert!(read(&path).unwrap().encoded_value().is_err());
        }

        let oversized = dir.join("oversized");
        write_seed_file(&oversized, &vec![b'a'; MAX_SEED_FILE_BYTES + 1]);
        assert!(read(&oversized).is_err());

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_permissive_files_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = temp_dir();
        let path = dir.join("seed");
        write_seed_file(&path, b"seed://0123");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            read(&path).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("seed-link");
        symlink(&path, &link).unwrap();
        assert!(read(&link).is_err());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_non_regular_files() {
        let dir = temp_dir();
        assert!(read(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
