use ed25519_dalek::SigningKey;
use getrandom::fill;
use std::{fs, io, path::Path};

pub fn load_or_create(path: &Path) -> io::Result<(SigningKey, bool)> {
    if path.exists() {
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "signing key file must contain exactly 32 bytes"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok((SigningKey::from_bytes(&seed), false));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut seed = [0u8; 32];
    fill(&mut seed).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("OS randomness unavailable: {e}")))?;
    fs::write(path, seed)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok((SigningKey::from_bytes(&seed), true))
}

pub fn generate(path: &Path, force: bool) -> io::Result<()> {
    if path.exists() && !force {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "key file already exists (use --force to overwrite)"));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut seed = [0u8; 32];
    fill(&mut seed).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("OS randomness unavailable: {e}")))?;
    fs::write(path, seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
