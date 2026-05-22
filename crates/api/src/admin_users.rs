use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use bcrypt::verify as verify_bcrypt;
use haltchain_db::DbBackend;
use uuid::Uuid;

pub struct AdminUser {
    #[allow(dead_code)]
    pub id: Uuid,
    pub email: String,
}

pub async fn find_and_verify_backend(
    db: &DbBackend,
    email: &str,
    password: &str,
) -> Option<AdminUser> {
    let row = db.admin_fetch_login_row(email).await.ok()??;
    let (password_hash, is_active) = row;
    if !is_active {
        return None;
    }
    if !verify_password_hash(&password_hash, password) {
        return None;
    }
    Some(AdminUser {
        id: Uuid::nil(),
        email: email.to_string(),
    })
}

fn verify_password_hash(stored_hash: &str, password: &str) -> bool {
    if stored_hash.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(stored_hash) {
            return Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok();
        }
        return false;
    }

    if stored_hash.starts_with("$2a$")
        || stored_hash.starts_with("$2b$")
        || stored_hash.starts_with("$2y$")
    {
        return verify_bcrypt(password, stored_hash).unwrap_or(false);
    }

    false
}

pub fn validate_password_strength(password: &str) -> Result<(), &'static str> {
    if password.len() < 12 {
        return Err("password must be at least 12 characters");
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("password must contain an uppercase letter");
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("password must contain a lowercase letter");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("password must contain a digit");
    }
    Ok(())
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Argon2 hashing is infallible for valid salt")
        .to_string()
}

pub async fn bootstrap_if_configured(db: &DbBackend) {
    let email = std::env::var("HALTCHAIN_BOOTSTRAP_ADMIN_EMAIL").ok();
    let password = std::env::var("HALTCHAIN_BOOTSTRAP_ADMIN_PASSWORD").ok();

    match (email, password) {
        (Some(email), Some(password)) => {
            if let Err(reason) = validate_password_strength(&password) {
                tracing::warn!(email = %email, reason, "bootstrap admin password is weak");
            }
            let hash = hash_password(&password);
            match db.admin_bootstrap_upsert(&email, &hash).await {
                Ok(()) => tracing::info!(email = %email, "bootstrap admin account synced"),
                Err(e) => tracing::error!("failed to sync bootstrap admin user: {e}"),
            }
        }
        _ => {
            let count = db.admin_users_count().await.unwrap_or(0);
            if count == 0 {
                tracing::warn!(
                    "no admin users exist — set HALTCHAIN_BOOTSTRAP_ADMIN_EMAIL and \
                     HALTCHAIN_BOOTSTRAP_ADMIN_PASSWORD to create the first account"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bcrypt::hash as hash_bcrypt;

    use super::{hash_password, verify_password_hash};

    #[test]
    fn verifies_argon2_password_hash() {
        let hash = hash_password("admin123");
        assert!(verify_password_hash(&hash, "admin123"));
        assert!(!verify_password_hash(&hash, "wrong"));
    }

    #[test]
    fn verifies_legacy_bcrypt_password_hash() {
        let bcrypt_hash = hash_bcrypt("admin123", 12).expect("bcrypt hash failed");
        assert!(verify_password_hash(&bcrypt_hash, "admin123"));
        assert!(!verify_password_hash(&bcrypt_hash, "wrong"));
    }
}
