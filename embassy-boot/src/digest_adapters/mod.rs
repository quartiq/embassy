#[cfg(feature = "ed25519-dalek")]
pub(crate) mod ed25519_dalek;

#[cfg(all(feature = "ed25519-salty", not(feature = "ed25519-dalek")))]
pub(crate) mod salty;
