//! Predefined KDF profiles for OPKE.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfProfile {
    pub name: &'static str,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

pub const PROFILE_PRODUCTION: KdfProfile = KdfProfile {
    name: "production",
    m_kib: 8_388_608, // 8 GiB
    t: 64,
    p: 8,
};

pub const PROFILE_STANDARD: KdfProfile = KdfProfile {
    name: "standard",
    m_kib: 8_388_608, // 8 GiB
    t: 64,
    p: 8,
};

pub const PROFILE_MODERATE: KdfProfile = KdfProfile {
    name: "moderate",
    m_kib: 1_048_576, // 1 GiB
    t: 16,
    p: 4,
};

pub const PROFILE_FAST: KdfProfile = KdfProfile {
    name: "fast",
    m_kib: 65_536, // 64 MiB
    t: 2,
    p: 2,
};

pub const PROFILE_TEST: KdfProfile = KdfProfile {
    name: "test",
    m_kib: 65_536, // 64 MiB
    t: 2,
    p: 2,
};

pub fn get_profile(name: &str) -> Option<KdfProfile> {
    match name.to_lowercase().as_str() {
        "production" => Some(PROFILE_PRODUCTION),
        "standard" => Some(PROFILE_STANDARD),
        "moderate" => Some(PROFILE_MODERATE),
        "fast" => Some(PROFILE_FAST),
        #[cfg(test)]
        "test" => Some(PROFILE_TEST),
        _ => None,
    }
}
