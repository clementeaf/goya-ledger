//! Node operation mode — selects between full node and light client behavior.

use std::fmt;

/// Determines which subsystems and routes the node activates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    /// Full node: all routes, consensus, storage, P2P.
    Full,
    /// Light client: Starter-tier routes only, proxies writes to seed node.
    Light,
}

impl NodeMode {
    /// Resolve from `NODE_MODE` environment variable.
    /// Defaults to `Full` when unset or unrecognized.
    pub fn from_env() -> Self {
        std::env::var("NODE_MODE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(Self::Full)
    }

    pub fn is_light(self) -> bool {
        matches!(self, Self::Light)
    }
}

impl fmt::Display for NodeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Light => write!(f, "light"),
        }
    }
}

impl std::str::FromStr for NodeMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "light" => Ok(Self::Light),
            "full" => Ok(Self::Full),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_light() {
        assert_eq!("light".parse::<NodeMode>(), Ok(NodeMode::Light));
        assert_eq!("LIGHT".parse::<NodeMode>(), Ok(NodeMode::Light));
        assert_eq!("Light".parse::<NodeMode>(), Ok(NodeMode::Light));
    }

    #[test]
    fn parse_full() {
        assert_eq!("full".parse::<NodeMode>(), Ok(NodeMode::Full));
        assert_eq!("FULL".parse::<NodeMode>(), Ok(NodeMode::Full));
    }

    #[test]
    fn parse_unknown_is_err() {
        assert!("banana".parse::<NodeMode>().is_err());
        assert!("".parse::<NodeMode>().is_err());
    }

    #[test]
    fn is_light_correct() {
        assert!(NodeMode::Light.is_light());
        assert!(!NodeMode::Full.is_light());
    }

    #[test]
    fn display() {
        assert_eq!(NodeMode::Full.to_string(), "full");
        assert_eq!(NodeMode::Light.to_string(), "light");
    }

    #[test]
    fn from_env_defaults_to_full() {
        // When NODE_MODE is not set, should default to Full.
        // (This test assumes NODE_MODE is not set in the test environment.)
        std::env::remove_var("NODE_MODE");
        assert_eq!(NodeMode::from_env(), NodeMode::Full);
    }

    #[test]
    fn from_env_reads_light() {
        std::env::set_var("NODE_MODE", "light");
        assert_eq!(NodeMode::from_env(), NodeMode::Light);
        std::env::remove_var("NODE_MODE");
    }
}
