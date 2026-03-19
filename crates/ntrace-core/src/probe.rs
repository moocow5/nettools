//! Probe tracking: maps outgoing probes to incoming ICMP responses.

use std::collections::HashMap;
use std::time::Instant;

/// Uniquely identifies a probe by its ICMP identifier + sequence number
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    pub identifier: u16,
    pub sequence: u16,
}

/// Record of a sent probe
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub ttl: u8,
    pub probe_num: u8,
    pub sent_at: Instant,
    pub key: ProbeKey,
}

/// Tracks outstanding probes and matches incoming responses
#[derive(Debug)]
pub struct ProbeTracker {
    identifier: u16,
    next_seq: u16,
    outstanding: HashMap<ProbeKey, ProbeRecord>,
}

impl ProbeTracker {
    /// Create a new tracker with the given ICMP identifier
    pub fn new(identifier: u16) -> Self {
        Self {
            identifier,
            next_seq: 0,
            outstanding: HashMap::new(),
        }
    }

    /// Get the ICMP identifier used by this tracker
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Register a new outgoing probe and return its (identifier, sequence) for the ICMP packet
    pub fn register_probe(&mut self, ttl: u8, probe_num: u8) -> ProbeKey {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let key = ProbeKey {
            identifier: self.identifier,
            sequence: seq,
        };

        let record = ProbeRecord {
            ttl,
            probe_num,
            sent_at: Instant::now(),
            key,
        };

        self.outstanding.insert(key, record);
        key
    }

    /// Try to match an incoming response to an outstanding probe.
    /// Returns the probe record if matched (and removes it from outstanding).
    pub fn match_response(&mut self, identifier: u16, sequence: u16) -> Option<ProbeRecord> {
        let key = ProbeKey {
            identifier,
            sequence,
        };
        self.outstanding.remove(&key)
    }

    /// Remove all probes that have been outstanding longer than the given timeout
    pub fn expire_probes(&mut self, timeout: std::time::Duration) -> Vec<ProbeRecord> {
        let now = Instant::now();
        let mut expired = Vec::new();

        self.outstanding.retain(|_, record| {
            if now.duration_since(record.sent_at) > timeout {
                expired.push(record.clone());
                false
            } else {
                true
            }
        });

        expired
    }

    /// Number of outstanding (unmatched) probes
    pub fn outstanding_count(&self) -> usize {
        self.outstanding.len()
    }

    /// Check if there are any outstanding probes
    pub fn has_outstanding(&self) -> bool {
        !self.outstanding.is_empty()
    }
}

/// Key for matching UDP/TCP probes by (src_port, dst_port) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortProbeKey {
    pub src_port: u16,
    pub dst_port: u16,
}

/// Record of a sent UDP/TCP probe tracked by port pair.
#[derive(Debug, Clone)]
pub struct PortProbeRecord {
    pub ttl: u8,
    pub probe_num: u8,
    pub sent_at: Instant,
    pub key: PortProbeKey,
}

/// Tracks outstanding UDP/TCP probes and matches incoming ICMP error responses
/// by extracting (src_port, dst_port) from the quoted original L4 header.
#[derive(Debug)]
pub struct PortProbeTracker {
    outstanding: HashMap<PortProbeKey, PortProbeRecord>,
}

impl PortProbeTracker {
    /// Create a new port-based probe tracker.
    pub fn new() -> Self {
        Self {
            outstanding: HashMap::new(),
        }
    }

    /// Register a new outgoing UDP/TCP probe with its source and destination ports.
    pub fn register_probe(
        &mut self,
        src_port: u16,
        dst_port: u16,
        ttl: u8,
        probe_num: u8,
    ) -> PortProbeKey {
        let key = PortProbeKey { src_port, dst_port };
        let record = PortProbeRecord {
            ttl,
            probe_num,
            sent_at: Instant::now(),
            key,
        };
        self.outstanding.insert(key, record);
        key
    }

    /// Try to match an incoming ICMP error response by (src_port, dst_port) extracted
    /// from the quoted original L4 header. Returns the probe record if matched.
    pub fn match_response(&mut self, src_port: u16, dst_port: u16) -> Option<PortProbeRecord> {
        let key = PortProbeKey { src_port, dst_port };
        self.outstanding.remove(&key)
    }

    /// Remove all probes that have been outstanding longer than the given timeout.
    pub fn expire_probes(&mut self, timeout: std::time::Duration) -> Vec<PortProbeRecord> {
        let now = Instant::now();
        let mut expired = Vec::new();

        self.outstanding.retain(|_, record| {
            if now.duration_since(record.sent_at) > timeout {
                expired.push(record.clone());
                false
            } else {
                true
            }
        });

        expired
    }

    /// Number of outstanding (unmatched) probes.
    pub fn outstanding_count(&self) -> usize {
        self.outstanding.len()
    }
}

/// Generate a pseudo-random identifier for probe tracking.
/// Combines process ID with system time to avoid collisions.
pub fn generate_identifier() -> u16 {
    let pid = std::process::id();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    ((pid ^ time) & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_match() {
        let mut tracker = ProbeTracker::new(0x1234);

        let key1 = tracker.register_probe(1, 0);
        let key2 = tracker.register_probe(1, 1);
        let key3 = tracker.register_probe(2, 0);

        assert_eq!(tracker.outstanding_count(), 3);

        // Match the second probe
        let record = tracker.match_response(key2.identifier, key2.sequence).unwrap();
        assert_eq!(record.ttl, 1);
        assert_eq!(record.probe_num, 1);
        assert_eq!(tracker.outstanding_count(), 2);

        // Match first
        let record = tracker.match_response(key1.identifier, key1.sequence).unwrap();
        assert_eq!(record.ttl, 1);
        assert_eq!(record.probe_num, 0);

        // Match third
        let record = tracker.match_response(key3.identifier, key3.sequence).unwrap();
        assert_eq!(record.ttl, 2);
        assert_eq!(record.probe_num, 0);

        assert_eq!(tracker.outstanding_count(), 0);
    }

    #[test]
    fn test_no_match_wrong_id() {
        let mut tracker = ProbeTracker::new(0x1234);
        tracker.register_probe(1, 0);

        assert!(tracker.match_response(0x5678, 0).is_none());
        assert_eq!(tracker.outstanding_count(), 1);
    }

    #[test]
    fn test_no_match_wrong_seq() {
        let mut tracker = ProbeTracker::new(0x1234);
        tracker.register_probe(1, 0);

        assert!(tracker.match_response(0x1234, 999).is_none());
    }

    #[test]
    fn test_expire_probes() {
        let mut tracker = ProbeTracker::new(0x1234);
        tracker.register_probe(1, 0);
        tracker.register_probe(2, 0);

        // With zero timeout, all should expire
        let expired = tracker.expire_probes(std::time::Duration::ZERO);
        assert_eq!(expired.len(), 2);
        assert_eq!(tracker.outstanding_count(), 0);
    }

    #[test]
    fn test_sequence_wrapping() {
        let mut tracker = ProbeTracker::new(0x1234);

        // Sequences should increment
        let k1 = tracker.register_probe(1, 0);
        let k2 = tracker.register_probe(1, 1);
        assert_eq!(k1.sequence, 0);
        assert_eq!(k2.sequence, 1);
    }

    #[test]
    fn test_generate_identifier() {
        let id1 = generate_identifier();
        let id2 = generate_identifier();
        // Can't guarantee they're different, but they should be valid u16
        assert!(id1 <= u16::MAX);
        assert!(id2 <= u16::MAX);
    }
}
