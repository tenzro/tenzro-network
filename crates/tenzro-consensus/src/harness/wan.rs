//! Wide-area network model: regions, delays, jitter, loss and bandwidth.

use rand::Rng;
use rand::rngs::StdRng;

/// Ten cloud regions: US East, US West, South America, Europe West, Europe
/// Central, South Asia, Southeast Asia, Northeast Asia, Oceania, Africa.
pub const REGIONS: usize = 10;

/// Round-trip times between the ten regions, milliseconds (each pair the
/// mean of both measured directions).
pub const RTT_MS: [[u32; REGIONS]; REGIONS] = [
    [2, 127, 132, 110, 111, 203, 242, 166, 221, 233],
    [127, 2, 187, 163, 165, 248, 188, 131, 165, 288],
    [132, 187, 2, 193, 218, 298, 346, 270, 317, 341],
    [110, 163, 193, 2, 66, 138, 192, 217, 260, 168],
    [111, 165, 218, 66, 2, 144, 200, 255, 308, 175],
    [203, 248, 298, 138, 144, 2, 93, 177, 271, 291],
    [242, 188, 346, 192, 200, 93, 2, 175, 305, 340],
    [166, 131, 270, 217, 255, 177, 175, 2, 138, 407],
    [221, 165, 317, 260, 308, 271, 305, 138, 2, 417],
    [233, 288, 341, 168, 175, 291, 340, 407, 417, 2],
];

/// Network parameters of one emulated run.
#[derive(Debug, Clone)]
pub struct Wan {
    /// Region of each node.
    pub region: Vec<usize>,
    /// Relative jitter applied to each one-way delay (0.05 = +-5%).
    pub jitter: f64,
    /// Probability a message needs one retransmission (QUIC recovers a lost
    /// packet after about one round trip).
    pub loss: f64,
    /// Per-node egress bandwidth, bits per second.
    pub egress_bps: f64,
}

impl Wan {
    /// `n` nodes spread round-robin over `regions` regions.
    pub fn spread(n: usize, regions: usize) -> Self {
        Self {
            region: (0..n).map(|i| i % regions.clamp(1, REGIONS)).collect(),
            jitter: 0.05,
            loss: 0.0,
            egress_bps: 1e9,
        }
    }

    /// One-way delay from `a` to `b` in microseconds, with jitter and loss.
    pub fn delay_us(&self, a: usize, b: usize, rng: &mut StdRng) -> u64 {
        let rtt = RTT_MS[self.region[a]][self.region[b]] as f64 * 1_000.0;
        let j = if self.jitter > 0.0 {
            rng.gen_range(-self.jitter..self.jitter)
        } else {
            0.0
        };
        let mut d = rtt / 2.0 * (1.0 + j);
        if self.loss > 0.0 && rng.gen_bool(self.loss) {
            d += rtt;
        }
        d.max(1.0) as u64
    }

    /// Microseconds `bytes` occupy the sender's uplink.
    pub fn serialization_us(&self, bytes: usize) -> u64 {
        ((bytes as f64 * 8.0) / self.egress_bps * 1e6).ceil() as u64
    }
}
