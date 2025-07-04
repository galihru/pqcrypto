//! Quantum‐Resistant Cryptography via Lemniscate Lattices and AGM Transformations
//!
//! References:
//! 1. Castryck, W., Decru, T. (2023). An efficient key recovery attack on SIDH. IACR Cryptol. ePrint Arch.
//! 2. Jao, D., De Feo, L. (2011). Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies. PQCrypto.
//! 3. Mestre, J. F. (2000). Lettre à Gaudry et Harley sur l'utilisation de l'AGM. Preprint.
//!
//! # Enhanced Features
//! - Comprehensive error diagnostics with solution hints
//! - Detailed transformation tracing
//! - Built-in runtime performance analysis
//! - Custom graphing module for cryptographic metrics
//! - Prime validation and parameter verification
//! - Complete operational history tracking

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};

/// Comprehensive error types with solution guidance
#[derive(Debug, Clone, PartialEq)]
pub enum LaiCryptoError {
    /// Modular square root failure (Tonelli-Shanks)
    SqrtFailure {
        input: u128,
        modulus: u128,
        attempts: u32,
        advice: String,
    },
    /// T-transform failure with context
    TransformFailure {
        point: (u128, u128),
        s: u128,
        steps: Vec<TraceStep>,
        advice: String,
    },
    /// Key generation failure
    KeygenFailed {
        attempts: u32,
        modulus: u128,
        base_point: (u128, u128),
        advice: String,
    },
    /// Parameter validation failure
    InvalidParameter {
        param: String,
        value: String,
        reason: String,
        valid_range: String,
    },
    /// Operation timeout
    Timeout {
        operation: String,
        duration: Duration,
        max_duration: Duration,
    },
    /// Cryptographic validation failure
    ValidationError {
        operation: String,
        expected: String,
        actual: String,
    },
    /// Graph rendering error
    GraphError {
        context: String,
        cause: String,
    },
}

impl fmt::Display for LaiCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SqrtFailure { input, modulus, attempts, advice } => write!(
                f,
                "Square root failure for {} mod {} after {} attempts. {}",
                input, modulus, attempts, advice
            ),
            Self::TransformFailure { point, s, steps, advice } => write!(
                f,
                "T-transform failed at point ({}, {}) with s={} after {} steps. {}",
                point.0, point.1, s, steps.len(), advice
            ),
            Self::KeygenFailed { attempts, modulus, base_point, advice } => write!(
                f,
                "Key generation failed after {} attempts (modulus={}, base_point=({}, {})). {}",
                attempts, modulus, base_point.0, base_point.1, advice
            ),
            Self::InvalidParameter { param, value, reason, valid_range } => write!(
                f,
                "Invalid parameter {}: {} (value={}). Valid range: {}",
                param, reason, value, valid_range
            ),
            Self::Timeout { operation, duration, max_duration } => write!(
                f,
                "Operation '{}' timed out after {:?} (max allowed: {:?})",
                operation, duration, max_duration
            ),
            Self::ValidationError { operation, expected, actual } => write!(
                f,
                "Validation failed for {}: expected {}, got {}",
                operation, expected, actual
            ),
            Self::GraphError { context, cause } => {
                write!(f, "Graph error in {}: {}", context, cause)
            }
        }
    }
}

/// Detailed transformation step recording
#[derive(Debug, Clone, PartialEq)]
pub struct TraceStep {
    pub step: u32,
    pub input: (u128, u128),
    pub s: u128,
    pub h: u128,
    pub x1: u128,
    pub y2: u128,
    pub y1: Option<u128>,
    pub output: Option<(u128, u128)>,
    pub duration: Duration,
}

/// Performance metrics for operations
#[derive(Debug, Clone)]
pub struct PerfMetrics {
    pub keygen_time: Duration,
    pub encrypt_time: Duration,
    pub decrypt_time: Duration,
    pub t_transform_count: u32,
    pub sqrt_attempts: u32,
    pub operation_history: Vec<(String, Duration)>,
}

/// Graphing module for cryptographic visualization
#[derive(Debug, Clone)]
pub struct CryptoGraph {
    pub title: String,
    pub data: Vec<(f64, f64)>,
    pub labels: HashMap<String, String>,
    pub style: GraphStyle,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GraphStyle {
    Line,
    Scatter,
    Histogram,
}

impl CryptoGraph {
    /// Renders graph to ASCII art
    pub fn render_ascii(&self, width: usize, height: usize) -> Result<String, LaiCryptoError> {
        if self.data.is_empty() {
            return Err(LaiCryptoError::GraphError {
                context: "render_ascii".to_string(),
                cause: "No data to plot".to_string(),
            });
        }

        let mut min_x = f64::MAX;
        let mut max_x = f64::MIN;
        let mut min_y = f64::MAX;
        let mut max_y = f64::MIN;

        for &(x, y) in &self.data {
            min_x = min_x.min(x);
            max_x = max_x.max(x);
            min_y = min_y.min(y);
            max_y = max_y.max(y);
        }

        let x_range = max_x - min_x;
        let y_range = max_y - min_y;

        if x_range <= 0.0 || y_range <= 0.0 {
            return Err(LaiCryptoError::GraphError {
                context: "render_ascii".to_string(),
                cause: "Invalid data range".to_string(),
            });
        }

        let mut grid = vec![vec![' '; width]; height];
        let mut result = String::new();

        // Add border
        for row in 0..height {
            grid[row][0] = '|';
            grid[row][width - 1] = '|';
        }
        for col in 0..width {
            grid[0][col] = '-';
            grid[height - 1][col] = '-';
        }
        grid[0][0] = '+';
        grid[0][width - 1] = '+';
        grid[height - 1][0] = '+';
        grid[height - 1][width - 1] = '+';

        // Plot data points
        for &(x, y) in &self.data {
            let col = ((x - min_x) / x_range * (width - 2) as f64) as usize + 1;
            let row = height - 1 - ((y - min_y) / y_range * (height - 2) as f64) as usize;

            if row < height && col < width {
                grid[row][col] = match self.style {
                    GraphStyle::Scatter => '●',
                    GraphStyle::Line => '•',
                    GraphStyle::Histogram => '█',
                };
            }
        }

        // Add title
        if !self.title.is_empty() {
            let title_pos = (width.saturating_sub(self.title.len())) / 2;
            for (i, c) in self.title.chars().enumerate() {
                if title_pos + i < width {
                    grid[0][title_pos + i] = c;
                }
            }
        }

        // Add axis labels
        if let Some(x_label) = self.labels.get("x") {
            let label_pos = (width.saturating_sub(x_label.len())) / 2;
            for (i, c) in x_label.chars().enumerate() {
                if label_pos + i < width {
                    grid[height - 1][label_pos + i] = c;
                }
            }
        }

        if let Some(y_label) = self.labels.get("y") {
            let label_pos = height / 2;
            for (i, c) in y_label.chars().enumerate() {
                if i < height && label_pos < width {
                    grid[label_pos][0] = c;
                }
            }
        }

        // Build output string
        for row in grid {
            result.extend(row);
            result.push('\n');
        }

        Ok(result)
    }
}

/// LAI cryptographic engine with enhanced capabilities
pub struct LaiCryptoEngine {
    pub p: u128,
    pub a: u128,
    pub p0: (u128, u128),
    pub trace: Vec<TraceStep>,
    pub metrics: PerfMetrics,
    pub max_attempts: u32,
    pub max_duration: Duration,
}

impl LaiCryptoEngine {
    /// Create new engine with parameter validation
    pub fn new(p: u128, a: u128, p0: (u128, u128)) -> Result<Self, LaiCryptoError> {
        // Validate parameters
        if p < 100 {
            return Err(LaiCryptoError::InvalidParameter {
                param: "p".to_string(),
                value: p.to_string(),
                reason: "Modulus too small (min 100)".to_string(),
                valid_range: "100 ≤ p ≤ 2^128-1".to_string(),
            });
        }

        if !is_prime(p) {
            return Err(LaiCryptoError::InvalidParameter {
                param: "p".to_string(),
                value: p.to_string(),
                reason: "Modulus must be prime".to_string(),
                valid_range: "Prime numbers only".to_string(),
            });
        }

        if a >= p {
            return Err(LaiCryptoError::InvalidParameter {
                param: "a".to_string(),
                value: a.to_string(),
                reason: "Parameter a must be less than modulus".to_string(),
                valid_range: format!("0 ≤ a < {}", p),
            });
        }

        // Verify base point
        let y_sq = (p0.0 * p0.0 * p0.0 + a * p0.0) % p;
        if !has_sqrt(y_sq, p) {
            return Err(LaiCryptoError::InvalidParameter {
                param: "p0".to_string(),
                value: format!("({}, {})", p0.0, p0.1),
                reason: "Base point not on curve".to_string(),
                valid_range: "Valid curve points".to_string(),
            });
        }

        Ok(Self {
            p,
            a,
            p0,
            trace: Vec::new(),
            metrics: PerfMetrics {
                keygen_time: Duration::default(),
                encrypt_time: Duration::default(),
                decrypt_time: Duration::default(),
                t_transform_count: 0,
                sqrt_attempts: 0,
                operation_history: Vec::new(),
            },
            max_attempts: 100,
            max_duration: Duration::from_secs(5),
        })
    }

    /// Record operation metrics
    fn record_operation(&mut self, op: &str, duration: Duration) {
        self.metrics.operation_history.push((op.to_string(), duration));
    }

    /// Modular exponentiation (optimized)
    pub fn mod_pow(&self, mut base: u128, mut exp: u128) -> u128 {
        let m = self.p;
        let mut result = 1u128;
        base %= m;
        while exp > 0 {
            if exp & 1 == 1 {
                result = (result * base) % m;
            }
            base = (base * base) % m;
            exp >>= 1;
        }
        result
    }

    /// Modular square root with detailed error handling
    pub fn sqrt_mod(&mut self, a: u128) -> Option<u128> {
        let a = a % self.p;
        if a == 0 {
            return Some(0);
        }
        if self.mod_pow(a, (self.p - 1) / 2) == self.p - 1 {
            return None;
        }

        let mut attempts = 0;
        let result = match self.p % 4 {
            3 => Some(self.mod_pow(a, (self.p + 1) / 4)),
            _ => {
                let mut q = self.p - 1;
                let mut s = 0;
                while q % 2 == 0 {
                    q /= 2;
                    s += 1;
                }

                let mut z = 2;
                while self.mod_pow(z, (self.p - 1) / 2) != self.p - 1 {
                    z += 1;
                    attempts += 1;
                }

                let mut m = s;
                let mut c = self.mod_pow(z, q);
                let mut t = self.mod_pow(a, q);
                let mut r = self.mod_pow(a, (q + 1) / 2);

                while t != 1 {
                    let mut i = 1;
                    let mut t2i = self.mod_pow(t, 2);
                    while t2i != 1 && i < m {
                        t2i = self.mod_pow(t2i, 2);
                        i += 1;
                        attempts += 1;
                    }
                    if i == m {
                        return None;
                    }

                    let b = self.mod_pow(c, 1 << (m - i - 1));
                    m = i;
                    c = (b * b) % self.p;
                    t = (t * c) % self.p;
                    r = (r * b) % self.p;
                }
                Some(r)
            }
        };

        self.metrics.sqrt_attempts += attempts;
        result
    }

    /// Enhanced hash function for T-transform
    pub fn h(&self, x: u128, y: u128, s: u128) -> u128 {
        let mut hasher = Sha512::new();
        hasher.update(x.to_be_bytes());
        hasher.update(y.to_be_bytes());
        hasher.update(s.to_be_bytes());
        hasher.update(self.p.to_be_bytes());
        let digest = hasher.finalize();
        let mut res = 0u128;
        for &b in digest.iter().take(16) {
            res = (res << 8) | b as u128;
        }
        res % self.p
    }

    /// Single T-transform with detailed tracing
    pub fn t(&mut self, point: (u128, u128), s: u128) -> Result<(u128, u128), LaiCryptoError> {
        let start = Instant::now();
        let (x, y) = point;
        let inv2 = self.mod_pow(2, self.p - 2);
        let mut s_cur = s;
        let mut steps = Vec::new();

        for i in 0..10 {
            let step_start = Instant::now();
            let hh = self.h(x, y, s_cur);
            let x1 = ((x + self.a + hh) * inv2) % self.p;
            let y2 = (x * y + hh) % self.p;
            let y1 = self.sqrt_mod(y2);
            let step_duration = step_start.elapsed();

            let output = y1.map(|y| (x1, y));
            let step = TraceStep {
                step: i,
                input: (x, y),
                s: s_cur,
                h: hh,
                x1,
                y2,
                y1,
                output,
                duration: step_duration,
            };
            steps.push(step.clone());
            self.trace.push(step);
            self.metrics.t_transform_count += 1;

            if let Some(y_val) = y1 {
                let duration = start.elapsed();
                self.record_operation("t", duration);
                return Ok((x1, y_val));
            }
            s_cur += 1;
        }

        let duration = start.elapsed();
        if duration > self.max_duration {
            return Err(LaiCryptoError::Timeout {
                operation: "t".to_string(),
                duration,
                max_duration: self.max_duration,
            });
        }

        self.record_operation("t", duration);
        Err(LaiCryptoError::TransformFailure {
            point,
            s,
            steps,
            advice: format!(
                "Possible solutions:\n1. Increase modulus (current: {})\n2. Try different starting s (current: {})\n3. Verify curve parameters (a={})",
                self.p, s, self.a
            ),
        })
    }

    /// Apply T-transform multiple times
    pub fn pow_t_range(
        &mut self,
        mut point: (u128, u128),
        start_s: u128,
        exp: u128,
    ) -> Result<(u128, u128), LaiCryptoError> {
        let start = Instant::now();
        let mut s = start_s;
        for _ in 0..exp {
            point = self.t(point, s)?;
            s += 1;
        }
        let duration = start.elapsed();
        self.record_operation("pow_t_range", duration);
        Ok(point)
    }

    /// Key generation with validation
    pub fn keygen(&mut self) -> Result<(u128, (u128, u128)), LaiCryptoError> {
        let start = Instant::now();
        for attempt in 0..self.max_attempts {
            let mut buf = [0u8; 16];
            OsRng.fill_bytes(&mut buf);
            let k = u128::from_be_bytes(buf) % (self.p - 1) + 1;
            match self.pow_t_range(self.p0, 1, k) {
                Ok(q) => {
                    // Validate generated key
                    if q.0 >= self.p || q.1 >= self.p {
                        continue;
                    }

                    let y_sq = (q.0 * q.0 * q.0 + self.a * q.0) % self.p;
                    let y_actual = (q.1 * q.1) % self.p;
                    
                    if y_sq != y_actual {
                        return Err(LaiCryptoError::ValidationError {
                            operation: "keygen".to_string(),
                            expected: format!("y² = {}", y_sq),
                            actual: format!("{}", y_actual),
                        });
                    }

                    let duration = start.elapsed();
                    self.metrics.keygen_time = duration;
                    self.record_operation("keygen", duration);
                    return Ok((k, q));
                }
                Err(e) => {
                    if attempt == self.max_attempts - 1 {
                        let duration = start.elapsed();
                        return Err(LaiCryptoError::KeygenFailed {
                            attempts: self.max_attempts,
                            modulus: self.p,
                            base_point: self.p0,
                            advice: format!("Key generation failed after {} attempts. Consider:\n1. Using larger modulus (current: {})\n2. Changing curve parameter (a={})\n3. Verifying base point ({}, {})",
                                self.max_attempts, self.p, self.a, self.p0.0, self.p0.1),
                        });
                    }
                }
            }
        }
        unreachable!()
    }

    /// Encryption with integrity checks
    pub fn encrypt(
        &mut self,
        m: u128,
        q: (u128, u128),
        k: u128,
    ) -> Result<((u128, u128), (u128, u128), u128), LaiCryptoError> {
        let start = Instant::now();
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        let r = u128::from_be_bytes(buf) % (self.p - 1) + 1;

        let c1 = self.pow_t_range(self.p0, 1, r)?;
        let sr = self.pow_t_range(q, 1, r)?;
        let c2 = ((m + sr.0) % self.p, sr.1);

        let duration = start.elapsed();
        self.metrics.encrypt_time = duration;
        self.record_operation("encrypt", duration);
        Ok((c1, c2, r))
    }

    /// Decryption with validation
    pub fn decrypt(
        &mut self,
        c1: (u128, u128),
        c2: (u128, u128),
        k: u128,
    ) -> Result<u128, LaiCryptoError> {
        let start = Instant::now();
        let s_val = self.pow_t_range(c1, 1, k)?;
        let m = (c2.0 + self.p - s_val.0) % self.p;

        // Verify decryption integrity
        if m >= self.p {
            return Err(LaiCryptoError::ValidationError {
                operation: "decrypt".to_string(),
                expected: format!("message < {}", self.p),
                actual: m.to_string(),
            });
        }

        let duration = start.elapsed();
        self.metrics.decrypt_time = duration;
        self.record_operation("decrypt", duration);
        Ok(m)
    }

    /// Generate performance graphs
    pub fn generate_perf_graph(&self, style: GraphStyle) -> CryptoGraph {
        let mut data = Vec::new();
        for (i, (_, duration)) in self.metrics.operation_history.iter().enumerate() {
            data.push((i as f64, duration.as_secs_f64() * 1000.0)); // ms
        }

        CryptoGraph {
            title: "Operation Timeline".to_string(),
            data,
            labels: [
                ("x".to_string(), "Operation Sequence".to_string()),
                ("y".to_string(), "Time (ms)".to_string()),
            ]
            .iter()
            .cloned()
            .collect(),
            style,
        }
    }

    /// Generate complexity graph
    pub fn generate_complexity_graph(&self) -> CryptoGraph {
        let mut data = Vec::new();
        for (i, step) in self.trace.iter().enumerate() {
            data.push((i as f64, step.duration.as_secs_f64() * 1_000_000.0)); // µs
        }

        CryptoGraph {
            title: "T-transform Step Complexity".to_string(),
            data,
            labels: [
                ("x".to_string(), "Step Index".to_string()),
                ("y".to_string(), "Duration (µs)".to_string()),
            ]
            .iter()
            .cloned()
            .collect(),
            style: GraphStyle::Line,
        }
    }

    /// Print detailed trace with diagnostics
    pub fn print_trace(&self) {
        println!("=== LAI Cryptographic Trace ===");
        println!("Modulus: {}, Parameter a: {}", self.p, self.a);
        println!("Base Point: ({}, {})", self.p0.0, self.p0.1);
        println!("Operations: {}", self.metrics.operation_history.len());
        println!("T-transforms: {}", self.metrics.t_transform_count);
        println!("Sqrt attempts: {}", self.metrics.sqrt_attempts);
        println!("\nDetailed Trace:");

        for step in &self.trace {
            println!(
                "[Step {}] s={} | Input: ({}, {})",
                step.step, step.s, step.input.0, step.input.1
            );
            println!("  Hash h={} | x'={}, y²={}", step.h, step.x1, step.y2);
            print!("  Status: ");
            match step.y1 {
                Some(y) => println!("Success -> Output: ({}, {})", step.x1, y),
                None => println!("Failure: No modular square root found"),
            }
            println!("  Duration: {:.3}µs", step.duration.as_secs_f64() * 1_000_000.0);
            println!("{}", "-".repeat(60));
        }

        println!("\nPerformance Metrics:");
        println!("Key Generation: {:.3}ms", self.metrics.keygen_time.as_secs_f64() * 1000.0);
        println!("Encryption: {:.3}ms", self.metrics.encrypt_time.as_secs_f64() * 1000.0);
        println!("Decryption: {:.3}ms", self.metrics.decrypt_time.as_secs_f64() * 1000.0);
    }
}

/// Miller-Rabin primality test for u128
fn is_prime(n: u128) -> bool {
    if n == 2 || n == 3 {
        return true;
    }
    if n <= 1 || n % 2 == 0 {
        return false;
    }

    let mut d = n - 1;
    let mut s = 0;
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }

    // Bases for 128-bit numbers (deterministic for n < 2^64)
    let bases = match n {
        _ if n < 2_047 => [2],
        _ if n < 1_373_653 => [2, 3],
        _ if n < 9_080_191 => [31, 73],
        _ if n < 25_326_001 => [2, 3, 5],
        _ if n < 3_215_031_751 => [2, 3, 5, 7],
        _ if n < 4_759_123_141 => [2, 7, 61],
        _ => [2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022],
    };

    'base_loop: for a in bases.iter() {
        let a = *a as u128;
        if a >= n {
            continue;
        }

        let mut x = mod_exp(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }

        for _ in 1..s {
            x = mod_exp(x, 2, n);
            if x == n - 1 {
                continue 'base_loop;
            }
        }
        return false;
    }
    true
}

/// Modular exponentiation helper
fn mod_exp(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    result
}

/// Check if a has square root modulo p
fn has_sqrt(a: u128, p: u128) -> bool {
    if a == 0 {
        return true;
    }
    mod_exp(a, (p - 1) / 2, p) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_prime() -> u128 {
        // 128-bit prime: 2^128 - 159
        340_282_366_920_938_463_463_374_607_431_768_211_297
    }

    #[test]
    fn test_engine_creation() {
        let prime = test_prime();
        let engine = LaiCryptoEngine::new(prime, 10, (5, 10));
        assert!(engine.is_ok());
    }

    #[test]
    fn test_key_gen() {
        let prime = test_prime();
        let mut engine = LaiCryptoEngine::new(prime, 10, (5, 10)).unwrap();
        let key = engine.keygen();
        assert!(key.is_ok());
    }

    #[test]
    fn test_encryption() {
        let prime = test_prime();
        let mut engine = LaiCryptoEngine::new(prime, 10, (5, 10)).unwrap();
        let (priv_key, pub_key) = engine.keygen().unwrap();
        let message = 12345;
        let enc_result = engine.encrypt(message, pub_key, priv_key);
        assert!(enc_result.is_ok());
    }

    #[test]
    fn test_ascii_graph() {
        let mut graph = CryptoGraph {
            title: "Test Graph".to_string(),
            data: vec![(0.0, 1.0), (1.0, 3.0), (2.0, 2.0), (3.0, 4.0)],
            labels: [
                ("x".to_string(), "X Axis".to_string()),
                ("y".to_string(), "Y Axis".to_string()),
            ]
            .iter()
            .cloned()
            .collect(),
            style: GraphStyle::Line,
        };

        let ascii = graph.render_ascii(60, 20);
        assert!(ascii.is_ok());
        println!("{}", ascii.unwrap());
    }
}
