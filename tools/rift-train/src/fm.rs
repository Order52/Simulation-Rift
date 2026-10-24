//! A factorization machine over the same hashed features as the linear
//! model: the linear score plus, for every pair of features in an address,
//! the dot product of their learned factor vectors. Pairs (a brand word in
//! the host with "login" in the path, a lure word with a hosting platform)
//! are what a linear model cannot weigh.
//!
//! Factors live in a smaller table than the weights (2^`factor_bits` rows of
//! `k`); a feature's row is its weight bucket's low bits ([`Factors::row`]).
//! With `k` = 0 this is exactly logistic regression.

use rift_core::urlmodel::{Factors, sigmoid};

#[derive(Clone)]
pub struct Fm {
    pub factor_bits: u32,
    pub k: usize,
    pub bias: f32,
    pub weights: Vec<f32>,
    /// Row-major, 2^factor_bits × k.
    pub factors: Vec<f32>,
}

/// AdaGrad state for one [`Fm`].
pub struct Trainer {
    bias_g2: f32,
    weights_g2: Vec<f32>,
    factors_g2: Vec<f32>,
    sums: Vec<f32>,
}

const RATE: f32 = 0.08;
const FACTOR_RATE: f32 = 0.04;

impl Fm {
    pub fn new(bits: u32, factor_bits: u32, k: usize, seed: u64) -> Self {
        let mut state = seed | 1;
        let mut uniform = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 40) as f32 / (1u64 << 24) as f32 - 0.5
        };
        let rows = 1usize << factor_bits;
        Self {
            factor_bits,
            k,
            bias: 0.0,
            weights: vec![0.0; 1 << bits],
            factors: (0..rows * k).map(|_| uniform() * 0.02).collect(),
        }
    }

    fn row(&self, bucket: usize) -> usize {
        Factors::row(self.k, self.factor_bits, bucket)
    }

    /// The score before the sigmoid; `sums` (length k) is left holding
    /// Σ v·x per factor, for the gradient.
    fn raw(&self, features: &[(usize, f32)], sums: &mut [f32]) -> f32 {
        let mut z = self.bias;
        sums.fill(0.0);
        let mut squares = 0f32;
        for &(bucket, x) in features {
            z += self.weights[bucket] * x;
            let row = self.row(bucket);
            for (sum, v) in sums.iter_mut().zip(&self.factors[row..row + self.k]) {
                let vx = v * x;
                *sum += vx;
                squares += vx * vx;
            }
        }
        z + 0.5 * (sums.iter().map(|s| s * s).sum::<f32>() - squares)
    }

    pub fn score(&self, features: &[(usize, f32)]) -> f32 {
        let mut sums = vec![0f32; self.k];
        sigmoid(self.raw(features, &mut sums))
    }

    pub fn trainer(&self) -> Trainer {
        Trainer {
            bias_g2: 1e-6,
            weights_g2: vec![1e-6; self.weights.len()],
            factors_g2: vec![1e-6; self.factors.len()],
            sums: vec![0.0; self.k],
        }
    }

    /// One AdaGrad step on one example of class weight `cw` (L2 `l2` on the
    /// weights, `factor_l2` on the factors); returns its loss.
    pub fn step(
        &mut self,
        t: &mut Trainer,
        features: &[(usize, f32)],
        malicious: bool,
        cw: f32,
        l2: f32,
        factor_l2: f32,
    ) -> f32 {
        let z = self.raw(features, &mut t.sums);
        let p = sigmoid(z);
        let y = if malicious { 1.0 } else { 0.0 };
        let loss = -cw
            * if malicious {
                p.max(1e-7).ln()
            } else {
                (1.0 - p).max(1e-7).ln()
            };
        let g = (p - y) * cw;
        for &(bucket, x) in features {
            let grad = g * x + l2 * self.weights[bucket];
            t.weights_g2[bucket] += grad * grad;
            self.weights[bucket] -= RATE * grad / t.weights_g2[bucket].sqrt();
            let row = self.row(bucket);
            for f in 0..self.k {
                let v = self.factors[row + f];
                let grad = g * x * (t.sums[f] - v * x) + factor_l2 * v;
                t.factors_g2[row + f] += grad * grad;
                self.factors[row + f] -= FACTOR_RATE * grad / t.factors_g2[row + f].sqrt();
            }
        }
        t.bias_g2 += g * g;
        self.bias -= RATE * g / t.bias_g2.sqrt();
        loss
    }
}
