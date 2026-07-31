//! Online statistics accumulators for flow features.

/// Welford online mean/variance with min/max tracking.
#[derive(Clone, Debug, Default)]
pub struct Welford {
    pub n: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl Welford {
    #[inline]
    pub fn push(&mut self, x: f64) {
        self.n += 1;
        if self.n == 1 {
            self.min = x;
            self.max = x;
        } else {
            if x < self.min {
                self.min = x;
            }
            if x > self.max {
                self.max = x;
            }
        }
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
    }

    pub fn mean_opt(&self) -> Option<f64> {
        if self.n >= 1 {
            Some(self.mean)
        } else {
            None
        }
    }

    /// Sample standard deviation (n-1 denominator); None if fewer than 2 samples.
    pub fn std_opt(&self) -> Option<f64> {
        if self.n >= 2 {
            Some((self.m2 / (self.n as f64 - 1.0)).max(0.0).sqrt())
        } else {
            None
        }
    }

    pub fn min_opt(&self) -> Option<f64> {
        if self.n >= 1 {
            Some(self.min)
        } else {
            None
        }
    }

    pub fn max_opt(&self) -> Option<f64> {
        if self.n >= 1 {
            Some(self.max)
        } else {
            None
        }
    }
}

/// Tracks active/idle periods separated by gaps exceeding a threshold.
#[derive(Clone, Debug)]
pub struct ActiveIdle {
    threshold_ns: i64,
    active_start: i64,
    last_ts: i64,
    started: bool,
    pub active: Welford,
    pub idle: Welford,
}

impl ActiveIdle {
    pub fn new(threshold_s: f64) -> ActiveIdle {
        ActiveIdle {
            threshold_ns: (threshold_s * 1e9) as i64,
            active_start: 0,
            last_ts: 0,
            started: false,
            active: Welford::default(),
            idle: Welford::default(),
        }
    }

    pub fn observe(&mut self, ts_ns: i64) {
        if !self.started {
            self.started = true;
            self.active_start = ts_ns;
            self.last_ts = ts_ns;
            return;
        }
        let gap = ts_ns - self.last_ts;
        if gap > self.threshold_ns {
            // Close the current active burst and record the idle gap.
            let dur = (self.last_ts - self.active_start) as f64 / 1e9;
            self.active.push(dur);
            self.idle.push(gap as f64 / 1e9);
            self.active_start = ts_ns;
        }
        self.last_ts = ts_ns;
    }

    /// Finalize the last active burst. Call once at flow close.
    pub fn finish(&mut self) {
        if self.started {
            let dur = (self.last_ts - self.active_start) as f64 / 1e9;
            self.active.push(dur);
        }
    }

    pub fn active_count(&self) -> u32 {
        self.active.n as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welford_matches_naive() {
        let mut w = Welford::default();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.push(x);
        }
        assert!((w.mean_opt().unwrap() - 5.0).abs() < 1e-9);
        // population std is 2.0, sample std = sqrt(32/7)
        assert!((w.std_opt().unwrap() - (32.0f64 / 7.0).sqrt()).abs() < 1e-9);
        assert_eq!(w.min_opt(), Some(2.0));
        assert_eq!(w.max_opt(), Some(9.0));
    }

    #[test]
    fn std_needs_two() {
        let mut w = Welford::default();
        w.push(1.0);
        assert_eq!(w.std_opt(), None);
    }

    #[test]
    fn active_idle_splits() {
        let mut ai = ActiveIdle::new(1.0);
        // three packets 0.1s apart (one active burst), then 5s gap, then two more
        let s = 1_000_000_000i64;
        ai.observe(0);
        ai.observe(s / 10);
        ai.observe(2 * s / 10);
        ai.observe(2 * s / 10 + 5 * s); // 5s gap -> idle
        ai.observe(2 * s / 10 + 5 * s + s / 10);
        ai.finish();
        assert_eq!(ai.active_count(), 2);
        assert_eq!(ai.idle.n, 1);
        assert!((ai.idle.min_opt().unwrap() - 5.0).abs() < 1e-6);
    }
}
