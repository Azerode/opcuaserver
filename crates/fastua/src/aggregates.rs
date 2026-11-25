//! Aggregates (Part 13): processed history (HistoryRead with
//! ReadProcessedDetails) and AggregateFilter on MonitoredItems.
//!
//! Every aggregate works on one interval `[start, end)` from the raw values
//! inside it and the raw values just before and after it (the bounds). The
//! computation is done on f64; results are converted back to the variable's
//! type where the aggregate returns a value of that type.

use crate::history::{CALCULATED, INTERPOLATED, MULTI_VALUE, PARTIAL};
use crate::types::*;
use crate::value::{self, Sample};

/// AggregateFunction node ids (namespace 0) with their browse names.
pub const FUNCTIONS: &[(u32, &str)] = &[
    (2341, "Interpolative"),
    (2342, "Average"),
    (2343, "TimeAverage"),
    (11285, "TimeAverage2"),
    (2344, "Total"),
    (11304, "Total2"),
    (2346, "Minimum"),
    (2347, "Maximum"),
    (2348, "MinimumActualTime"),
    (2349, "MaximumActualTime"),
    (2350, "Range"),
    (11286, "Minimum2"),
    (11287, "Maximum2"),
    (11305, "MinimumActualTime2"),
    (11306, "MaximumActualTime2"),
    (11288, "Range2"),
    (2351, "AnnotationCount"),
    (2352, "Count"),
    (11307, "DurationInStateZero"),
    (11308, "DurationInStateNonZero"),
    (2355, "NumberOfTransitions"),
    (2357, "Start"),
    (2358, "End"),
    (2359, "Delta"),
    (11505, "StartBound"),
    (11506, "EndBound"),
    (11507, "DeltaBounds"),
    (2360, "DurationGood"),
    (2361, "DurationBad"),
    (2362, "PercentGood"),
    (2363, "PercentBad"),
    (2364, "WorstQuality"),
    (11292, "WorstQuality2"),
    (11426, "StandardDeviationSample"),
    (11427, "StandardDeviationPopulation"),
    (11428, "VarianceSample"),
    (11429, "VariancePopulation"),
];

pub const AGGREGATE_FUNCTION_TYPE: u32 = 2340;

/// An aggregate the server computes.
pub fn supported(id: &NodeId) -> Option<u32> {
    let n = id.as_ns0()?;
    FUNCTIONS.iter().any(|f| f.0 == n).then_some(n)
}

/// Aggregates that need numeric values.
fn numeric_only(agg: u32) -> bool {
    !matches!(agg, 2341 | 2351 | 2352 | 2355 | 2357 | 2358 | 11505 | 11506 | 2360 | 2361 | 2362 | 2363 | 2364 | 11292)
}

/// Whether `agg` accepts values of `kind`.
pub fn accepts(agg: u32, kind: u8) -> bool {
    let numeric = value::bits_as_f64(kind, 0).is_some() || kind == builtin::BOOLEAN;
    numeric || !numeric_only(agg) && !matches!(agg, 11307 | 11308)
}

/// AggregateConfiguration (Part 13 §4.2.1.2).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Config {
    pub use_server_defaults: bool,
    pub treat_uncertain_as_bad: bool,
    pub percent_bad: u8,
    pub percent_good: u8,
    pub sloped_extrapolation: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            use_server_defaults: true,
            treat_uncertain_as_bad: true,
            percent_bad: 100,
            percent_good: 100,
            sloped_extrapolation: false,
        }
    }
}

impl Config {
    /// The configuration in effect, or BadAggregateConfigurationRejected.
    pub fn revise(self) -> Result<Config, u32> {
        if self.use_server_defaults {
            return Ok(Config::default());
        }
        if self.percent_bad > 100
            || self.percent_good > 100
            || (self.percent_good as u16 + self.percent_bad as u16) < 100
        {
            return Err(status::BAD_AGGREGATE_CONFIGURATION_REJECTED);
        }
        Ok(self)
    }

    pub fn decode(r: &mut crate::codec::Reader) -> crate::codec::DResult<Config> {
        Ok(Config {
            use_server_defaults: r.bool()?,
            treat_uncertain_as_bad: r.bool()?,
            percent_bad: r.u8()?,
            percent_good: r.u8()?,
            sloped_extrapolation: r.bool()?,
        })
    }

    pub fn encode(&self, w: &mut crate::codec::Writer) {
        w.bool(self.use_server_defaults);
        w.bool(self.treat_uncertain_as_bad);
        w.u8(self.percent_bad);
        w.u8(self.percent_good);
        w.bool(self.sloped_extrapolation);
    }
}

/// Raw data around one interval.
pub struct Window<'a> {
    pub before: Option<&'a Sample>,
    pub values: &'a [Sample],
    pub after: Option<&'a Sample>,
}

fn is_uncertain(code: u32) -> bool {
    code & 0xC000_0000 == 0x4000_0000
}

/// Intervals of a processed read: `(start, end, partial, timestamp)` with
/// `start < end`, in the order the results are returned.
pub fn intervals(start: i64, end: i64, interval_ms: f64) -> impl Iterator<Item = (i64, i64, bool, i64)> {
    let (lo, hi, reverse) = if start <= end { (start, end, false) } else { (end, start, true) };
    let span = hi - lo;
    let step = (interval_ms * 10_000.0) as i64;
    let step = if step <= 0 || step >= span { span.max(1) } else { step };
    let count = if span == 0 { 0 } else { (span + step - 1) / step };
    (0..count).map(move |k| {
        if reverse {
            // Intervals start at StartTime and go back in time.
            let e = hi - k * step;
            let s = (e - step).max(lo);
            (s, e, e - s < step, e)
        } else {
            let s = lo + k * step;
            let e = (s + step).min(hi);
            (s, e, e - s < step, s)
        }
    })
}

/// Number of intervals [`intervals`] yields.
pub fn interval_count(start: i64, end: i64, interval_ms: f64) -> usize {
    let span = (end - start).abs();
    let step = (interval_ms * 10_000.0) as i64;
    let step = if step <= 0 || step >= span { span.max(1) } else { step };
    if span == 0 {
        0
    } else {
        ((span + step - 1) / step) as usize
    }
}

/// Computes `agg` over `[start, end)`; `ts` is the reported timestamp.
#[allow(clippy::too_many_arguments)]
pub fn compute(
    agg: u32,
    kind: u8,
    stepped: bool,
    cfg: &Config,
    start: i64,
    end: i64,
    partial: bool,
    ts: i64,
    w: &Window,
) -> Sample {
    let c = Calc { kind, stepped: stepped || value::bits_as_f64(kind, 0).is_none(), cfg, start, end, w };
    let partial_bit = if partial { PARTIAL } else { 0 };
    let out =
        |value: Variant, status: u32| Sample { value, status: status | partial_bit, source_ts: ts, server_ts: ts };
    let no_data = || Sample { value: Variant::Empty, status: status::BAD_NO_DATA, source_ts: ts, server_ts: ts };
    let dbl = Variant::Double;
    let same_type = |f: f64| value::variant_from_f64(kind, f).unwrap_or(Variant::Double(f));
    match agg {
        // Interpolative: the value at the start of the interval.
        2341 => match c.at(start) {
            Some((v, st, exact)) => out(v, if exact { st } else { st | INTERPOLATED }),
            None => no_data(),
        },
        2342 => {
            let (sum, n) = c.good_values().fold((0.0, 0usize), |(s, n), v| (s + v.1, n + 1));
            if n == 0 {
                return no_data();
            }
            out(dbl(sum / n as f64), c.count_status() | CALCULATED)
        }
        2343 | 2344 | 11285 | 11304 => {
            let v2 = matches!(agg, 11285 | 11304);
            let Some((area, duration, st)) = c.area(v2) else { return no_data() };
            if duration <= 0.0 {
                return no_data();
            }
            let avg = area / duration;
            let v = if matches!(agg, 2343 | 11285) { avg } else { avg * (if v2 { duration } else { c.span_s() }) };
            out(dbl(v), st | CALCULATED)
        }
        2346 | 2347 | 2348 | 2349 | 2350 | 11286 | 11287 | 11305 | 11306 | 11288 => {
            let with_bounds = matches!(agg, 11286 | 11287 | 11305 | 11306 | 11288);
            let st = c.count_status();
            if !with_bounds {
                // One pass, no allocation: extremes, first time and count of each.
                let mut it = c.good_values();
                let Some((t0, f0, _)) = it.next() else { return no_data() };
                let (mut min, mut tmin, mut nmin, mut max, mut tmax, mut nmax) = (f0, t0, 1, f0, t0, 1);
                for (t, f, _) in it {
                    if f < min {
                        (min, tmin, nmin) = (f, t, 1);
                    } else if f == min {
                        nmin += 1;
                    }
                    if f > max {
                        (max, tmax, nmax) = (f, t, 1);
                    } else if f == max {
                        nmax += 1;
                    }
                }
                if agg == 2350 {
                    return out(same_type(max - min), st | CALCULATED);
                }
                let (want, at, hits) = if matches!(agg, 2346 | 2348) { (min, tmin, nmin) } else { (max, tmax, nmax) };
                let multi = if hits > 1 { MULTI_VALUE } else { 0 };
                let mut s = out(same_type(want), st | CALCULATED | multi);
                if matches!(agg, 2348 | 2349) {
                    s.source_ts = at;
                    s.server_ts = at;
                }
                return s;
            }
            let mut pts: Vec<(i64, f64)> = c.good_values().map(|(t, f, _)| (t, f)).collect();
            {
                for t in [start, end] {
                    if let Some((v, st, exact)) = c.at(t) {
                        if !exact && c.counts_as_good(st) {
                            if let Some(f) = value::variant_as_f64(&v) {
                                pts.push((t, f));
                            }
                        }
                    }
                }
                pts.sort_by_key(|p| p.0);
            }
            if pts.is_empty() {
                return no_data();
            }
            let min = pts.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
            let max = pts.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
            match agg {
                2350 | 11288 => out(same_type(max - min), st | CALCULATED),
                _ => {
                    let want = if matches!(agg, 2346 | 2348 | 11286 | 11305) { min } else { max };
                    let hits: Vec<i64> = pts.iter().filter(|p| p.1 == want).map(|p| p.0).collect();
                    let multi = if hits.len() > 1 { MULTI_VALUE } else { 0 };
                    let actual = matches!(agg, 2348 | 2349 | 11305 | 11306);
                    let mut s = out(same_type(want), st | CALCULATED | multi);
                    if actual {
                        s.source_ts = hits[0];
                        s.server_ts = hits[0];
                    }
                    s
                }
            }
        }
        2351 => out(Variant::Int32(0), status::GOOD | CALCULATED),
        2352 => out(Variant::Int32(c.good_values().count() as i32), c.count_status_or_good() | CALCULATED),
        11307 | 11308 => {
            let zero = agg == 11307;
            let d = c.state_duration(|f| (f == 0.0) == zero);
            out(dbl(d), c.duration_status() | CALCULATED)
        }
        2355 => {
            let mut last =
                c.w.before.filter(|s| c.counts_as_good(s.status)).and_then(|s| value::variant_as_f64(&s.value));
            let mut n = 0;
            for (_, f, _) in c.good_values() {
                if last.is_some_and(|l| l != f) {
                    n += 1;
                }
                last = Some(f);
            }
            out(Variant::Int32(n), c.count_status_or_good() | CALCULATED)
        }
        2357 | 2358 => {
            let mut good = c.w.values.iter().filter(|s| c.counts_as_good(s.status));
            let s = if agg == 2357 { good.next() } else { good.next_back() };
            match s {
                Some(s) => Sample {
                    value: s.value.clone(),
                    status: s.status | partial_bit,
                    source_ts: s.source_ts,
                    server_ts: s.source_ts,
                },
                None => no_data(),
            }
        }
        2359 => {
            let mut good = c.good_values();
            let first = good.next();
            let last = good.last().or(first);
            match (first, last) {
                (Some(a), Some(b)) => out(same_type(b.1 - a.1), c.count_status() | CALCULATED),
                _ => no_data(),
            }
        }
        11505..=11507 => {
            let bound = |t: i64| c.at(t);
            match agg {
                11505 | 11506 => match bound(if agg == 11505 { start } else { end }) {
                    Some((v, st, exact)) => out(v, if exact { st } else { st | INTERPOLATED }),
                    None => no_data(),
                },
                _ => match (bound(start), bound(end)) {
                    (Some((a, sa, _)), Some((b, sb, _))) => {
                        match (value::variant_as_f64(&a), value::variant_as_f64(&b)) {
                            (Some(a), Some(b)) => {
                                let st = worse(sa, sb) & 0xFFFF_0000;
                                out(same_type(b - a), st | CALCULATED)
                            }
                            _ => no_data(),
                        }
                    }
                    _ => no_data(),
                },
            }
        }
        2360..=2363 => {
            let (good, bad) = c.quality_durations();
            let total = c.span_ms();
            let v = match agg {
                2360 => good,
                2361 => bad,
                2362 => 100.0 * good / total,
                _ => 100.0 * bad / total,
            };
            out(dbl(v), status::GOOD | CALCULATED)
        }
        2364 | 11292 => {
            let mut worst = status::GOOD;
            let mut seen = 0;
            let bounds = if agg == 11292 { c.w.before } else { None };
            for s in bounds.into_iter().chain(c.w.values.iter()) {
                worst = worse(worst, s.status);
                seen += 1;
            }
            if seen == 0 {
                return no_data();
            }
            out(Variant::StatusCode(worst & 0xFFFF_0000), status::GOOD | CALCULATED)
        }
        11426..=11429 => {
            let good = c.good_values();
            let sample = matches!(agg, 11426 | 11428);
            let (sum, n) = good.clone().fold((0.0, 0usize), |(s, n), v| (s + v.1, n + 1));
            if n == 0 || (sample && n < 2) {
                return no_data();
            }
            let mean = sum / n as f64;
            let ss: f64 = good.map(|s| (s.1 - mean).powi(2)).sum();
            let var = ss / if sample { (n - 1) as f64 } else { n as f64 };
            let v = if matches!(agg, 11426 | 11427) { var.sqrt() } else { var };
            out(dbl(v), c.count_status() | CALCULATED)
        }
        _ => {
            Sample { value: Variant::Empty, status: status::BAD_AGGREGATE_NOT_SUPPORTED, source_ts: ts, server_ts: ts }
        }
    }
}

fn severity(code: u32) -> u32 {
    code >> 30
}

/// The worse of two status codes (Bad > Uncertain > Good).
fn worse(a: u32, b: u32) -> u32 {
    let rank = |c: u32| match severity(c) {
        0 => 0,
        1 => 1,
        _ => 2,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

struct Calc<'a> {
    kind: u8,
    stepped: bool,
    cfg: &'a Config,
    start: i64,
    end: i64,
    w: &'a Window<'a>,
}

impl Calc<'_> {
    fn counts_as_good(&self, st: u32) -> bool {
        status::is_good(st) || (!self.cfg.treat_uncertain_as_bad && is_uncertain(st))
    }

    fn span_ms(&self) -> f64 {
        (self.end - self.start) as f64 / 10_000.0
    }

    fn span_s(&self) -> f64 {
        (self.end - self.start) as f64 / 10_000_000.0
    }

    /// Good numeric values in the interval: (time, value, status).
    fn good_values(&self) -> impl Iterator<Item = (i64, f64, u32)> + Clone + '_ {
        self.w.values.iter().filter(|s| self.counts_as_good(s.status)).filter_map(|s| {
            let f = value::variant_as_f64(&s.value).or(if let Variant::Boolean(b) = s.value {
                Some(b as u8 as f64)
            } else {
                None
            })?;
            Some((s.source_ts, f, s.status))
        })
    }

    /// Good / Uncertain / Bad from the share of good values (by count).
    fn count_status(&self) -> u32 {
        let total = self.w.values.len();
        let good = self.w.values.iter().filter(|s| self.counts_as_good(s.status)).count();
        self.share_status(good as f64, total as f64)
    }

    fn count_status_or_good(&self) -> u32 {
        if self.w.values.is_empty() {
            status::GOOD
        } else {
            self.count_status()
        }
    }

    fn duration_status(&self) -> u32 {
        let (good, _) = self.quality_durations();
        self.share_status(good, self.span_ms())
    }

    fn share_status(&self, good: f64, total: f64) -> u32 {
        if total <= 0.0 {
            return status::GOOD;
        }
        let pct_good = 100.0 * good / total;
        if pct_good >= self.cfg.percent_good as f64 {
            status::GOOD
        } else if 100.0 - pct_good >= self.cfg.percent_bad as f64 {
            0x8000_0000 // Bad
        } else {
            status::UNCERTAIN_DATA_SUB_NORMAL
        }
    }

    /// Value at `t` from the raw data: (value, status, exact). Sloped
    /// interpolation between the neighbours for numbers, stepped otherwise;
    /// after the last value, stepped (or sloped) extrapolation as
    /// Uncertain.
    fn at(&self, t: i64) -> Option<(Variant, u32, bool)> {
        // before, values, after: sorted by time; binary search, then walk
        // to the nearest good values.
        let w = self.w;
        let b = w.before.is_some() as usize;
        let n = b + w.values.len() + w.after.is_some() as usize;
        let get = |i: usize| -> &Sample {
            if i < b {
                w.before.unwrap()
            } else if i - b < w.values.len() {
                &w.values[i - b]
            } else {
                w.after.unwrap()
            }
        };
        let (mut lo, mut hi) = (0, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if get(mid).source_ts < t {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let mut j = lo;
        while j < n && get(j).source_ts == t {
            let s = get(j);
            if self.counts_as_good(s.status) {
                return Some((s.value.clone(), s.status, true));
            }
            j += 1;
        }
        let good = |i: &usize| self.counts_as_good(get(*i).status);
        let next = (j..n).find(good).map(get);
        let mut before_t = (0..j).rev().filter(good).map(get);
        let prev = before_t.next();
        let prev2 = before_t.next();
        let p = prev?;
        let pf = value::variant_as_f64(&p.value);
        match next {
            Some(n) if !self.stepped => {
                let (a, b) = (pf?, value::variant_as_f64(&n.value)?);
                let f = (t - p.source_ts) as f64 / (n.source_ts - p.source_ts) as f64;
                let v = value::variant_from_f64(self.kind, a + (b - a) * f)?;
                Some((v, worse(p.status, n.status) & 0xFFFF_0000, false))
            }
            Some(_) => Some((p.value.clone(), p.status & 0xFFFF_0000, false)),
            None => {
                // Extrapolation past the last value.
                let v = match (self.cfg.sloped_extrapolation && !self.stepped, prev2) {
                    (true, Some(q)) => {
                        let (a, b) = (value::variant_as_f64(&q.value)?, pf?);
                        let f = (t - q.source_ts) as f64 / (p.source_ts - q.source_ts) as f64;
                        value::variant_from_f64(self.kind, a + (b - a) * f)?
                    }
                    _ => p.value.clone(),
                };
                Some((v, status::UNCERTAIN_DATA_SUB_NORMAL, false))
            }
        }
    }

    /// Time-weighted area (value × seconds) and the duration (seconds) it
    /// covers, with the status from the share of good time. `only_good`
    /// (the "2" variants) leaves bad periods out of both; otherwise bad
    /// periods are bridged by interpolation.
    fn area(&self, only_good: bool) -> Option<(f64, f64, u32)> {
        let first = match self.at(self.start) {
            Some((v, st, _)) => Some((self.start, value::variant_as_f64(&v)?, self.counts_as_good(st))),
            None => None,
        };
        let last = match self.at(self.end) {
            Some((v, st, _)) => Some((self.end, value::variant_as_f64(&v)?, self.counts_as_good(st))),
            None => None,
        };
        let inner = self.w.values.iter().filter_map(|s| {
            let good = self.counts_as_good(s.status);
            if !good && !only_good {
                return None;
            }
            match value::variant_as_f64(&s.value) {
                Some(f) => Some((s.source_ts, f, good)),
                None if !good => Some((s.source_ts, 0.0, false)),
                None => None,
            }
        });
        // Trapezoids between consecutive points, without collecting them.
        let (mut area, mut dur, mut count) = (0.0, 0.0, 0usize);
        let mut prev: Option<(i64, f64, bool)> = None;
        for b in first.into_iter().chain(inner).chain(last) {
            count += 1;
            if let Some(a) = prev {
                let dt = (b.0 - a.0) as f64 / 10_000_000.0;
                if dt > 0.0 && !(only_good && !a.2) {
                    let h = if self.stepped || (only_good && !b.2) { a.1 } else { (a.1 + b.1) / 2.0 };
                    area += h * dt;
                    dur += dt;
                }
            }
            prev = Some(b);
        }
        if count < 2 {
            return None;
        }
        let total = self.span_s();
        let (good_ms, _) = self.quality_durations();
        let st = self.share_status(good_ms, total * 1000.0);
        Some((area, if only_good { dur } else { total }, st))
    }

    /// Milliseconds of good and bad quality in the interval, the status of
    /// each raw value holding until the next one (before the first value:
    /// the status of the value before the interval, bad if none).
    fn quality_durations(&self) -> (f64, f64) {
        let mut t = self.start;
        let mut cur = self.w.before.map(|s| self.counts_as_good(s.status));
        let (mut good, mut bad) = (0i64, 0i64);
        let mut add = |from: i64, to: i64, g: Option<bool>| match g {
            Some(true) => good += to - from,
            _ => bad += to - from,
        };
        for s in self.w.values {
            add(t, s.source_ts.max(t), cur);
            t = s.source_ts.max(t);
            cur = Some(self.counts_as_good(s.status));
        }
        add(t, self.end, cur);
        (good as f64 / 10_000.0, bad as f64 / 10_000.0)
    }

    /// Milliseconds during which the (stepped) value satisfies `pred`.
    fn state_duration(&self, pred: impl Fn(f64) -> bool) -> f64 {
        let as_f = |s: &Sample| {
            value::variant_as_f64(&s.value).or(if let Variant::Boolean(b) = s.value {
                Some(b as u8 as f64)
            } else {
                None
            })
        };
        let mut t = self.start;
        let mut cur = self.w.before.filter(|s| self.counts_as_good(s.status)).and_then(as_f);
        let mut total = 0i64;
        for s in self.w.values.iter().filter(|s| self.counts_as_good(s.status)) {
            if cur.is_some_and(&pred) {
                total += s.source_ts - t;
            }
            t = s.source_ts;
            cur = as_f(s);
        }
        if cur.is_some_and(&pred) {
            total += self.end - t;
        }
        total as f64 / 10_000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 10_000_000;

    fn s(t: i64, v: f64, st: u32) -> Sample {
        Sample { value: Variant::Double(v), status: st, source_ts: t * S, server_ts: t * S }
    }

    fn run(agg: u32, data: &[Sample], start: i64, end: i64) -> Sample {
        let before = data.iter().rfind(|x| x.source_ts < start * S);
        let after = data.iter().find(|x| x.source_ts >= end * S);
        let values: Vec<Sample> =
            data.iter().filter(|x| x.source_ts >= start * S && x.source_ts < end * S).cloned().collect();
        let w = Window { before, values: &values, after };
        compute(agg, builtin::DOUBLE, false, &Config::default(), start * S, end * S, false, start * S, &w)
    }

    fn val(s: &Sample) -> f64 {
        value::variant_as_f64(&s.value).unwrap()
    }

    #[test]
    fn intervals_cover_the_range() {
        let v: Vec<_> = intervals(0, 25 * S, 10_000.0).collect();
        assert_eq!(v, vec![(0, 10 * S, false, 0), (10 * S, 20 * S, false, 10 * S), (20 * S, 25 * S, true, 20 * S)]);
        let r: Vec<_> = intervals(25 * S, 0, 10_000.0).collect();
        assert_eq!(r[0], (15 * S, 25 * S, false, 25 * S));
        assert_eq!(r[2], (0, 5 * S, true, 5 * S));
        assert_eq!(intervals(0, 25 * S, 0.0).count(), 1);
        assert_eq!(interval_count(0, 25 * S, 10_000.0), 3);
    }

    #[test]
    fn basic_aggregates() {
        let g = status::GOOD;
        let d = [s(0, 0.0, g), s(2, 10.0, g), s(4, 20.0, g), s(6, 20.0, g), s(10, 40.0, g)];
        assert_eq!(val(&run(2342, &d, 0, 10)), 12.5); // Average of 0, 10, 20, 20
        assert_eq!(val(&run(2346, &d, 0, 10)), 0.0);
        let max = run(2347, &d, 0, 10);
        assert_eq!(val(&max), 20.0);
        assert_eq!(max.status & MULTI_VALUE, MULTI_VALUE);
        let at = run(2349, &d, 0, 10);
        assert_eq!(at.source_ts, 4 * S);
        assert_eq!(val(&run(2350, &d, 0, 10)), 20.0);
        assert_eq!(run(2352, &d, 0, 10).value, Variant::Int32(4));
        assert_eq!(val(&run(2357, &d, 1, 10)), 10.0);
        assert_eq!(val(&run(2358, &d, 0, 10)), 20.0);
        assert_eq!(val(&run(2359, &d, 0, 10)), 20.0);
        assert_eq!(run(2355, &d, 0, 10).value, Variant::Int32(2));
        // Interpolative at t = 1: between 0 and 10.
        let i = run(2341, &d, 1, 10);
        assert_eq!((val(&i), i.status), (5.0, INTERPOLATED));
        // TimeAverage over [0, 10): trapezoids 10 + 30 + 40 + 120 = 200 → 20.
        assert_eq!(val(&run(2343, &d, 0, 10)), 20.0);
        assert_eq!(val(&run(2344, &d, 0, 10)), 200.0);
        assert_eq!(val(&run(11285, &d, 0, 10)), 20.0);
        // Bounds.
        assert_eq!(val(&run(11505, &d, 1, 5)), 5.0);
        assert_eq!(val(&run(11506, &d, 1, 5)), 20.0);
        assert_eq!(val(&run(11507, &d, 1, 5)), 15.0);
        assert_eq!(val(&run(11286, &d, 1, 5)), 5.0);
        // Statistics: population variance of 0, 10, 20, 20 = 68.75.
        assert_eq!(val(&run(11429, &d, 0, 10)), 68.75);
        assert_eq!(run(2342, &d, 20, 30).status, status::BAD_NO_DATA);
    }

    #[test]
    fn quality_aggregates() {
        let (g, b) = (status::GOOD, 0x8000_0000);
        let d = [s(0, 1.0, g), s(4, 2.0, b), s(6, 3.0, g)];
        assert_eq!(val(&run(2360, &d, 0, 10)), 8000.0);
        assert_eq!(val(&run(2361, &d, 0, 10)), 2000.0);
        assert_eq!(val(&run(2362, &d, 0, 10)), 80.0);
        assert_eq!(run(2364, &d, 0, 10).value, Variant::StatusCode(b));
        // One bad value of three: Uncertain with the default 100 / 100.
        assert_eq!(run(2342, &d, 0, 10).status & 0xFFFF_0000, status::UNCERTAIN_DATA_SUB_NORMAL);
        let zero = [s(0, 0.0, g), s(3, 1.0, g), s(5, 0.0, g)];
        assert_eq!(val(&run(11307, &zero, 0, 10)), 8000.0);
        assert_eq!(val(&run(11308, &zero, 0, 10)), 2000.0);
    }

    #[test]
    fn config_rules() {
        assert!(Config { use_server_defaults: false, percent_bad: 40, percent_good: 50, ..Config::default() }
            .revise()
            .is_err());
        let c = Config { use_server_defaults: false, percent_bad: 50, percent_good: 60, ..Config::default() };
        assert_eq!(c.revise(), Ok(c));
        assert!(accepts(2342, builtin::DOUBLE));
        assert!(!accepts(2342, builtin::STRING));
        assert!(accepts(2352, builtin::STRING));
    }
}
