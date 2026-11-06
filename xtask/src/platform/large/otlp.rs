//! A tiny OTLP/HTTP metrics collector for the overload proof: it receives the real
//! server's exports (plain protobuf), decodes the gauges and counters it needs with a
//! hand-written wire-format reader, and keeps the time series so the report can say what
//! the peak of running and queued operations really was.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub name: String,
    pub value: f64,
    /// Seconds since the collector started.
    pub at: f64,
}

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *b.get(*i)?;
        *i += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

#[derive(Debug)]
enum Field<'a> {
    Varint,
    Fixed64(u64),
    Len(&'a [u8]),
    Fixed32,
}

fn fields(b: &[u8]) -> Option<Vec<(u32, Field<'_>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = varint(b, &mut i)?;
        let number = (key >> 3) as u32;
        out.push((
            number,
            match key & 7 {
                0 => {
                    varint(b, &mut i)?;
                    Field::Varint
                }
                1 => {
                    let v = u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?);
                    i += 8;
                    Field::Fixed64(v)
                }
                2 => {
                    let len = varint(b, &mut i)? as usize;
                    let data = b.get(i..i.checked_add(len)?)?;
                    i += len;
                    Field::Len(data)
                }
                5 => {
                    b.get(i..i + 4)?;
                    i += 4;
                    Field::Fixed32
                }
                _ => return None,
            },
        ));
    }
    Some(out)
}

/// `(metric name, value)` of every number data point of an `ExportMetricsServiceRequest`
/// (gauges and sums; histograms are skipped).
pub fn decode_metrics(body: &[u8]) -> Option<Vec<(String, f64)>> {
    let mut out = Vec::new();
    for (n, resource) in fields(body)? {
        if n != 1 {
            continue;
        }
        let Field::Len(resource) = resource else {
            continue;
        };
        for (n, scope) in fields(resource)? {
            if n != 2 {
                continue;
            }
            let Field::Len(scope) = scope else { continue };
            for (n, metric) in fields(scope)? {
                if n != 2 {
                    continue;
                }
                let Field::Len(metric) = metric else { continue };
                let mut name = String::new();
                let mut points: Vec<f64> = Vec::new();
                for (n, f) in fields(metric)? {
                    match (n, f) {
                        (1, Field::Len(s)) => name = String::from_utf8_lossy(s).into_owned(),
                        (5 | 7, Field::Len(data)) => {
                            for (n, dp) in fields(data)? {
                                if n != 1 {
                                    continue;
                                }
                                let Field::Len(dp) = dp else { continue };
                                for (n, v) in fields(dp)? {
                                    match (n, v) {
                                        (4, Field::Fixed64(bits)) => {
                                            points.push(f64::from_bits(bits))
                                        }
                                        (6, Field::Fixed64(bits)) => {
                                            points.push(bits as i64 as f64)
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // several attribute sets of one metric are summed (rejections by reason)
                if !name.is_empty() && !points.is_empty() {
                    out.push((name, points.iter().sum()));
                }
            }
        }
    }
    Some(out)
}

/// Encodes one gauge point the way the OTLP wire format does (for the decoder's test).
pub fn encode_gauge(name: &str, value: i64) -> Vec<u8> {
    fn put_len(out: &mut Vec<u8>, field: u32, data: &[u8]) {
        let mut key = u64::from(field << 3 | 2);
        loop {
            let b = (key & 0x7f) as u8;
            key >>= 7;
            out.push(if key == 0 { b } else { b | 0x80 });
            if key == 0 {
                break;
            }
        }
        let mut len = data.len() as u64;
        loop {
            let b = (len & 0x7f) as u8;
            len >>= 7;
            out.push(if len == 0 { b } else { b | 0x80 });
            if len == 0 {
                break;
            }
        }
        out.extend_from_slice(data);
    }
    let mut point = vec![(6 << 3 | 1) as u8];
    point.extend_from_slice(&value.to_le_bytes());
    let mut gauge = Vec::new();
    put_len(&mut gauge, 1, &point);
    let mut metric = Vec::new();
    put_len(&mut metric, 1, name.as_bytes());
    put_len(&mut metric, 5, &gauge);
    let mut scope = Vec::new();
    put_len(&mut scope, 2, &metric);
    let mut resource = Vec::new();
    put_len(&mut resource, 2, &scope);
    let mut request = Vec::new();
    put_len(&mut request, 1, &resource);
    request
}

pub struct Collector {
    pub url: String,
    samples: Arc<Mutex<Vec<Sample>>>,
    error_tokens: Arc<Mutex<std::collections::BTreeSet<String>>>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Collector {
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let samples: Arc<Mutex<Vec<Sample>>> = Arc::default();
        let error_tokens: Arc<Mutex<std::collections::BTreeSet<String>>> = Arc::default();
        let tokens = error_tokens.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (s, st) = (samples.clone(), stop.clone());
        let origin = Instant::now();
        let join = thread::spawn(move || {
            while !st.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut conn, _)) => {
                        let s = s.clone();
                        let tokens = tokens.clone();
                        thread::spawn(move || {
                            let _ = handle(&mut conn, &s, &tokens, origin);
                        });
                    }
                    Err(_) => thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(Self {
            url,
            samples,
            error_tokens,
            stop,
            join: Some(join),
        })
    }

    pub fn samples(&self) -> Vec<Sample> {
        self.samples.lock().unwrap().clone()
    }

    /// Stable error-code strings seen in the real OTLP protobuf payloads. This is a
    /// bounded token scan, not a decoding of event counts or attribution to one request.
    pub fn error_tokens(&self) -> Vec<String> {
        self.error_tokens.lock().unwrap().iter().cloned().collect()
    }

    /// Peak of `name` over all exports.
    pub fn peak(&self, name: &str) -> Option<f64> {
        self.samples()
            .iter()
            .filter(|s| s.name == name)
            .map(|s| s.value)
            .fold(None, |m, v| Some(m.map_or(v, |m: f64| m.max(v))))
    }

    pub fn last(&self, name: &str) -> Option<f64> {
        self.samples()
            .iter()
            .rev()
            .find(|s| s.name == name)
            .map(|s| s.value)
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn handle(
    conn: &mut std::net::TcpStream,
    samples: &Mutex<Vec<Sample>>,
    error_tokens: &Mutex<std::collections::BTreeSet<String>>,
    origin: Instant,
) -> std::io::Result<()> {
    conn.set_nonblocking(false)?;
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")?
                .trim()
                .parse::<usize>()
                .ok()
        })
        .unwrap_or(0);
    while buf.len() < end + length {
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    for token in [
        "output_limit",
        "input_limit",
        "metadata_limit",
        "memory_limit",
        "temp_limit",
        "deadline_exceeded",
        "capacity_exceeded",
        "cancelled",
    ] {
        if buf[end..]
            .windows(token.len())
            .any(|bytes| bytes == token.as_bytes())
        {
            error_tokens.lock().unwrap().insert(token.to_owned());
        }
    }
    let first = head.lines().next().unwrap_or("");
    if first.contains("/v1/metrics")
        && let Some(points) = decode_metrics(&buf[end..])
    {
        let at = origin.elapsed().as_secs_f64();
        let mut samples = samples.lock().unwrap();
        for (name, value) in points {
            samples.push(Sample { name, value, at });
        }
    }
    conn.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
}
