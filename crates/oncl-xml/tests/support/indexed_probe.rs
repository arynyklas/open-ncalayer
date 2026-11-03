//! Shared by the ignored integration case and the executable release probe.
use oncl_pki::{
    io::{Region, Source, TemporaryStore},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
};
use oncl_xml::{XmlDocument, XmlLimits};
use std::{
    io::Read,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const RECORDS: u64 = 65537;
const PAYLOAD: usize = 65536;
const TARGET: &[u8] = b"<signed:record xmlns:signed='urn:oncl:records' Id='beyond-4gib'><amount currency='KZT'>4242.75</amount><owner>\xd2\x9a\xd0\xb0\xd0\xb7\xd0\xb0\xd2\x9b\xd1\x81\xd1\x82\xd0\xb0\xd0\xbd</owner></signed:record>";
const PREFIX: &[u8] = b"<?xml version='1.0' encoding='UTF-8'?><records xmlns='urn:oncl:records'>";
fn head(i: u64) -> String {
    format!("<record Id='record-{i}' sequence='{i}'><samples encoding='csv'>")
}
const TAIL: &[u8] = b"</samples></record>";
struct Generated {
    phase: u64,
    part: Vec<u8>,
    at: usize,
    records: u64,
}
impl Generated {
    fn new(records: u64) -> Self {
        Self {
            phase: 0,
            part: Vec::new(),
            at: 0,
            records,
        }
    }
    fn part(&mut self) -> bool {
        self.part.clear();
        self.at = 0;
        if self.phase == 0 {
            self.part.extend_from_slice(PREFIX);
        } else if self.phase <= self.records {
            let i = self.phase - 1;
            self.part.extend_from_slice(head(i).as_bytes());
            // Each record is a named, sequenced telemetry record containing a
            // fixed-size CSV sample window, not sparse bytes or unused padding.
            let row = format!("{i},temperature,23.25,pressure,1013.20,humidity,42.50\n");
            for j in 0..PAYLOAD {
                self.part.push(row.as_bytes()[j % row.len()]);
            }
            self.part.extend_from_slice(TAIL);
        } else if self.phase == self.records + 1 {
            self.part.extend_from_slice(TARGET);
            self.part.extend_from_slice(b"</records>");
        } else {
            return false;
        }
        self.phase += 1;
        true
    }
    fn target_region(records: u64) -> Region {
        let mut offset = PREFIX.len() as u64;
        for i in 0..records {
            offset += head(i).len() as u64 + PAYLOAD as u64 + TAIL.len() as u64;
        }
        Region {
            offset,
            len: TARGET.len() as u64,
        }
    }
}
impl Read for Generated {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        if self.at == self.part.len() && !self.part() {
            return Ok(0);
        }
        let n = b.len().min(self.part.len() - self.at);
        b[..n].copy_from_slice(&self.part[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
struct Control(Arc<AtomicBool>);
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::Relaxed) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
pub fn run(parent: PathBuf, large: bool) -> Result<(), Box<dyn std::error::Error>> {
    run_records(parent, if large { RECORDS } else { 33 })
}
pub fn run_records(parent: PathBuf, records: u64) -> Result<(), Box<dyn std::error::Error>> {
    assert!((1..=RECORDS).contains(&records));
    let expected = Generated::target_region(records);
    if records == RECORDS {
        assert!(expected.offset > u32::MAX as u64);
    }
    let limits = ResourceLimits {
        operation_timeout: Duration::from_secs(1800),
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone())?);
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut scope = budget.begin(limits.clone(), Arc::new(Control(cancelled.clone())))?;
    let scratch = tempfile::tempdir_in(&parent)?;
    let store = TemporaryStore::new(scratch.path())?;
    let root = std::fs::read_dir(scratch.path())?
        .next()
        .ok_or("missing owned store")??
        .path();
    let start = Instant::now();
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Generated::new(records), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )?;
    let node = doc.lookup_id("beyond-4gib")?.ok_or("missing target")?;
    let actual = doc.node_region(&node)?;
    assert_eq!(actual, expected);
    let mut bytes = vec![0; TARGET.len()];
    let n = doc.read_node(&node, 0, &mut bytes)?;
    assert_eq!(&bytes[..n], TARGET);
    let record = doc
        .lookup_id(&format!("record-{}", records - 1))?
        .ok_or("missing last record")?;
    let r = doc.node_region(&record)?;
    let mut prefix = [0; 128];
    let n = doc.read_node(&record, 0, &mut prefix)?;
    assert!(prefix[..n].starts_with(head(records - 1).as_bytes()));
    assert_eq!(
        r.len,
        head(records - 1).len() as u64 + PAYLOAD as u64 + TAIL.len() as u64
    );
    println!(
        "INDEX_OK records={records} bytes={} tokens={} target_offset={} target_len={} exact_content=true last_record_offset={} elapsed_ms={}",
        doc.len(),
        doc.token_count(),
        actual.offset,
        actual.len,
        r.offset,
        start.elapsed().as_millis()
    );
    cancelled.store(true, Ordering::Relaxed);
    assert!(matches!(
        doc.lookup_id("beyond-4gib"),
        Err(ProcessingError::Cancelled)
    ));
    println!("CANCEL_OK replay observes original operation cancellation");
    drop(doc);
    drop(scope);
    assert_eq!(std::fs::read_dir(&root)?.count(), 0);
    let mut tiny = limits.clone();
    tiny.temp_bytes = 262144;
    let mut scope = budget.begin(tiny, Arc::new(Control(Arc::new(AtomicBool::new(false)))))?;
    let result = XmlDocument::index(
        Source::sequential(&mut Generated::new(33), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    );
    assert!(matches!(result, Err(ProcessingError::TempLimit)));
    assert_eq!(std::fs::read_dir(&root)?.count(), 0);
    println!("DISK_QUOTA_OK partial source removed; owned_store_files=0");
    drop(scope);
    drop(store);
    assert_eq!(std::fs::read_dir(scratch.path())?.count(), 0);
    println!("CLEANUP_OK source/token/key/run artifacts and owned store removed");
    Ok(())
}
