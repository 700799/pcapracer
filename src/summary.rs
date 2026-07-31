use crate::config::TableSet;
use std::collections::BTreeMap;

/// Counters describing a completed extraction run.
#[derive(Default, Debug)]
pub struct RunSummary {
    pub packets: u64,
    pub decode_errors: u64,
    pub bytes_read: u64,
    pub table_rows: BTreeMap<&'static str, u64>,
    pub table_paths: BTreeMap<&'static str, String>,
    pub elapsed_s: f64,
}

impl RunSummary {
    pub fn new(tables: &TableSet) -> RunSummary {
        let mut s = RunSummary::default();
        if tables.packets {
            s.table_rows.insert("packets", 0);
        }
        if tables.flows {
            s.table_rows.insert("flows", 0);
        }
        if tables.dns {
            s.table_rows.insert("dns", 0);
        }
        if tables.http {
            s.table_rows.insert("http", 0);
        }
        if tables.tls {
            s.table_rows.insert("tls", 0);
        }
        s
    }

    pub fn pkts_per_s(&self) -> f64 {
        if self.elapsed_s > 0.0 {
            self.packets as f64 / self.elapsed_s
        } else {
            0.0
        }
    }
}
