use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone};
use csv::{QuoteStyle, ReaderBuilder, StringRecord, WriterBuilder};
use hashbrown::HashSet;

use crate::detections::configs::SortCsvOption;
use crate::detections::message::AlertMessage;

const TIMESTAMP_COLUMN: &str = "Timestamp";
const EVTX_FILE_COLUMN: &str = "EvtxFile";

/// Timestamp formats Hayabusa can write for the `Timestamp` column (see `format_time` in
/// `utils.rs`). `%.f` matches whatever fractional-second precision was used (`.3f`/`.6f`/none),
/// so the default and the `--rfc-3339` outputs share a pattern. Offset-bearing formats are parsed
/// as `DateTime`; the offset-less ones fall through to the naive parsers below.
const OFFSET_FORMATS: &[&str] = &[
    "%Y-%m-%d %H:%M:%S%.f %:z",    // default
    "%Y-%m-%d %H:%M:%S%.f%:z",     // --rfc-3339
    "%m-%d-%Y %H:%M:%S%.f %:z",    // --us-military-time
    "%d-%m-%Y %H:%M:%S%.f %:z",    // --european-time
    "%m-%d-%Y %I:%M:%S%.f %p %:z", // --us-time
    "%a, %e %b %Y %H:%M:%S %:z",   // --rfc-2822
];

const NAIVE_FORMATS: &[&str] = &[
    "%Y-%m-%dT%H:%M:%S%.fZ", // --iso-8601 (the trailing Z is literal in Hayabusa's output)
    "%Y-%m-%d %H:%M:%S%.f",
];

const DATE_ONLY_FORMATS: &[&str] = &["%Y-%m-%d", "%m-%d-%Y", "%d-%m-%Y", "%a, %e %b %Y"];

/// Turn a UTC-anchored timestamp into a comparable nanosecond key. Unlike `timestamp_nanos_opt`,
/// which is `None` for dates outside roughly 1677-2262, this covers the full range chrono can
/// represent, so an old event timestamp does not flip the whole file to a lexical fallback.
fn sort_key<Tz: TimeZone>(dt: DateTime<Tz>) -> i128 {
    dt.timestamp() as i128 * 1_000_000_000 + i128::from(dt.timestamp_subsec_nanos())
}

/// Parse a Hayabusa timestamp cell into a comparable nanosecond value. Offset-aware timestamps are
/// normalized to UTC; offset-less and date-only ones are taken at face value. Returns `None` when
/// none of the known formats match, which flips the whole sort to a lexical fallback.
fn parse_timestamp(value: &str) -> Option<i128> {
    let value = value.trim();
    for fmt in OFFSET_FORMATS {
        if let Ok(parsed) = DateTime::parse_from_str(value, fmt) {
            return Some(sort_key(parsed));
        }
    }
    for fmt in NAIVE_FORMATS {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(value, fmt) {
            return Some(sort_key(parsed.and_utc()));
        }
    }
    for fmt in DATE_ONLY_FORMATS {
        if let Ok(date) = NaiveDate::parse_from_str(value, fmt) {
            return Some(sort_key(date.and_hms_opt(0, 0, 0)?.and_utc()));
        }
    }
    None
}

/// Gather the CSV files to process: the single `-f` file, or every `*.csv` in the `-d` directory
/// (sorted by path so a directory scan is deterministic).
fn collect_input_files(opt: &SortCsvOption) -> Vec<PathBuf> {
    if let Some(file) = &opt.filepath {
        return vec![file.clone()];
    }
    let Some(dir) = &opt.directory else {
        return vec![];
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            AlertMessage::alert(&format!(
                "Failed to read directory {}. {err}",
                dir.display()
            ))
            .ok();
            process::exit(1);
        }
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
        })
        .collect();
    files.sort();
    files
}

/// Read one CSV, returning its header row and its data rows. The header is checked against the
/// first file's header by the caller so that rows from different files line up column-for-column.
///
/// Rows are kept as the `csv::StringRecord` the reader already produced (2 allocations per row)
/// instead of being converted to `Vec<String>` (one allocation per cell), which matters because
/// every row of every input file is held in memory at once.
fn read_csv(path: &Path) -> Option<(Vec<String>, Vec<StringRecord>)> {
    let mut reader = match ReaderBuilder::new().flexible(true).from_path(path) {
        Ok(reader) => reader,
        Err(err) => {
            AlertMessage::alert(&format!("Failed to open {}. {err}", path.display())).ok();
            return None;
        }
    };
    let header = match reader.headers() {
        Ok(header) => header.iter().map(str::to_string).collect::<Vec<_>>(),
        Err(err) => {
            AlertMessage::alert(&format!(
                "Failed to read header of {}. {err}",
                path.display()
            ))
            .ok();
            return None;
        }
    };
    let mut rows = vec![];
    for record in reader.records() {
        match record {
            Ok(record) => rows.push(record),
            Err(err) => {
                AlertMessage::alert(&format!(
                    "Failed to read a row in {}. {err}",
                    path.display()
                ))
                .ok();
                return None;
            }
        }
    }
    Some((header, rows))
}

/// Order `rows` by `key_of` and keep only the first of any set of rows that are identical apart
/// from the `EvtxFile` column, so the same detection collected from overlapping/backup `.evtx`
/// files collapses to one entry (same logic as `-X, --remove-duplicate-detections`).
///
/// `key_of` drives both the sort and the dedup, and the caller deliberately cannot supply them
/// separately. The dedup key contains the `Timestamp` column, so two rows that are duplicates of
/// each other necessarily share a timestamp, hence a sort key: sorting by it makes them adjacent,
/// so `seen` only has to hold one run of equal keys at a time instead of a copy of every unique
/// row in the file. That reasoning holds only while the two uses agree. Keying the dedup on the
/// raw timestamp string while sorting on the parsed value, for instance, would split a run
/// whenever rows written in different timezones (`+09:00` and `+00:00` for the same instant)
/// interleave, and duplicates would slip through. Same approach as `get_duplicate_indices` in
/// `src/results/mod.rs`.
fn sort_and_dedup<K, F>(
    rows: &[StringRecord],
    evtx_idx: Option<usize>,
    mut key_of: F,
) -> Vec<&StringRecord>
where
    K: Ord,
    F: FnMut(usize) -> K,
{
    // Sorting indexes leaves the rows themselves in place. The sort is stable and the input order
    // is already deterministic (`collect_input_files` sorts by path and rows follow file order),
    // so ordering on the timestamp alone is reproducible without a tie-break on the row contents,
    // which would deep-compare rows O(n log n) times. The rule that settles: rows sharing a
    // timestamp are emitted in input order, i.e. path order, so the surviving row of a duplicate
    // group is the one from the first input file rather than the one that sorts first by content.
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&i| key_of(i));

    let mut output_rows = vec![];
    let mut seen: HashSet<Vec<&str>> = HashSet::new();
    let mut prev_key: Option<K> = None;
    for idx in order {
        let key = key_of(idx);
        if prev_key.as_ref() != Some(&key) {
            seen.clear();
            prev_key = Some(key);
        }
        let row = &rows[idx];
        let dedup_key: Vec<&str> = match evtx_idx {
            Some(i) => row
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, cell)| cell)
                .collect(),
            None => row.iter().collect(),
        };
        if seen.insert(dedup_key) {
            output_rows.push(row);
        }
    }
    output_rows
}

pub fn sort_csv(opt: &SortCsvOption) {
    let files = collect_input_files(opt);
    if files.is_empty() {
        AlertMessage::alert("No CSV files were found to sort.").ok();
        process::exit(1);
    }

    let mut header: Option<Vec<String>> = None;
    let mut rows: Vec<StringRecord> = vec![];
    for file in &files {
        let Some((file_header, file_rows)) = read_csv(file) else {
            process::exit(1);
        };
        match &header {
            None => header = Some(file_header),
            Some(expected) if expected != &file_header => {
                AlertMessage::warn(&format!(
                    "Skipping {}: its header does not match the other files.",
                    file.display()
                ))
                .ok();
                continue;
            }
            Some(_) => {}
        }
        rows.extend(file_rows);
    }

    let header = header.unwrap();
    let Some(timestamp_idx) = header.iter().position(|col| col == TIMESTAMP_COLUMN) else {
        AlertMessage::alert(&format!(
            "The input CSV has no {TIMESTAMP_COLUMN} column, so it cannot be sorted by time."
        ))
        .ok();
        process::exit(1);
    };
    let evtx_idx = header.iter().position(|col| col == EVTX_FILE_COLUMN);

    // Sentinel for a timestamp none of the known formats matched. `parsed` is only read when
    // `all_parsed` is true, so this value can never take part in the ordering. Storing a plain
    // `i128` rather than `Option<i128>` halves the table: `Option<i128>` has no niche, so it
    // costs 32 bytes per row to carry 16 bytes of data. `all_parsed` is settled by the time the
    // vector exists, because `collect` drives the whole iterator.
    const UNPARSED: i128 = i128::MIN;

    let mut all_parsed = true;
    let parsed: Vec<i128> = rows
        .iter()
        .map(
            |row| match row.get(timestamp_idx).and_then(parse_timestamp) {
                Some(key) => key,
                None => {
                    all_parsed = false;
                    UNPARSED
                }
            },
        )
        .collect();

    // Sort and dedup on the parsed timestamp. If any row's timestamp is in a format we don't
    // recognize, fall back to the raw timestamp string, which orders lexically.
    let output_rows = if all_parsed {
        sort_and_dedup(&rows, evtx_idx, |i| parsed[i])
    } else {
        sort_and_dedup(&rows, evtx_idx, |i| rows[i].get(timestamp_idx))
    };

    if let Err(err) = write_output(opt, &header, &output_rows) {
        AlertMessage::alert(&format!("Failed to write output. {err}")).ok();
        process::exit(1);
    }
}

fn write_output(opt: &SortCsvOption, header: &[String], rows: &[&StringRecord]) -> io::Result<()> {
    let sink: Box<dyn Write> = if let Some(path) = &opt.output {
        if path.exists() && !opt.clobber {
            AlertMessage::alert(&format!(
                "{} already exists. Use -C, --clobber to overwrite it.",
                path.display()
            ))
            .ok();
            process::exit(1);
        }
        Box::new(BufWriter::new(fs::File::create(path)?))
    } else {
        Box::new(BufWriter::new(io::stdout()))
    };

    let mut writer = WriterBuilder::new()
        .quote_style(QuoteStyle::NonNumeric)
        .from_writer(sink);
    writer.write_record(header)?;
    for row in rows {
        writer.write_record(*row)?;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path in the system temp dir, namespaced by process id so two test runs on the same
    /// machine do not fight over the same file.
    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hayabusa_sortcsv_test_{}_{name}", process::id()))
    }

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let path = temp_path(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn sorts_by_timestamp_and_drops_evtxfile_duplicates() {
        // Two records share every field except EvtxFile (collected from a backup evtx), so one is
        // a duplicate. The input is also out of time order to exercise the sort.
        let input = "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\"\n\
\"2021-12-13 09:05:00.000 +09:00\",\"Later\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Earlier\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Earlier\",\"host1\",\"backup.evtx\"\n";
        let in_path = write_temp("in.csv", input);
        let out_path = temp_path("out.csv");
        let _ = fs::remove_file(&out_path);

        let opt = SortCsvOption {
            filepath: Some(in_path.clone()),
            directory: None,
            output: Some(out_path.clone()),
            clobber: true,
            common_options: Default::default(),
        };
        sort_csv(&opt);

        let result = fs::read_to_string(&out_path).unwrap();
        let lines: Vec<&str> = result.lines().collect();

        // Header preserved.
        assert_eq!(
            lines[0],
            "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\""
        );
        // The duplicate (same fields, different EvtxFile) is gone: header + 2 rows.
        assert_eq!(lines.len(), 3);
        // Earlier timestamp sorts first.
        assert!(lines[1].contains("Earlier"));
        assert!(lines[2].contains("Later"));

        let _ = fs::remove_file(&in_path);
        let _ = fs::remove_file(&out_path);
    }

    /// Run `sort_csv` over `input` and return the lines it wrote. `name` has to be unique per
    /// test because the temp files are named after it and tests run in parallel.
    fn run_sort_csv(name: &str, input: &str) -> Vec<String> {
        let in_path = write_temp(&format!("{name}_in.csv"), input);
        let out_path = temp_path(&format!("{name}_out.csv"));
        let _ = fs::remove_file(&out_path);

        let opt = SortCsvOption {
            filepath: Some(in_path.clone()),
            directory: None,
            output: Some(out_path.clone()),
            clobber: true,
            common_options: Default::default(),
        };
        sort_csv(&opt);

        let result = fs::read_to_string(&out_path).unwrap();
        let _ = fs::remove_file(&in_path);
        let _ = fs::remove_file(&out_path);
        result.lines().map(str::to_string).collect()
    }

    #[test]
    fn duplicates_sharing_a_timestamp_are_removed_even_when_not_adjacent() {
        // `seen` is cleared at every timestamp-group boundary, so a duplicate is only caught if
        // both copies land in the same group. Here another row with the same timestamp sits
        // between them in the input, which is exactly the case a per-row reset would miss.
        let input = "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Dup\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Other\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Dup\",\"host1\",\"backup.evtx\"\n";
        let lines = run_sort_csv("nonadjacent", input);

        // Header + Dup + Other: the second copy of Dup is gone.
        assert_eq!(lines.len(), 3);
        assert_eq!(lines.iter().filter(|line| line.contains("Dup")).count(), 1);
    }

    #[test]
    fn duplicates_are_removed_when_offsets_differ_within_one_timestamp_group() {
        // These CSVs were written in different timezones, so rows for the same instant carry
        // different timestamp strings and interleave inside a single sort-key group. Resetting
        // `seen` on the raw string instead of the sort key would split the two Dup rows apart
        // and let the duplicate through.
        let input = "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Dup\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 00:00:00.000 +00:00\",\"Other\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Dup\",\"host1\",\"backup.evtx\"\n";
        let lines = run_sort_csv("mixedoffsets", input);

        assert_eq!(lines.len(), 3);
        assert_eq!(lines.iter().filter(|line| line.contains("Dup")).count(), 1);
    }

    #[test]
    fn rows_sharing_a_timestamp_keep_their_input_order() {
        // The sort has no tie-break on the row contents, so rows with the same timestamp come
        // out in input order (path order across files). This is the documented rule, not an
        // accident of the comparator: with a content tie-break "Alpha" would sort first.
        let input = "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Zulu\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Alpha\",\"host1\",\"a.evtx\"\n";
        let lines = run_sort_csv("inputorder", input);

        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("Zulu"));
        assert!(lines[2].contains("Alpha"));
    }

    #[test]
    fn lexical_fallback_still_sorts_and_dedups() {
        // One unrecognized timestamp flips the whole file to the lexical fallback; sorting and
        // dedup have to keep working on the raw strings.
        let input = "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\"\n\
\"zzz not a timestamp\",\"Unparsable\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Dup\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Dup\",\"host1\",\"backup.evtx\"\n";
        let lines = run_sort_csv("fallback", input);

        // Header + Dup + Unparsable: the duplicate is gone and "2..." sorts before "z...".
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("Dup"));
        assert!(lines[2].contains("Unparsable"));
    }

    #[test]
    fn parses_all_supported_timestamp_formats() {
        assert!(parse_timestamp("2021-12-13 09:00:00.000 +09:00").is_some());
        assert!(parse_timestamp("2021-12-13T09:00:00.000000Z").is_some());
        assert!(parse_timestamp("12-13-2021 09:00:00.000 +09:00").is_some());
        assert!(parse_timestamp("2021-12-13").is_some());
        assert!(parse_timestamp("not a timestamp").is_none());
    }

    #[test]
    fn earlier_timestamp_orders_first() {
        let earlier = parse_timestamp("2021-12-13 09:00:00.000 +09:00").unwrap();
        let later = parse_timestamp("2021-12-13 09:05:00.000 +09:00").unwrap();
        assert!(earlier < later);
    }

    #[test]
    fn timestamps_before_the_nanosecond_epoch_still_sort() {
        // Dates before ~1677 overflow chrono's `timestamp_nanos_opt`; the sort key must still
        // cover them so a single old row does not flip the whole file to a lexical fallback.
        let ancient = parse_timestamp("1601-01-01").unwrap();
        let modern = parse_timestamp("2021-12-13").unwrap();
        assert!(ancient < modern);
    }
}
