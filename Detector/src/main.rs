extern crate clap;
use clap::{value_parser, Arg, Command};
use log::{error, warn, LevelFilter, Log};
use nix::unistd::chdir;
use perf_event::events::Hardware;
use perf_event::Builder;
use rand::Rng;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use std::time::Duration;
use systemd_journal_logger::{connected_to_journal, JournalLog};

const CACHE_MISS_REF_RATIO_THRESHOLD: f64 = 87.6;
const CACHE_MISS_IGNORE_THRESHOLD: u64 = 10_000;
const RECORDING_TIME_MIN: usize = 2;
const RECORDING_TIME_MAX: usize = 5;

macro_rules! verboseln {
    ($extra:expr, $($arg:tt)*) => {
        {
            if ($extra.verbose && !$extra.daemon) {
                println!($($arg)*);
            }
        }
    };
}

struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let _ = writeln!(std::io::stderr(), "{}", record.args());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

pub struct Config {
    verbose: bool,
    daemon: bool,
    relax_time: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        Config {
            verbose: false,
            daemon: false,
            relax_time: u64::MAX,
        }
    }
}

fn generate_cpu_list() -> Vec<usize> {
    vec![4] // Only return CPU 4
}

fn sleep_sec(sleeptime: u64) {
    let sleep_duration = Duration::from_secs(sleeptime);
    thread::sleep(sleep_duration);
}

fn cli() -> Command {
    Command::new("detector")
        .version("0.1.0")
        .author("Group Project")
        .about("Detection Tool for Cache Side-Channel Attacks")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .required(false)
                .num_args(0)
                .help("Increase verbosity level"),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .required(false)
                .num_args(0)
                .help("Print warn to journal, no debug messages & light daemonize"),
        )
        .arg(
            Arg::new("relax-time")
                .long("relax-time")
                .required(false)
                .value_parser(value_parser!(u64))
                .help("allow to make a break between core scanns, in seconds to wait between, default: 0"),
        )
}

fn parse_args() -> Config {
    let mut cfg = Config::new();
    let matches = cli().get_matches();

    if let Some(c) = matches.get_one::<bool>("verbose") {
        cfg.verbose = *c;
    }

    if let Some(c) = matches.get_one::<bool>("daemon") {
        cfg.daemon = *c
    }

    if let Some(c) = matches.get_one::<u64>("relax-time") {
        cfg.relax_time = *c
    }

    cfg
}

fn recording(record_time: usize, cfg: &Config) {
    if record_time < RECORDING_TIME_MIN {
        panic!(
            "a recording should be at least {} seconds",
            RECORDING_TIME_MIN
        );
    }

    let cpu = 4; // CPU to monitor
    let mut cache_refs = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_REFERENCES)
        .build()
        .unwrap();

    let mut cache_misses = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_MISSES)
        .build()
        .unwrap();

    cache_refs.enable().unwrap();
    cache_misses.enable().unwrap();
    sleep_sec(record_time as u64);
    cache_refs.disable().unwrap();
    cache_misses.disable().unwrap();

    let cache_misses_no = cache_misses.read().unwrap();
    let cache_refs_no = cache_refs.read().unwrap();
    let ratio = (cache_misses_no as f64 / cache_refs_no as f64) * 100.0;

    let cache_refs_per_second = cache_refs_no / record_time as u64;
    if cache_refs_per_second < CACHE_MISS_IGNORE_THRESHOLD {
        verboseln!(
            cfg,
            "ignore record, just nearly no instructions recorded: {}",
            cache_refs_no
        );
        return;
    }

    if cfg.verbose {
        println!(
            "misses: {} refs: {}, ratio: {:.2}%",
            cache_misses_no, cache_refs_no, ratio
        );
    }

    if ratio > CACHE_MISS_REF_RATIO_THRESHOLD {
        let mut msg = String::new();
        msg += &format!(
            "Possible cache side-channel attack on CPU detected!\n"
        );
        msg += &format!(
            "Cache miss/ref ratio {:.2}% above trigger threshold of {:.2}%\n",
            ratio, CACHE_MISS_REF_RATIO_THRESHOLD
        );
        msg += &format!(
            "Within {} recorded seconds on CPU, {} cache references \
               where detected and {} cache misses\n",
            record_time, cache_refs_no, cache_misses_no
        );
        error!("{}", msg);
    }
}

fn daemonize_it(_cfg: &Config) -> Result<(), &'static str> {
    if chdir::<Path>(Path::new("/")).is_err() {
        return Err("Failed to change directory to root (/)");
    }

    if connected_to_journal() {
        JournalLog::default().install().unwrap();
    } else {
        log::set_logger(&SimpleLogger).unwrap();
    }

    log::set_max_level(LevelFilter::Info);

    Ok(())
}

fn banner() {
    warn!("Detection started [monitoring L2 Cache]");
}

fn main() -> std::io::Result<()> {
    let cfg = parse_args();

    daemonize_it(&cfg).unwrap();
    banner();

    loop {
        let record_time = RECORDING_TIME_MAX;
        verboseln!(cfg, "monitoring L2 Cache for {} seconds", record_time);
        recording(record_time, &cfg);

        if cfg.relax_time != u64::MAX {
            verboseln!(cfg, "pause scanning for {} seconds", cfg.relax_time);
            sleep_sec(cfg.relax_time)
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

