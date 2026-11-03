//! Run with --out <existing scratch parent>; --small is 2 MiB, --medium is 64 MiB.
#[path = "../tests/support/indexed_probe.rs"]
mod probe;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut parent = None;
    let mut large = true;
    let mut medium = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                parent = Some(std::path::PathBuf::from(
                    args.next()
                        .ok_or("--out requires an existing scratch parent")?,
                ))
            }
            "--small" => large = false,
            "--medium" => medium = true,
            _ => return Err(format!("unknown argument {arg}").into()),
        }
    }
    let parent = parent.ok_or("explicit --out scratch parent required")?;
    if medium {
        probe::run_records(parent, 1024)
    } else {
        probe::run(parent, large)
    }
}
