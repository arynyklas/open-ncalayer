//! Run with --out <existing scratch parent>; --small selects a quick local run.
#[path = "../tests/support/indexed_probe.rs"]
mod probe;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut parent = None;
    let mut large = true;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                parent = Some(std::path::PathBuf::from(
                    args.next()
                        .ok_or("--out requires an existing scratch parent")?,
                ))
            }
            "--small" => large = false,
            _ => return Err(format!("unknown argument {arg}").into()),
        }
    }
    probe::run(
        parent.ok_or("explicit --out scratch parent required")?,
        large,
    )
}
