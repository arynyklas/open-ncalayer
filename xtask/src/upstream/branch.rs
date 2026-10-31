//! The `upstream` branch as a git worktree: fetched from the remote (or created as an orphan
//! on the first run), the emitted files copied in, committed (JSON only) and pushed without
//! force.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

use super::branch_layout::RUN;
use super::run::files_under;

/// The branch name.
pub const BRANCH: &str = "upstream";

/// A worktree of the branch.
#[derive(Clone, Debug)]
pub struct Branch {
    /// The worktree.
    pub dir: PathBuf,
    /// Created as an orphan (no remote branch yet).
    pub created: bool,
    /// The repository the worktree belongs to.
    repo: PathBuf,
    /// Extra environment of every git command.
    env: Vec<(OsString, OsString)>,
}

fn git(dir: &Path, env: &[(OsString, OsString)]) -> Command {
    let mut c = Command::new("git");
    c.arg("-C").arg(dir);
    c.envs(env.iter().map(|(k, v)| (k, v)));
    c
}

fn run(mut c: Command, what: &str) -> anyhow::Result<String> {
    let out = c.output().with_context(|| format!("git {what}"))?;
    if !out.status.success() {
        bail!(
            "git {what} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Opens the branch `branch` of `remote` as a worktree of `repo` at `dir`: fetched when the
/// remote has it, else a new orphan. A worktree left at `dir` by an earlier run is replaced.
///
/// # Errors
///
/// git errors.
pub fn open(
    repo: &Path,
    remote: &str,
    branch: &str,
    dir: &Path,
    env: &[(OsString, OsString)],
) -> anyhow::Result<Branch> {
    if dir.exists() {
        let mut c = git(repo, env);
        c.args(["worktree", "remove", "--force"]).arg(dir);
        let _ = c.output();
        if dir.exists() {
            std::fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
        }
    }
    let mut prune = git(repo, env);
    prune.args(["worktree", "prune"]);
    run(prune, "worktree prune")?;
    // Another worktree holding the branch (an earlier run elsewhere) would block it.
    let mut list = git(repo, env);
    list.args(["worktree", "list", "--porcelain"]);
    let listing = run(list, "worktree list")?;
    for block in listing.split("\n\n") {
        let path = block.lines().find_map(|l| l.strip_prefix("worktree "));
        let holds = block
            .lines()
            .any(|l| l == format!("branch refs/heads/{branch}"));
        if let (Some(path), true) = (path, holds) {
            let mut remove = git(repo, env);
            remove.args(["worktree", "remove", "--force", path]);
            run(remove, "worktree remove")?;
        }
    }
    let mut fetch = git(repo, env);
    fetch.args(["fetch", "--depth=1", remote, branch]);
    let fetched = fetch.output().map(|o| o.status.success()).unwrap_or(false);
    let mut add = git(repo, env);
    if fetched {
        add.args(["worktree", "add", "--force", "-B", branch])
            .arg(dir)
            .arg("FETCH_HEAD");
    } else {
        let mut delete = git(repo, env);
        delete.args(["branch", "-D", branch]);
        let _ = delete.output();
        add.args(["worktree", "add", "--force", "--orphan", "-b", branch])
            .arg(dir);
    }
    run(add, "worktree add")?;
    Ok(Branch {
        dir: dir.to_owned(),
        created: !fetched,
        repo: repo.to_owned(),
        env: env.to_vec(),
    })
}

impl Branch {
    /// Copies the files of `emit` (but `run.json`) into the worktree; the paths whose bytes
    /// changed.
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn apply(&self, emit: &Path) -> anyhow::Result<Vec<String>> {
        let mut changed = Vec::new();
        for rel in files_under(emit)? {
            if rel == RUN {
                continue;
            }
            let bytes = std::fs::read(emit.join(&rel))?;
            let dest = self.dir.join(&rel);
            if std::fs::read(&dest).ok().as_deref() == Some(bytes.as_slice()) {
                continue;
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&dest, &bytes).with_context(|| format!("write {}", dest.display()))?;
            changed.push(rel);
        }
        Ok(changed)
    }

    /// Commits everything; `false` when nothing changed. Every tracked file must be JSON.
    ///
    /// # Errors
    ///
    /// git errors or a tracked file that is not JSON.
    pub fn commit(&self, message: &str) -> anyhow::Result<bool> {
        let mut add = git(&self.dir, &self.env);
        add.args(["add", "-A"]);
        run(add, "add")?;
        let mut ls = git(&self.dir, &self.env);
        ls.args(["ls-files", "-z"]);
        let files = run(ls, "ls-files")?;
        let stray: Vec<&str> = files
            .split('\0')
            .filter(|f| !f.is_empty() && !f.ends_with(".json"))
            .collect();
        if !stray.is_empty() {
            bail!("the upstream branch holds non-JSON files: {stray:?}");
        }
        let mut quiet = git(&self.dir, &self.env);
        quiet.args(["diff", "--cached", "--quiet"]);
        let has_head = {
            let mut c = git(&self.dir, &self.env);
            c.args(["rev-parse", "--verify", "--quiet", "HEAD"]);
            c.output().map(|o| o.status.success()).unwrap_or(false)
        };
        if has_head && quiet.status().context("git diff")?.success() {
            return Ok(false);
        }
        if !has_head && files.is_empty() {
            return Ok(false);
        }
        let mut commit = git(&self.dir, &self.env);
        if std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| v == "true") {
            commit.args([
                "-c",
                "user.name=github-actions[bot]",
                "-c",
                "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            ]);
        }
        commit.args(["commit", "-q", "-m", message]);
        run(commit, "commit")?;
        Ok(true)
    }

    /// Pushes to `refs/heads/upstream` of `remote`, without force.
    ///
    /// # Errors
    ///
    /// The push is refused.
    pub fn push(&self, remote: &str) -> anyhow::Result<()> {
        let mut push = git(&self.dir, &self.env);
        push.args(["push", "-q", remote, &format!("HEAD:refs/heads/{BRANCH}")]);
        run(push, "push").map(drop)
    }

    /// The repository of the worktree.
    pub fn repo(&self) -> &Path {
        &self.repo
    }
}
