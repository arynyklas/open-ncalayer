#[path = "server_support/mod.rs"]
mod support;

#[test]
fn standalone_binary_dispatches_typed_json_to_the_real_sdk() {
    let process = support::Process::start("");
    let runtime = support::runtime();
    let (status, bytes) = runtime.block_on(support::request(
        process.address,
        &process.token,
        "/v1/operations",
        br#"{"metadata":{"items":[{"id":"process","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"process","role":"document"}]},"documents":{"doc":"abc"}}"#,
        &[("content-type", "application/json")],
        None,
    ));
    assert_eq!(status, 200);
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["type"], "final");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["results"][0]["item_id"], "process");
    assert_eq!(result["results"][0]["applied"], "NotApplied");
    assert_eq!(result["results"][0]["result"]["bytes_in"], 3);
    assert_eq!(
        result["results"][0]["result"]["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    process.stop();
}

fn scratch_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_file() {
            files.push(entry.path());
        } else if kind.is_dir() {
            files.extend(scratch_files(&entry.path()));
        }
    }
    files
}
#[cfg(windows)]
fn assert_owner_only_file(path: &std::path::Path) {
    let script = r#"$a=Get-Acl -LiteralPath '__PATH__';$t=[System.Security.Principal.SecurityIdentifier];[pscustomobject]@{owner=$a.GetOwner($t).Value;current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rules=@($a.GetAccessRules($true,$true,$t)|ForEach-Object{[pscustomobject]@{sid=$_.IdentityReference.Value;kind=$_.AccessControlType.ToString()}})}|ConvertTo-Json -Depth 4 -Compress"#;
    let script = script.replace("__PATH__", &path.to_string_lossy().replace('\'', "''"));
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .unwrap();
    assert!(output.status.success(), "ACL query failed");
    let acl: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(acl["owner"], acl["current"]);
    let rules = acl["rules"].as_array().unwrap();
    assert!(!rules.is_empty());
    for rule in rules {
        assert_eq!(rule["sid"], acl["current"]);
        assert_eq!(rule["kind"], "Allow");
    }
}
#[cfg(unix)]
fn assert_owner_only_file(path: &std::path::Path) {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o077, 0);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        metadata.uid(),
        std::fs::metadata(path.parent().unwrap()).unwrap().uid()
    );
}

#[test]
fn standalone_multipart_uses_actual_random_private_scratch_and_cleans_it() {
    use std::{
        io::{Read, Write},
        time::{Duration, Instant},
    };
    let process = support::Process::configured("127.0.0.1:0", |root| {
        format!(
            "scratch_directory = {}\nmax_in_flight = 1\nblocking_workers = 1\nqueue_capacity = 1",
            support::toml_path(&root.join("scratch"))
        )
    });
    let scratch = process.directory.path().join("scratch");
    assert!(scratch_files(&scratch).is_empty());
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        process.address,
        process.token.as_str()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    let metadata = r#"{"items":[{"id":"process","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"process","role":"document"}]}"#;
    let prefix = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"../../caller-selected.pdf\"\r\nContent-Type: application/pdf\r\n\r\nabc"
    );
    stream
        .write_all(format!("{:x}\r\n", prefix.len()).as_bytes())
        .unwrap();
    stream.write_all(prefix.as_bytes()).unwrap();
    stream.write_all(b"\r\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let file = loop {
        let files = scratch_files(&scratch);
        if let Some(file) = files
            .into_iter()
            .find(|path| std::fs::metadata(path).unwrap().len() == 3)
        {
            break file;
        }
        assert!(
            Instant::now() < deadline,
            "actual input staging never became observable"
        );
        std::thread::park_timeout(Duration::from_millis(1));
    };
    assert_eq!(std::fs::read(&file).unwrap(), b"abc");
    let name = file.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("oncl-"));
    assert_eq!(name.len(), 37);
    assert!(!name.contains("caller-selected"));
    assert_owner_only_file(&file);
    assert_eq!(
        support::runtime()
            .block_on(support::request(
                process.address,
                &process.token,
                "/health",
                b"",
                &[],
                None
            ))
            .0,
        200
    );
    let suffix = b"\r\n--b--\r\n";
    stream
        .write_all(format!("{:x}\r\n", suffix.len()).as_bytes())
        .unwrap();
    stream.write_all(suffix).unwrap();
    stream.write_all(b"\r\n0\r\n\r\n").unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let body = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let result: serde_json::Value = serde_json::from_slice(&response[body..]).unwrap();
    assert_eq!(result["type"], "final");
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["results"][0]["result"]["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(scratch_files(&scratch).is_empty());
    assert!(
        !process
            .directory
            .path()
            .join("caller-selected.pdf")
            .exists()
    );
    let metadata = r#"{"items":[{"id":"secret","operation":{"kind":"hash","algorithm":"sha256","input":"key"}}],"parts":[{"name":"key","item_id":"secret","role":"secret"}]}"#;
    let secret = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"key\"; filename=\"../private-key.pdf\"\r\nContent-Type: application/pdf\r\n\r\nCHILD-SECRET-MARKER-NEVER-SPOOL\r\n--b--\r\n"
    );
    let mut rejected = std::net::TcpStream::connect(process.address).unwrap();
    rejected
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        process.address,
        process.token.as_str(),
        secret.len()
    );
    rejected.write_all(headers.as_bytes()).unwrap();
    rejected.write_all(secret.as_bytes()).unwrap();
    let mut response = Vec::new();
    rejected.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 400"));
    assert!(!String::from_utf8_lossy(&response).contains("CHILD-SECRET-MARKER"));
    assert!(scratch_files(&scratch).is_empty());
    process.stop();
}
