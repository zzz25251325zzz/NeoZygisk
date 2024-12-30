use std::{
    fs::File,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

use log::debug;

use crate::constants::MIN_APATCH_VERSION;

const CONFIG_FILE: &str = "/data/adb/ap/package_config";

pub enum Version {
    Supported,
    TooOld,
}

#[allow(dead_code)]
struct PackageInfo {
    pkg: String,
    exclude: bool,
    allow: bool,
    uid: i32,
    to_uid: i32,
    sctx: String,
}

pub fn get_apatch() -> Option<Version> {
    Command::new("apd")
        .arg("-V")
        .stdout(Stdio::piped())
        .spawn()
        .ok()
        .and_then(|child| child.wait_with_output().ok())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| {
            let parts: Vec<&str> = output.split_whitespace().collect();
            if parts.len() != 2 {
                None
            } else {
                parts[1].parse::<i32>().ok()
            }
        })
        .map(|version| {
            if version >= MIN_APATCH_VERSION {
                Version::Supported
            } else {
                Version::TooOld
            }
        })
}

fn parse_config_file(filename: &str) -> Result<Vec<PackageInfo>, String> {
    let file = File::open(filename).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut reader = BufReader::new(file);

    // Skip the header row
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read header: {}", e))?;
    line.clear();

    let mut result = Vec::new();
    while let Ok(bytes_read) = reader.read_line(&mut line) {
        if bytes_read == 0 {
            break; // Reached end of file
        }

        let mut parts = line.trim().split(',');
        match (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) {
            (
                Some(pkg),
                Some(exclude),
                Some(allow),
                Some(uid_str),
                Some(to_uid_str),
                Some(sctx),
            ) => {
                let uid = uid_str
                    .parse::<i32>()
                    .map_err(|e| format!("Invalid field uid {uid_str}: {}", e))?;
                let to_uid = to_uid_str
                    .parse::<i32>()
                    .map_err(|e| format!("Invalid field to_uid {to_uid_str}: {}", e))?;
                result.push(PackageInfo {
                    pkg: pkg.to_string(),
                    exclude: exclude == "1",
                    allow: allow == "1",
                    uid,
                    to_uid,
                    sctx: sctx.to_string(),
                });
            }
            _ => {
                return Err(format!("Invalid line format: {}", line));
            }
        }
        line.clear();
    }

    Ok(result)
}

pub fn uid_granted_root(uid: i32) -> bool {
    match parse_config_file(CONFIG_FILE) {
        Ok(packages) => {
            for pkg in packages {
                if pkg.uid == uid {
                    return pkg.allow;
                }
            }
            false
        }
        Err(msg) => {
            debug!("Failed to parse config file: {msg}");
            false
        }
    }
}

pub fn uid_should_umount(uid: i32) -> bool {
    match parse_config_file(CONFIG_FILE) {
        Ok(packages) => {
            for pkg in packages {
                if pkg.uid == uid {
                    return pkg.exclude;
                }
            }
            false
        }
        Err(msg) => {
            debug!("Failed to parse config file: {msg}");
            false
        }
    }
}

pub fn uid_is_manager(uid: i32) -> bool {
    if let Ok(s) = rustix::fs::stat("/data/user_de/0/me.bmax.apatch") {
        return s.st_uid == uid as u32;
    }
    false
}
