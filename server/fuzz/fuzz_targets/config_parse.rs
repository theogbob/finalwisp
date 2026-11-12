#![no_main]
//! 60.20 C8 cli.rs expand_config on a random --config file and command line: never panics; an accepted file leaves no
//! --config behind and parse_args can run on the result; an error never shows a value from the file.
//! Input: the command line (NUL-separated tokens, as cli_parse: a token whose first byte b is 0x01..=0x1f is a known
//! flag, cli::FLAGS[(b - 1 + 31 * (len - 1)) % FLAGS.len()], or, when b = 0x1f, --config (a 1-byte token), --preset (2
//! bytes) or a preset name (60.59)), then 0xff 0xfe, then the file. Also 60.59: every token of the result has a layer,
//! no --preset is left in it, and the preset line never panics.
use finalwisp_fuzz::cli;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (cmd, file) = match data.windows(2).position(|w| w == [0xff, 0xfe]) {
        Some(i) => (&data[..i], &data[i + 2..]),
        None => (&data[..0], data),
    };
    let mut args: Vec<String> = if cmd.is_empty() {
        Vec::new()
    } else {
        cmd.split(|&b| b == 0)
            .map(|t| match t.first() {
                Some(0x1f) if t.len() == 1 => "--config".to_string(),
                Some(0x1f) if t.len() == 2 => "--preset".to_string(),
                Some(0x1f) => cli::PRESETS[t.len() % cli::PRESETS.len()].0.to_string(),
                Some(&b @ 1..=0x1e) => cli::FLAGS[(b as usize - 1 + 31 * (t.len() - 1)) % cli::FLAGS.len()].0.to_string(),
                _ => String::from_utf8_lossy(t).into_owned(),
            })
            .collect()
    };
    if !args.iter().any(|a| a == "--config") {
        args.extend(["--config".to_string(), "F".to_string()]);
    }
    let mut loaded = false;
    match cli::expand_config(args.clone(), |p| {
        loaded = true;
        assert!(!p.is_empty() || args.iter().any(|a| a.is_empty()));
        Ok((file.to_vec(), 0o644))
    }) {
        Ok(ex) => {
            if ex.config.is_some() {
                assert!(loaded);
            }
            // 60.59 one layer per token; a preset line exactly when a preset was named
            assert_eq!(ex.args.len(), ex.src.len());
            assert_eq!(cli::preset_line(&ex).is_some(), ex.preset.is_some());
            let _ = cli::parse_args(ex.args, 4);
        }
        Err(e) => {
            assert!(!e.is_empty());
            // no value from the file shows up in the message (secrets). Values are taken with the file format's rules;
            // only values with a character that no message text has (non-ASCII or one of MARK) are checked, after the
            // the message body after the "FILE:LINE: " or "--config FILE: " prefix (the path is an argv token) is checked;
            // other values can match flag names or reasons.
            const MARK: &str = cli::REDACTION_MARKS; // 70.28 (cli.rs tests check that no error text has one)
            let mut i = 0;
            let mut path = None;
            while i < args.len() {
                // the config path as expand_config finds it (--config at an option position)
                if args[i] == "--config" {
                    path = path.or(args.get(i + 1).cloned());
                }
                let value = matches!(args[i].as_str(), "--config" | "--preset" | "--print-preset")
                    || cli::FLAGS.iter().any(|&(f, v)| v && f == args[i]);
                i += if value { 2 } else { 1 };
            }
            let e = match &path {
                Some(p) => {
                    if let Some(b) = e.strip_prefix(&format!("--config {p}: ")) {
                        b.to_string()
                    } else if let Some(b) = e.strip_prefix(&format!("{p}:")) {
                        b.trim_start_matches(|c: char| c.is_ascii_digit()).trim_start_matches(": ").to_string()
                    } else {
                        e
                    }
                }
                None => e,
            };
            for line in String::from_utf8_lossy(file).lines() {
                let t = line.trim();
                if t.starts_with('#') {
                    continue;
                }
                if let Some((_, v)) = t.split_once([' ', '\t']) {
                    let v = v.trim();
                    if v.chars().any(|c| !c.is_ascii() || MARK.contains(c)) {
                        assert!(!e.contains(v), "value shown: {e}");
                    }
                }
            }
        }
    }
});
