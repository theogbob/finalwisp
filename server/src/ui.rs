//! 60.60 what the command line prints: --help, usage errors, the start block, warnings and hints, --show-config, and
//! colour. Text only: every function here returns a String (unit-tested: width, shape); main writes it. The options
//! and their texts are cli::OPTIONS.
use crate::cli::{self, OptSpec, Setting, Src, Start, COMMON, OPTIONS, TOPICS};
use std::ffi::OsStr;

/// no line of --help, of a usage error or of the start block is longer (a word that is longer stands alone)
pub const WIDTH: usize = 80;
/// the release version: server/Cargo.toml is its one source (bench/release.sh and bench/package.sh read the same)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const DOCS: &str = "https://github.com/theogbob/finalwisp (docs/configuration.md)";

/// The columns a text takes on a terminal: 2 for the wide East Asian and emoji ranges, 0 for combining marks, else 1
/// (an operator's value, such as a --motd, can hold any text; the built-in texts are ASCII). An estimate: the exact
/// tables are a dependency's work.
pub fn cols(s: &str) -> usize {
    s.chars()
        .map(|c| match c as u32 {
            0x300..=0x36f | 0x200b..=0x200f | 0xfe00..=0xfe0f => 0,
            0x1100..=0x115f | 0x2e80..=0xa4cf | 0xac00..=0xd7a3 | 0xf900..=0xfaff | 0xfe30..=0xfe4f => 2,
            0xff00..=0xff60 | 0xffe0..=0xffe6 | 0x1f300..=0x1faff | 0x20000..=0x3fffd => 2,
            _ => 1,
        })
        .sum()
}

/// Word wrap at `width` columns: the first line starts with `first`, the others with `rest`. Words are never cut.
pub fn wrap(text: &str, width: usize, first: &str, rest: &str) -> String {
    let (mut out, mut line) = (String::new(), first.to_string());
    let mut empty = true; // the line holds only its indent
    for word in text.split_whitespace() {
        if !empty && cols(&line) + 1 + cols(word) > width {
            out += line.trim_end();
            out.push('\n');
            line = rest.to_string();
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line += word;
        empty = false;
    }
    out += line.trim_end();
    out
}

/// ANSI colour, only where a person reads it: the stream is a terminal, NO_COLOR is unset or empty (no-color.org) and
/// TERM is set and not "dumb". Files, pipes and journald get plain text.
pub fn colour_wanted(tty: bool, no_color: Option<&OsStr>, term: Option<&OsStr>) -> bool {
    tty && no_color.is_none_or(|v| v.is_empty()) && term.is_some_and(|t| !t.is_empty() && t != "dumb")
}

/// The colours of one stream (false: every method returns the text unchanged)
#[derive(Clone, Copy)]
pub struct Paint(pub bool);

impl Paint {
    /// for stdout (fd 1) or stderr (fd 2)
    pub fn of(fd: libc::c_int) -> Paint {
        // SAFETY: isatty only reads the descriptor number
        let tty = unsafe { libc::isatty(fd) } == 1;
        Paint(colour_wanted(tty, std::env::var_os("NO_COLOR").as_deref(), std::env::var_os("TERM").as_deref()))
    }
    fn sgr(self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn bold(self, s: &str) -> String {
        self.sgr("1", s)
    }
    /// `finalwisp: warning: text` / `finalwisp: hint: text`, wrapped; the word is yellow (warning) or cyan (hint)
    pub fn note(self, kind: &str, text: &str) -> String {
        let whole = format!("finalwisp: {kind}: {text}");
        let mut plain = wrap(&whole, WIDTH, "", "  ");
        // the fix on its own line, when the what and the fix then still take 2 lines
        if let Some((what, fix)) = whole.split_once(" Fix: ").filter(|_| plain.contains('\n')) {
            let split = format!("{}\n{}", wrap(what, WIDTH, "", "  "), wrap(&format!("Fix: {fix}"), WIDTH, "  ", "  "));
            if split.lines().count() <= 2 {
                plain = split;
            }
        }
        let word = format!("{kind}:");
        plain.replacen(&word, &self.sgr(if kind == "warning" { "33" } else { "36" }, &word), 1)
    }
}

fn topic_names() -> String {
    TOPICS.iter().map(|t| t.0).chain(["all"]).collect::<Vec<_>>().join(", ")
}

/// `--name ARG`
fn form(s: &OptSpec) -> String {
    if s.arg.is_empty() {
        s.name.to_string()
    } else {
        format!("{} {}", s.name, s.arg)
    }
}

/// `finalwisp --help`: the first page
pub fn help_main(p: Paint) -> String {
    let mut out = format!("finalwisp {VERSION} - a Wisp server: TCP and UDP for browsers, over a WebSocket\n\n");
    out += &format!("{} finalwisp [PORT] [OPTIONS]\n\n{}\n", p.bold("Usage:"), p.bold("Start it:"));
    for (cmd, what) in [
        ("finalwisp", "a local test on ws://127.0.0.1:6001/"),
        ("finalwisp --preset public --trusted-proxy 127.0.0.1", "a public server behind nginx or Caddy"),
        ("finalwisp --preset public --host 0.0.0.0 --port 443 --tls-cert C --tls-key K", "a public server with built-in TLS (wss://)"),
        ("finalwisp --config FILE", "options from a file"),
    ] {
        const COL: usize = 36;
        if cmd.len() + 4 <= COL {
            out += &format!("  {cmd:<w$}{what}\n", w = COL - 2);
        } else {
            out += &format!("  {cmd}\n{:COL$}{what}\n", "");
        }
    }
    out += &format!("\n{}\n", p.bold("Common options:"));
    let common: Vec<&OptSpec> = COMMON.iter().filter_map(|n| cli::spec(n)).collect();
    let w = common.iter().map(|s| form(s).len()).max().unwrap_or(0);
    let d = common.iter().map(|s| s.default.len()).max().unwrap_or(0) + 2;
    for s in common {
        // (a default of "off" or "none" says nothing on this page; --preset none is a value)
        let quiet = s.default.is_empty() || s.default == "off" || (s.default == "none" && s.name != "--preset");
        let default = if quiet { String::new() } else { format!("[{}]", s.default) };
        let line = format!("  {:<w$}  {:<sw$}{default}", form(s), s.summary, sw = WIDTH - 4 - w - d);
        out += line.trim_end();
        out.push('\n');
    }
    out += &format!("\n{} finalwisp --help TOPIC (or --help all)\n", p.bold("More options by topic:"));
    let w = TOPICS.iter().map(|t| t.0.len()).max().unwrap_or(0);
    for (name, line, _) in TOPICS {
        out += &format!("  {name:<w$}  {line}\n");
    }
    out += &format!("\n{}\n", p.bold("Other commands:"));
    for (cmd, what) in [
        ("finalwisp [OPTIONS] --show-config", "check the options, show the settings, exit"),
        ("finalwisp --print-preset public", "print the settings of a preset"),
        ("finalwisp --version", "print the version"),
    ] {
        out += &format!("  {cmd:<33}  {what}\n");
    }
    out + &format!("\n{} {DOCS}\n", p.bold("Docs:"))
}

/// One topic's page: every option of the topic with its default and its long text
fn topic_page(p: Paint, name: &str, intro: &str) -> String {
    let mut out = format!("{}\n{}\n", p.bold(&format!("finalwisp {VERSION} - options: {name}")), wrap(intro, WIDTH, "", ""));
    for s in OPTIONS.iter().filter(|s| s.topic == name) {
        let (left, right) =
            (format!("  {}", form(s)), if s.default.is_empty() { String::new() } else { format!("[default: {}]", s.default) });
        out.push('\n');
        if left.len() + 2 + right.len() <= WIDTH {
            out += format!("{}{right:>w$}", p.bold(&left), w = WIDTH - left.len()).trim_end();
        } else {
            out += &format!("{}\n      {right}", p.bold(&left));
        }
        out += &format!("\n{}\n", wrap(if s.long.is_empty() { s.summary } else { s.long }, WIDTH, "      ", "      "));
    }
    out
}

/// `finalwisp --help TOPIC` (`all`: every topic). Err: the usage error for a topic that does not exist.
pub fn help_topic(p: Paint, topic: &str) -> Result<String, String> {
    if topic == "all" {
        return Ok(TOPICS.iter().map(|t| topic_page(p, t.0, t.2)).collect::<Vec<_>>().join("\n") + "\nFirst page: finalwisp --help\n");
    }
    match TOPICS.iter().find(|t| t.0 == topic) {
        Some(t) => Ok(topic_page(p, t.0, t.2) + "\nOther topics: finalwisp --help\n"),
        None => {
            // (the word is echoed only if it looks like a name: the rule of every error text)
            let near = cli::nearest(topic, TOPICS.iter().map(|t| t.0).chain(["all"]));
            let what = match (cli::flag_like(topic), near) {
                (true, Some(n)) => format!("--help: no topic {topic:?} (did you mean {n}?)"),
                (true, None) => format!("--help: no topic {topic:?}"),
                (false, _) => "--help: no such topic".to_string(),
            };
            Err(format!(
                "{}\n{}\nTry: finalwisp --help\n",
                wrap(&format!("finalwisp: {what}"), WIDTH, "", "  "),
                wrap(&format!("Topics: {}", topic_names()), WIDTH, "", "  ")
            ))
        }
    }
}

/// The --help topic an error message points to: the topic of the first option the message names (`--name`), else of
/// the option after "did you mean" (a config file's names have no dashes)
fn error_topic(msg: &str) -> Option<&'static str> {
    let word = |c: char| !(c.is_ascii_alphanumeric() || c == '-');
    // (--help and --version have no page of their own to point to)
    let named = msg.split(word).filter(|w| w.starts_with("--") && !matches!(*w, "--help" | "--version")).find_map(cli::spec);
    let meant = || msg.split_once("did you mean ").and_then(|(_, m)| cli::spec(&format!("--{}", m.split(word).next()?)));
    named.or_else(meant).map(|s| s.topic)
}

/// A usage error as main prints it (exit 2): the message, then where to read more. Never the option list. `tty`:
/// stderr is a terminal, so the message is wrapped at WIDTH; in a file, a pipe or journald it is one line (as every
/// log line: grep finds the whole text).
pub fn usage_error(msg: &str, tty: bool) -> String {
    let more = error_topic(msg).map_or(String::new(), |t| format!(" {t}"));
    let msg = format!("finalwisp: {msg}");
    format!("{}\nTry: finalwisp --help{more}\n", if tty { wrap(&msg, WIDTH, "", "  ") } else { msg })
}

/// in a block value: a space where the line must not break (`max-conns 5` stays together)
const TIE: char = '\u{1}';

/// Rows `key  value` with the keys in one column; long values wrap under their start
pub fn block(rows: &[(String, String)]) -> String {
    let w = rows.iter().map(|r| cols(&r.0)).max().unwrap_or(0) + 2;
    let mut out = String::new();
    for (k, v) in rows {
        let first = format!("  {k:<w$}");
        out += &wrap(v, WIDTH, &first, &" ".repeat(w + 2));
        out.push('\n');
    }
    out.replace(TIE, " ")
}

fn layer(s: Src) -> &'static str {
    match s {
        Src::Preset => "preset",
        Src::File => "config file",
        Src::Cmd => "command line",
    }
}

/// The rows of the start block that say where the settings come from: `preset`, `config file`, `command line`. Every
/// setting that is not the default stands once, under the layer that decides it; the preset's row lists every setting
/// of the preset with the value in effect (and the layer, when another one overrides it).
pub fn layer_rows(st: &Start) -> Vec<(String, String)> {
    let keys = cli::preset_keys(st.preset);
    let one = |s: &Setting| format!("{}{TIE}{}", s.key, s.value);
    let mut rows = Vec::new();
    let preset = match st.preset {
        None => "none".to_string(),
        Some((name, _)) if keys.is_empty() => name.to_string(),
        Some((name, _)) => {
            let parts = keys.iter().filter_map(|k| st.settings.iter().find(|s| s.key == k)).map(|s| match s.src {
                Some(Src::Preset) => one(s),
                other => format!("{}{TIE}({})", one(s), other.map_or("default", layer).replace(' ', &TIE.to_string())),
            });
            format!("{name}: {}", parts.collect::<Vec<_>>().join(", "))
        }
    };
    rows.push(("preset".to_string(), preset));
    let of = |l: Src| {
        let own = st.settings.iter().filter(|s| s.src == Some(l) && s.changed && !keys.iter().any(|k| k == s.key));
        own.map(one).collect::<Vec<_>>().join(", ")
    };
    if let Some(path) = &st.config {
        let set = of(Src::File);
        rows.push(("config file".to_string(), if set.is_empty() { path.clone() } else { format!("{path}: {set}") }));
    }
    let set = of(Src::Cmd);
    if !set.is_empty() {
        rows.push(("command line".to_string(), set));
    }
    rows
}

/// `finalwisp [OPTIONS] --show-config`: every setting in effect by topic, with the layer that set it, then what this
/// host allows (`host`: rows from main) and notes about it.
pub fn show_config(p: Paint, st: &Start, host: &[(String, String)], notes: &[String]) -> String {
    let mut out = format!("{}\n", p.bold(&format!("finalwisp {VERSION}: the options are valid. Nothing was started.")));
    out += &wrap(
        "Every setting in effect, by --help topic. A value without a layer in brackets is the default. Layers, lowest \
         first: preset, config file, command line.",
        WIDTH,
        "",
        "",
    );
    out.push('\n');
    for (topic, _, _) in TOPICS {
        let mut rows = Vec::new();
        if *topic == "config" {
            let name = |l: Option<Src>| l.map_or(String::new(), |l| format!(" ({})", layer(l)));
            rows.push(("preset".to_string(), st.preset.map_or("none".to_string(), |(n, l)| format!("{n}{}", name(Some(l))))));
            rows.push(("config".to_string(), st.config.clone().unwrap_or("none".to_string())));
        }
        for s in st.settings.iter().filter(|s| s.topic == *topic) {
            let value = match s.src {
                Some(l) => format!("{} ({})", s.value, layer(l)),
                None if s.key == "threads" => format!("{} ({})", st.opts.threads.max(1), s.value),
                None => s.value.clone(),
            };
            rows.push((s.key.to_string(), value));
        }
        out += &format!("\n{}\n{}", p.bold(topic), block(&rows));
    }
    out += &format!("\n{}\n{}", p.bold("This host"), block(host));
    if !notes.is_empty() {
        out += &format!("\n{}\n", p.bold("Notes"));
        for n in notes {
            out += &wrap(n, WIDTH, "  ", "  ");
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: Paint = Paint(false);

    fn fits(text: &str) -> bool {
        // a line is at most WIDTH columns, or it is one word (a path or a URL is never cut)
        text.lines().all(|l| cols(l) <= WIDTH || !l.trim_start().contains(' '))
    }

    fn start(cmd: &str, file: &str) -> Start {
        let args = cmd.split_whitespace().map(String::from).collect();
        match cli::command(args, 4, |_| Ok((file.as_bytes().to_vec(), 0o600))) {
            Ok(cli::Command::Start(st)) => *st,
            _ => panic!("{cmd}: not a start"),
        }
    }

    #[test]
    fn wrap_keeps_words_and_width() {
        assert_eq!(wrap("a b c", 80, "", ""), "a b c");
        assert_eq!(wrap("aaa bbb ccc ddd", 7, "", "  "), "aaa bbb\n  ccc\n  ddd");
        assert_eq!(wrap("aaa bbb ccc", 9, "> ", "  "), "> aaa bbb\n  ccc");
        assert_eq!(wrap("a-very-long-word b", 5, "", " "), "a-very-long-word\n b", "a word is never cut");
        assert_eq!(wrap("", 80, "x", ""), "x");
        assert_eq!(wrap("  a   b \n c ", 80, "", ""), "a b c");
        assert_eq!(wrap("\u{e9}\u{e9} \u{e9}\u{e9}", 5, "", ""), "\u{e9}\u{e9} \u{e9}\u{e9}", "columns, not bytes");
        // a wide character is 2 columns, a combining mark none
        assert_eq!((cols("abc"), cols("\u{754c}\u{754c}"), cols("e\u{301}"), cols("")), (3, 4, 1, 0));
        assert_eq!(wrap("\u{754c}\u{754c} \u{754c}\u{754c}", 8, "", ""), "\u{754c}\u{754c}\n\u{754c}\u{754c}");
        // an operator's text with wide characters in the start block and in --show-config
        let motd = vec!["\u{754c}"; 60].join(" ");
        let rows = block(&[("command line".to_string(), format!("motd {motd}"))]);
        assert!(rows.lines().count() > 1 && rows.lines().all(|l| cols(l) <= WIDTH), "{rows}");
    }

    /// B: the first page is short: a title with the version, the usage, start examples, the common options with
    /// their defaults (one line each), the topics, the other commands, the docs
    #[test]
    fn help_first_page() {
        let h = help_main(PLAIN);
        assert!(h.lines().count() <= 45, "{} lines", h.lines().count());
        assert!(h.lines().all(|l| l.chars().count() <= WIDTH), "{h}");
        assert!(h.starts_with(&format!("finalwisp {VERSION} - ")) && h.ends_with('\n'));
        for part in ["\nUsage: finalwisp [PORT] [OPTIONS]\n", "\nStart it:\n", "\nCommon options:\n", "\nOther commands:\n", "\nDocs: "] {
            assert!(h.contains(part), "{part:?}");
        }
        for example in [
            "  finalwisp  ",
            "  finalwisp --preset public --trusted-proxy 127.0.0.1\n",
            "--tls-cert C --tls-key K\n",
            "  finalwisp --config FILE ",
        ] {
            assert!(h.contains(example), "{example:?}");
        }
        assert!(!h.contains("--preset public --host 0.0.0.0\n"), "no example of plain ws:// open to everyone");
        for name in COMMON {
            let s = cli::spec(name).unwrap();
            let line: Vec<&str> = h.lines().filter(|l| l.starts_with(&format!("  {name} "))).collect();
            assert_eq!(line.len(), 1, "{name}: one line");
            assert!(line[0].contains(s.summary), "{}", line[0]);
        }
        assert!(h.contains("[127.0.0.1]") && h.contains("[6001]") && h.contains("[one per CPU]") && h.contains("[info]"));
        for (name, line, _) in TOPICS {
            assert!(h.contains(&format!("  {name:<12}  {line}\n")), "{name}");
        }
        for cmd in ["--show-config", "--print-preset public", "--version", "--help TOPIC", "--help all"] {
            assert!(h.contains(cmd), "{cmd}");
        }
        assert!(!h.contains('\x1b') && help_main(Paint(true)).contains("\x1b[1mUsage:\x1b[0m"));
    }

    /// B / A: every option is in exactly one topic page, with its long text, wrapped; `all` is every page
    #[test]
    fn help_topics_hold_every_option_once() {
        let pages: Vec<(&str, String)> = TOPICS.iter().map(|t| (t.0, help_topic(PLAIN, t.0).unwrap())).collect();
        let heads = |page: &str, s: &OptSpec| {
            page.lines().filter(|l| *l == format!("  {}", form(s)) || l.starts_with(&format!("  {}  ", form(s)))).count()
        };
        for s in OPTIONS {
            for (topic, page) in &pages {
                assert_eq!(heads(page, s), (*topic == s.topic) as usize, "{} in --help {topic}", s.name);
            }
            let page = &pages.iter().find(|p| p.0 == s.topic).unwrap().1;
            let first = s.long.split_whitespace().take(4).collect::<Vec<_>>().join(" ");
            assert!(page.contains(&format!("      {first}")), "{}: its text", s.name);
            assert!(s.default.is_empty() || page.contains(&format!("[default: {}]", s.default)), "{}: its default", s.name);
        }
        let all = help_topic(PLAIN, "all").unwrap();
        for (topic, page) in &pages {
            assert!(fits(page) && !page.contains('\x1b'), "--help {topic}");
            assert!(
                page.starts_with(&format!("finalwisp {VERSION} - options: {topic}\n"))
                    && page.ends_with("\nOther topics: finalwisp --help\n")
            );
            assert!(all.contains(page.trim_end_matches("\nOther topics: finalwisp --help\n")), "all holds {topic}");
        }
        assert!(OPTIONS.iter().all(|s| heads(&all, s) == 1) && fits(&all));
        // a page is plain reading text: no option list in brackets, no line of the old usage wall
        assert!(!all.contains("[--") && all.lines().all(|l| l.chars().count() <= WIDTH));
    }

    #[test]
    fn unknown_topic_lists_the_topics() {
        let e = help_topic(PLAIN, "limit").unwrap_err();
        assert_eq!(
            e,
            "finalwisp: --help: no topic \"limit\" (did you mean limits?)\nTopics: config, listen, tls, client-ip, limits, \
             destinations, auth, upstream,\n  dns, logs, memory, advanced, all\nTry: finalwisp --help\n"
        );
        assert!(help_topic(PLAIN, "nothing").unwrap_err().starts_with("finalwisp: --help: no topic \"nothing\"\nTopics: config, "));
        let e = help_topic(PLAIN, "s3cret/VALUE").unwrap_err();
        assert!(e.starts_with("finalwisp: --help: no such topic\n") && !e.contains("s3cret"), "{e}");
        for t in TOPICS {
            assert!(help_topic(PLAIN, t.0).is_ok());
        }
    }

    /// D: a usage error is the message and the way to more: never the option list
    #[test]
    fn usage_errors_point_to_a_topic() {
        for (msg, want) in [
            (
                "unknown option --max-con (did you mean --max-conns?)",
                "finalwisp: unknown option --max-con (did you mean --max-conns?)\nTry: finalwisp --help limits\n",
            ),
            (
                "--port: \"abc\" is not a port (1-65535)",
                "finalwisp: --port: \"abc\" is not a port (1-65535)\nTry: finalwisp --help listen\n",
            ),
            ("unknown option --frobnicate", "finalwisp: unknown option --frobnicate\nTry: finalwisp --help\n"),
            (
                "unknown argument \"help\" (did you mean --help?)",
                "finalwisp: unknown argument \"help\" (did you mean --help?)\nTry: finalwisp --help\n",
            ),
            (
                "/etc/fw.conf:7: unknown option \"max-con\" (did you mean max-conns?)",
                "finalwisp: /etc/fw.conf:7: unknown option \"max-con\" (did you mean max-conns?)\nTry: finalwisp --help limits\n",
            ),
            (
                "f:3: --threads: (value not shown) is not a whole number",
                "finalwisp: f:3: --threads: (value not shown) is not a whole number\nTry: finalwisp --help listen\n",
            ),
            ("--config f: No such file or directory", "finalwisp: --config f: No such file or directory\nTry: finalwisp --help config\n"),
            (
                "--preset: unknown preset \"pubic\" (the presets: public, none)",
                "finalwisp: --preset: unknown preset \"pubic\" (the presets: public, none)\nTry: finalwisp --help config\n",
            ),
            ("an argument is not valid UTF-8", "finalwisp: an argument is not valid UTF-8\nTry: finalwisp --help\n"),
        ] {
            assert_eq!(usage_error(msg, true), want);
            assert_eq!(usage_error(msg, false), want, "a short message is the same in a file");
        }
        let removed = "--prio was removed before v1.0.0: the priority lane is the default (--no-prio turns it off); drop it";
        let long = usage_error(removed, true);
        assert_eq!(long.lines().count(), 3, "{long}");
        assert!(fits(&long) && long.lines().nth(1).unwrap().starts_with("  ") && long.ends_with("Try: finalwisp --help advanced\n"));
        // not a terminal: the message is one line (a log line), then the Try line
        assert_eq!(usage_error(removed, false), format!("finalwisp: {removed}\nTry: finalwisp --help advanced\n"));
    }

    /// G: colour only where a person reads it
    #[test]
    fn colour_only_on_a_terminal() {
        let os = |s: &'static str| Some(OsStr::new(s));
        assert!(colour_wanted(true, None, os("xterm-256color")));
        assert!(colour_wanted(true, os(""), os("xterm")), "an empty NO_COLOR does not count (no-color.org)");
        assert!(!colour_wanted(false, None, os("xterm")), "a file, a pipe, journald");
        assert!(!colour_wanted(true, os("1"), os("xterm")), "NO_COLOR");
        assert!(!colour_wanted(true, None, os("dumb")));
        assert!(!colour_wanted(true, None, None) && !colour_wanted(true, None, os("")), "no TERM");
        // the test runner's stderr may be anything; an fd that is not open is no terminal
        assert!(!Paint::of(-1).0);
        let (text, fix) = ("mail ports 25, 465 and 587 are open to clients.", "Fix: --block-smtp (part of --preset public).");
        let plain = PLAIN.note("hint", &format!("{text} {fix}"));
        assert_eq!(plain, format!("finalwisp: hint: {text}\n  {fix}"));
        assert!(!plain.contains('\x1b') && !PLAIN.bold("x").contains('\x1b'));
        let on = Paint(true);
        assert_eq!(on.bold("finalwisp listening on ws://127.0.0.1:6001/"), "\x1b[1mfinalwisp listening on ws://127.0.0.1:6001/\x1b[0m");
        assert!(on.note("hint", "x").starts_with("finalwisp: \x1b[36mhint:\x1b[0m x"));
        assert!(on.note("warning", "x").starts_with("finalwisp: \x1b[33mwarning:\x1b[0m x"));
        // the same text with and without colour
        let strip = |s: &str| s.replace("\x1b[36m", "").replace("\x1b[33m", "").replace("\x1b[1m", "").replace("\x1b[0m", "");
        assert_eq!(strip(&on.note("hint", &format!("{text} {fix}"))), plain);
        assert_eq!(strip(&help_main(on)), help_main(PLAIN));
        assert_eq!(strip(&help_topic(on, "all").unwrap()), help_topic(PLAIN, "all").unwrap());
    }

    /// F: a warning is what, the effect and the fix in at most 2 lines; the fix starts the second line when it fits
    #[test]
    fn notes_take_two_lines() {
        let n = PLAIN.note(
            "warning",
            "open-file limit 1024: it caps connections plus streams. Fix: ulimit -n 65536, or LimitNOFILE=65536 in the systemd unit.",
        );
        assert_eq!(
            n,
            "finalwisp: warning: open-file limit 1024: it caps connections plus streams.\n  Fix: ulimit -n 65536, or LimitNOFILE=65536 in the systemd unit."
        );
        assert_eq!(PLAIN.note("warning", "short. Fix: this."), "finalwisp: warning: short. Fix: this.", "one line when it fits");
        let long = PLAIN.note("warning", &format!("{} Fix: do it.", "word ".repeat(30).trim_end()));
        assert!(long.lines().count() == 3 && fits(&long), "a long text wraps as it comes: {long}");
    }

    /// F: the rows that say where the settings come from: every setting that is not the default, once
    #[test]
    fn start_block_layer_rows() {
        let rows = |cmd: &str, file: &str| {
            layer_rows(&start(cmd, file)).into_iter().map(|(k, v)| format!("{k}: {}", v.replace(TIE, " "))).collect::<Vec<_>>()
        };
        assert_eq!(rows("", ""), ["preset: none"]);
        assert_eq!(rows("--port 6001 --host 127.0.0.1 --max-conns 0 --no-block-smtp", ""), ["preset: none"], "defaults are not listed");
        // (T: the settings that v1.3.0 added to the preset: 60.57 / 60.58 and the four of 60.63)
        const T: &str =
            ", fd-admission on, conn-share on, dns-own on, dns-reserve on, tcpmem-share on, port-share on, dest-failfast on, net-watch on";
        let t = |s: &str| format!("{s}{T}");
        assert_eq!(rows("--preset public", ""), [t("preset: public: block-smtp on, max-streams-per-conn 1024")]);
        assert_eq!(rows("--preset none 7000", ""), ["preset: none", "command line: port 7000"]);
        // a config file or the command line turns one of them off: the row names the layer
        assert_eq!(
            rows("--preset public --config f --no-dns-reserve", "no-conn-share\nno-dns-own\n"),
            [
                "preset: public: block-smtp on, max-streams-per-conn 1024, fd-admission on, conn-share off (config file), dns-own off (config file), \
                 dns-reserve off (command line), tcpmem-share on, port-share on, dest-failfast on, net-watch on",
                "config file: f"
            ]
        );
        assert_eq!(
            rows("--preset public --no-block-smtp --no-udp", ""),
            [t("preset: public: block-smtp off (command line), max-streams-per-conn 1024"), "command line: udp off".to_string()]
        );
        assert_eq!(
            rows("--preset public --config /etc/fw.conf --host 0.0.0.0", "trusted-proxy 127.0.0.1\nmax-streams-per-conn 256\nport 6001\n"),
            [
                t("preset: public: block-smtp on, max-streams-per-conn 256 (config file)"),
                "config file: /etc/fw.conf: trusted-proxy 127.0.0.1".to_string(),
                "command line: host 0.0.0.0".to_string()
            ]
        );
        assert_eq!(rows("--config f", "port 6001\n"), ["preset: none", "config file: f"]);
        assert_eq!(
            rows("--config f", "preset public\nblock-smtp\n"),
            [t("preset: public: block-smtp on (config file), max-streams-per-conn 1024"), "config file: f".to_string()]
        );
        // the block: one key column; a long value wraps under its start, between settings (never inside one)
        let mut all = vec![("version".to_string(), "1.3.0".to_string())];
        all.extend(layer_rows(&start(
            "--preset public --host 0.0.0.0 --port 443 --max-conns 20000 --max-conns-per-ip 64 --motd hello --no-udp --no-splice --balance",
            "",
        )));
        let b = block(&all);
        assert_eq!(
            b,
            "  version       1.3.0\n  preset        public: block-smtp on, max-streams-per-conn 1024,\n                fd-admission on, conn-share on, \
             dns-own on, dns-reserve on,\n                tcpmem-share on, port-share on, dest-failfast on, net-watch on\n  command line  host 0.0.0.0, port 443, \
             splice off, balance on, udp off,\n                motd hello, max-conns 20000, max-conns-per-ip 64\n"
        );
        assert!(fits(&b));
    }

    /// E: --show-config names every setting once, under its topic, with the layer of a value that is not the default
    #[test]
    fn show_config_lists_every_setting() {
        let st =
            start("--preset public --config /etc/fw.conf --port 7000 --no-udp", "max-streams-per-conn 256\ntrusted-proxy 10.0.0.0/8\n");
        let host = vec![("kernel".to_string(), "6.8.0".to_string())];
        let s = show_config(PLAIN, &st, &host, &["a note".to_string()]);
        assert!(s.starts_with(&format!("finalwisp {VERSION}: the options are valid. Nothing was started.\n")));
        assert!(fits(&s) && !s.contains('\x1b'), "{s}");
        let row = |key: &str| {
            let hit: Vec<&str> =
                s.lines().filter(|l| l.strip_prefix("  ").is_some_and(|r| r.split_whitespace().next() == Some(key))).collect();
            assert_eq!(hit.len(), 1, "{key}: {hit:?}");
            hit[0].split_whitespace().skip(1).collect::<Vec<_>>().join(" ")
        };
        for x in &st.settings {
            row(x.key);
        }
        assert_eq!(row("preset"), "public (command line)");
        assert_eq!(row("config"), "/etc/fw.conf");
        assert_eq!(row("port"), "7000 (command line)");
        assert_eq!(row("udp"), "off (command line)");
        assert_eq!(row("block-smtp"), "on (preset)");
        assert_eq!(row("max-streams-per-conn"), "256 (config file)");
        assert_eq!(row("trusted-proxy"), "10.0.0.0/8 (config file)");
        assert_eq!(row("host"), "127.0.0.1");
        assert_eq!(row("threads"), "4 (one per CPU)");
        assert_eq!(row("splice"), "on");
        assert_eq!(row("kernel"), "6.8.0");
        // the topics in --help's order, then the host and the notes
        let heads: Vec<&str> = s.lines().skip(3).filter(|l| !l.is_empty() && !l.starts_with(' ')).collect();
        let want: Vec<&str> = TOPICS.iter().map(|t| t.0).chain(["This host", "Notes"]).collect();
        assert_eq!(heads, want);
        assert!(s.ends_with("\nNotes\n  a note\n"));
        assert!(!show_config(PLAIN, &start("", ""), &host, &[]).contains("Notes"));
    }
}
