// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Utilities for reading key template test data

use regex::Regex;
use std::{io::BufRead, path::PathBuf};
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::KeyTemplate;

/// Read a [`KeyTemplate`] from testdata/templates.
pub fn key_template_proto(dir: &str, name: &str) -> Result<KeyTemplate, TinkError> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("testdata");
    path.push("templates");
    path.push(dir);
    path.push(name);

    let mut template = KeyTemplate {
        type_url: "".to_string(),
        value: vec![],
        output_prefix_type: tink_proto::OutputPrefixType::UnknownPrefix as i32,
    };

    // Key templates are in text proto format, which is not supported by prost.
    // Parse manually.
    let comment_re = Regex::new(r"^\s*#.*$").unwrap();
    let type_re = Regex::new(r#"^\s*type_url\s*:\s*"(.+)"\s*$"#).unwrap();
    let value_re = Regex::new(r#"^\s*value\s*:\s*"(.+)"\s*$"#).unwrap();
    let prefix_re = Regex::new(r#"^\s*output_prefix_type\s*:\s*(\S+)\s*$"#).unwrap();
    let file = std::fs::File::open(&path).map_err(|e| wrap_err("Failed to open", e))?;
    for line in std::io::BufReader::new(file).lines().flatten() {
        if comment_re.is_match(&line) {
            continue;
        }
        if let Some(captures) = type_re.captures(&line) {
            template.type_url = captures[1].to_string();
        } else if let Some(captures) = value_re.captures(&line) {
            template.value = escaped_string_to_bytes(&captures[1])?;
        } else if let Some(captures) = prefix_re.captures(&line) {
            template.output_prefix_type = match &captures[1] {
                "TINK" => tink_proto::OutputPrefixType::Tink,
                "LEGACY" => tink_proto::OutputPrefixType::Legacy,
                "RAW" => tink_proto::OutputPrefixType::Raw,
                "CRUNCHY" => tink_proto::OutputPrefixType::Crunchy,
                _ => tink_proto::OutputPrefixType::UnknownPrefix,
            } as i32;
        } else {
            return Err(format!("Failed to parse text protobuf line: '{}'", line).into());
        }
    }

    Ok(template)
}

/// Convert a string to bytes, allowing for escaped data.
fn escaped_string_to_bytes(input: &str) -> Result<Vec<u8>, TinkError> {
    let mut output = vec![];
    enum State {
        Normal,
        Escaped,
        Octal1(u8),
        Octal2(u8),
    }
    let mut state = State::Normal;
    for c in input.chars() {
        match state {
            State::Normal => match c {
                '\\' => state = State::Escaped,
                _ if c.is_ascii() => {
                    let mut b = vec![0];
                    c.encode_utf8(&mut b);
                    output.push(b[0]);
                }
                _ => return Err(format!("Parse failure: invalid non-ASCII char {}", c).into()),
            },
            State::Escaped => match c {
                'n' => {
                    output.push(10);
                    state = State::Normal;
                }
                't' => {
                    output.push(9);
                    state = State::Normal;
                }
                'r' => {
                    output.push(13);
                    state = State::Normal;
                }
                'f' => {
                    output.push(12);
                    state = State::Normal;
                }
                '\\' => {
                    output.push(92);
                    state = State::Normal;
                }
                '\'' => {
                    output.push(39);
                    state = State::Normal;
                }
                '\"' => {
                    output.push(34);
                    state = State::Normal;
                }
                '0' => state = State::Octal1(0),
                '1' => state = State::Octal1(1),
                '2' => state = State::Octal1(2),
                '3' => state = State::Octal1(3),
                _ => return Err(format!("Parse failure: invalid escape char {}", c).into()),
            },
            State::Octal1(h) => match c {
                '0' => state = State::Octal2(h << 3),
                '1' => state = State::Octal2((h << 3) + 1),
                '2' => state = State::Octal2((h << 3) + 2),
                '3' => state = State::Octal2((h << 3) + 3),
                '4' => state = State::Octal2((h << 3) + 4),
                '5' => state = State::Octal2((h << 3) + 5),
                '6' => state = State::Octal2((h << 3) + 6),
                '7' => state = State::Octal2((h << 3) + 7),
                _ => return Err(format!("Parse failure: invalid first octal digit {}", c).into()),
            },
            State::Octal2(hi) => {
                let lo = match c {
                    '0' => 0,
                    '1' => 1,
                    '2' => 2,
                    '3' => 3,
                    '4' => 4,
                    '5' => 5,
                    '6' => 6,
                    '7' => 7,
                    _ => {
                        return Err(
                            format!("Parse failure: invalid second octal digit {}", c).into()
                        )
                    }
                };
                output.push((hi << 3) + lo);
                state = State::Normal;
            }
        }
    }
    Ok(output)
}
