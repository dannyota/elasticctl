const PREFIX: &str = "mcp_answers_across_verticals timing ";
const TOOLS: [&str; 4] = [
    "alert_context",
    "detection_coverage",
    "rule_health",
    "rule_readiness",
];

pub(super) fn public_timing_lines(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .filter(|line| is_public_timing(line))
        .map(str::to_owned)
        .collect()
}

fn is_public_timing(line: &str) -> bool {
    let Some(rest) = line.strip_prefix(PREFIX) else {
        return false;
    };
    let mut words = rest.split(' ');
    if !words.next().is_some_and(|tool| TOOLS.contains(&tool)) {
        return false;
    }
    let digits = |s: &str| !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit());
    let mut seconds = 0;
    let mut words = words.peekable();
    while let Some(word) = words.peek() {
        match word.strip_suffix('s') {
            Some(n) if digits(n) => {
                seconds += 1;
                words.next();
            }
            _ => break,
        }
    }
    if seconds == 0 {
        return false;
    }
    match (words.next(), words.next(), words.next()) {
        (None, _, _) => true,
        (Some("pages"), Some(n), None) => digits(n),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_only_exact_timing_lines() {
        let output = b"running 1 test\n\
mcp_answers_across_verticals timing alert_context 3s\n\
mcp_answers_across_verticals timing detection_coverage 9s 8s pages 5\n\
mcp_answers_across_verticals timing rule_health 2s\n\
test mcp_answers_across_verticals ... ok\n";
        assert_eq!(
            public_timing_lines(output),
            [
                "mcp_answers_across_verticals timing alert_context 3s",
                "mcp_answers_across_verticals timing detection_coverage 9s 8s pages 5",
                "mcp_answers_across_verticals timing rule_health 2s",
            ]
        );
    }

    #[test]
    fn refuses_anything_that_could_carry_other_text() {
        for line in [
            "mcp_answers_across_verticals timing alert_context",
            "mcp_answers_across_verticals timing other_tool 3s",
            "mcp_answers_across_verticals timing alert_context 3s host.example",
            "mcp_answers_across_verticals timing alert_context 3.5s",
            "mcp_answers_across_verticals timing alert_context -3s",
            "mcp_answers_across_verticals timing alert_context 3s pages",
            "mcp_answers_across_verticals timing alert_context 3s pages 5 x",
            "mcp_answers_across_verticals timing alert_context 1234567s",
            " mcp_answers_across_verticals timing alert_context 3s",
            "mcp_answers_across_verticals timing alert_context  3s",
            "other_contract timing alert_context 3s",
        ] {
            assert!(!is_public_timing(line), "{line}");
        }
    }
}
