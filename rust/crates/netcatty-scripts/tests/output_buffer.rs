//! Port of `electron/scripts/sessionOutputBuffer.test.cjs`.

use netcatty_scripts::buffer::OutputBuffer;
use netcatty_scripts::pattern::WaitPattern;
use netcatty_scripts::prompt_patterns::shell_prompt_patterns;
use std::time::Duration;
use tokio::task::JoinHandle;

fn t(s: &str) -> WaitPattern {
    WaitPattern::text(s)
}

fn re(source: &str, flags: &str) -> WaitPattern {
    WaitPattern::regex(source, flags)
}

fn x(n: usize) -> String {
    "x".repeat(n)
}

fn buf() -> OutputBuffer {
    OutputBuffer::new("s1")
}

/// Spawn a wait and assert it has not resolved after 30 ms
/// (`resolvedEarly === false`).
async fn pending<T: Send + 'static>(
    future: netcatty_scripts::buffer::WaitFuture<T>,
) -> JoinHandle<Result<T, netcatty_scripts::WaitError>> {
    let handle = tokio::spawn(future);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!handle.is_finished(), "wait resolved early");
    handle
}

async fn done<T>(handle: JoinHandle<Result<T, netcatty_scripts::WaitError>>) -> T {
    handle.await.unwrap().unwrap()
}

fn prompts_with(first: &str) -> Vec<WaitPattern> {
    let mut patterns = vec![t(first)];
    patterns.extend(shell_prompt_patterns());
    patterns
}

#[tokio::test]
async fn wait_for_resolves_on_appended_data() {
    let b = buf();
    let p = tokio::spawn(b.wait_for(&t("$ "), 1000, None));
    b.append("user@host:$ ");
    assert_eq!(done(p).await, "$ ");
}

#[tokio::test]
async fn wait_for_resolves_root_shell_prompt() {
    let b = buf();
    let p = tokio::spawn(b.wait_for(&t("# "), 1000, None));
    b.append("Welcome to Ubuntu\nroot@VM-4-16-ubuntu:~# ");
    assert_eq!(done(p).await, "# ");
}

#[tokio::test]
async fn wait_for_regex_resolves_regex_source_strings_across_line_breaks() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_regex(&t(".*SSH资源.*登录方式.*"), 1000, None));
    b.append("1. SSH资源\n请选择SSH资源\n'zxadmin'登录方式:");
    assert_eq!(
        done(p).await,
        "1. SSH资源\n请选择SSH资源\n'zxadmin'登录方式:"
    );
}

#[tokio::test]
async fn wait_for_treats_wildcard_looking_strings_as_literal_text() {
    let b = buf();
    let f = b.wait_for(&t(".*SSH资源.*登录方式.*"), 200, None);
    b.append("1. SSH资源\n请选择SSH资源\n'zxadmin'登录方式:");
    let p = pending(f).await;
    b.append("\n.*SSH资源.*登录方式.*");
    assert_eq!(done(p).await, ".*SSH资源.*登录方式.*");
}

#[tokio::test]
async fn wait_for_preserves_slash_regex_dot_behavior() {
    let b = buf();
    let f = b.wait_for(&t("/BEGIN.*END/"), 200, None);
    b.append("BEGIN\nEND");
    let p = pending(f).await;
    b.append("\nBEGIN END");
    assert_eq!(done(p).await, "BEGIN END");
}

#[tokio::test]
async fn wait_for_handles_invalid_regex_looking_strings_literally() {
    let b = buf();
    let p = tokio::spawn(b.wait_for(&t("literal .* [broken"), 1000, None));
    b.append("literal .* [broken");
    assert_eq!(done(p).await, "literal .* [broken");
}

#[tokio::test]
async fn wait_for_regex_resolves_simple_source_strings_immediately() {
    let b = buf();
    b.append("READY");
    assert_eq!(
        b.wait_for_regex(&t("READY"), 1000, None).await.unwrap(),
        "READY"
    );
}

#[tokio::test]
async fn wait_for_regex_resolves_simple_source_strings_after_append() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_regex(&t("READY"), 1000, None));
    b.append("READY");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn wait_for_text_keeps_strings_literal() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_text(&t("资源'[Empty]'账户:"), 1000, None));
    b.append("资源'[Empty]'账户:");
    assert_eq!(done(p).await, "资源'[Empty]'账户:");
}

#[tokio::test]
async fn wait_for_text_treats_wildcard_looking_strings_as_literal_text() {
    let b = buf();
    let f = b.wait_for_text(&t("literal .* prompt"), 200, None);
    b.append("literal abc prompt");
    let p = pending(f).await;
    b.append("\nliteral .* prompt");
    assert_eq!(done(p).await, "literal .* prompt");
}

#[tokio::test]
async fn wait_for_regex_does_not_treat_stale_edge_wildcard_matches_as_fresh() {
    let b = buf();
    b.append(&format!("SSH资源{}", x(600)));
    let p = pending(b.wait_for_regex(&t(".*SSH资源.*"), 200, None)).await;
    b.append("\nSSH资源");
    assert_eq!(done(p).await, "\nSSH资源");
}

#[tokio::test]
async fn wait_for_regex_preserves_the_full_regex_match_value() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_regex(&t("Version: .*"), 1000, None));
    b.append("Version: 1.2.3 ready");
    assert_eq!(done(p).await, "Version: 1.2.3 ready");
}

#[tokio::test]
async fn wait_for_regex_applies_stale_protection_to_regexp_objects() {
    let b = buf();
    b.append(&format!("SSH资源{}", x(600)));
    let p = pending(b.wait_for_regex(&re(".*SSH资源.*", "s"), 200, None)).await;
    b.append("\nSSH资源");
    assert_eq!(done(p).await, "\nSSH资源");
}

#[tokio::test]
async fn wait_for_regex_handles_lazy_edge_wildcards() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_regex(&re(".*?READY.*?", "s"), 1000, None));
    b.append("READY");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn wait_for_regex_applies_stale_protection_to_anchored_edge_wildcards() {
    let b = buf();
    b.append(&format!("READY{}", x(600)));
    let p = pending(b.wait_for_regex(&re("^.*READY.*$", "s"), 200, None)).await;
    b.append("\nREADY");
    assert_eq!(done(p).await, "\nREADY");
}

#[tokio::test]
async fn wait_for_regex_applies_stale_protection_to_edge_plus_wildcards() {
    let b = buf();
    b.append(&format!("xREADYy{}", x(600)));
    let p = pending(b.wait_for_regex(&re(".+READY.+", "s"), 200, None)).await;
    b.append("\nxREADYy");
    assert_eq!(done(p).await, "\nxREADYy");
}

#[tokio::test]
async fn wait_for_regex_accepts_fresh_core_matches_later_in_a_full_regex_result() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_regex(&t(".*READY.*"), 1000, None));
    let text = format!("READY{}READY", x(600));
    b.append(&text);
    assert_eq!(done(p).await, text);
}

#[tokio::test]
async fn wait_for_regex_does_not_combine_stale_prefix_with_fresh_suffix() {
    let b = buf();
    b.append(&format!("SSH资源{}", x(600)));
    let f = b.wait_for_regex(&t(".*SSH资源.*登录方式.*"), 1000, None);
    b.append("\n登录方式:");
    let p = pending(f).await;
    b.append("\nSSH资源\n登录方式:");
    assert_eq!(done(p).await, "\nSSH资源\n登录方式:");
}

#[tokio::test]
async fn wait_for_regex_finds_fresh_match_after_rejected_stale_overlap() {
    let b = buf();
    b.append(&format!("SSH资源{}", x(600)));
    let p = tokio::spawn(b.wait_for_regex(&t(".*SSH资源.*登录方式.*"), 1000, None));
    b.append("\n登录方式:\nSSH资源\n登录方式:");
    assert_eq!(done(p).await, "\nSSH资源\n登录方式:");
}

#[tokio::test]
async fn wait_for_regex_rejects_preexisting_stale_prefix_with_tail_suffix() {
    let b = buf();
    b.append(&format!("SSH资源{}登录方式:", x(600)));
    let p = pending(b.wait_for_regex(&t(".*SSH资源.*登录方式.*"), 1000, None)).await;
    b.append("\nSSH资源\n登录方式:");
    assert_eq!(done(p).await, "\nSSH资源\n登录方式:");
}

#[tokio::test]
async fn wait_for_regex_does_not_loop_forever_on_stale_zero_length_matches() {
    let b = buf();
    b.append(&format!("READY{}", x(600)));
    let err = b
        .wait_for_regex(&re("(?=READY)", ""), 50, None)
        .await
        .unwrap_err();
    assert!(err.message().contains("waitForRegex timed out"), "{err}");
}

#[tokio::test]
async fn wait_for_any_matches_shell_prompt_patterns() {
    let b = buf();
    let patterns = vec![
        t("# "),
        t("$ "),
        re(
            netcatty_scripts::prompt_patterns::SHELL_PROMPT_END_REGEX,
            "m",
        ),
    ];
    let p = tokio::spawn(b.wait_for_any(&patterns, 1000, None, false));
    b.append("root@VM-4-16-ubuntu:~# ");
    assert_eq!(done(p).await, 0);
}

#[tokio::test]
async fn wait_for_ignores_stale_scrollback_not_near_buffer_tail() {
    let b = buf();
    b.append(&format!(
        "{}Do you want to reset password? {}",
        x(600),
        x(600)
    ));
    let p = pending(b.wait_for(&re("Do you want to reset password", ""), 200, None)).await;
    b.append("Do you want to reset password? ");
    assert_eq!(done(p).await, "Do you want to reset password");
}

#[tokio::test]
async fn wait_for_resolves_prompt_already_at_buffer_tail() {
    let b = buf();
    b.append("root@host:~# ");
    assert_eq!(b.wait_for(&t("# "), 1000, None).await.unwrap(), "# ");
}

#[tokio::test]
async fn wait_for_ignores_stale_prompt_before_cursor() {
    let b = buf();
    b.append("user@host:~$ ");
    assert_eq!(b.wait_for(&t("$ "), 1000, None).await.unwrap(), "$ ");
    let p = pending(b.wait_for(&t("$ "), 1000, None)).await;
    b.append("ls output\nuser@host:~$ ");
    assert_eq!(done(p).await, "$ ");
}

#[tokio::test]
async fn mark_current_output_consumed_prevents_startup_text_from_matching() {
    let b = buf();
    b.append("previous deploy READY\nuser@host:~$ ");
    b.mark_current_output_consumed(&shell_prompt_patterns());
    let p = pending(b.wait_for(&t("READY"), 200, None)).await;
    b.append("fresh READY\n");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn mark_current_output_consumed_preserves_the_startup_prompt_once() {
    let b = buf();
    b.append("root@host:~# ");
    b.mark_current_output_consumed(&shell_prompt_patterns());
    assert_eq!(
        b.wait_for_any(&shell_prompt_patterns(), 1000, None, true)
            .await
            .unwrap(),
        0
    );
    let p = pending(b.wait_for_any(&shell_prompt_patterns(), 200, None, false)).await;
    b.append("root@host:~# ");
    assert_eq!(done(p).await, 0);
}

#[tokio::test]
async fn normal_wait_for_any_does_not_consume_preserved_startup_prompts() {
    let b = buf();
    b.append("previous deploy READY\nuser@host:~$ ");
    b.mark_current_output_consumed(&shell_prompt_patterns());
    let p = pending(b.wait_for_any(&prompts_with("READY"), 200, None, false)).await;
    b.append("READY\n");
    assert_eq!(done(p).await, 0);
}

#[tokio::test]
async fn preserved_prompt_can_be_consumed_explicitly_for_wait_for_prompt() {
    let b = buf();
    b.append("previous deploy READY\nuser@host:~$ ");
    b.mark_current_output_consumed(&shell_prompt_patterns());
    assert_eq!(
        b.wait_for_any(&prompts_with("READY"), 1000, None, true)
            .await
            .unwrap(),
        2
    );
}

fn menu(entries: usize) -> String {
    (0..entries)
        .map(|i| format!("  [{i}] menu entry line"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn wait_for_slash_regex_matches_output_followed_by_long_multi_line_burst() {
    let b = buf();
    let p = tokio::spawn(b.wait_for(&t("/SSH资源\\(/"), 1000, None));
    b.append(&format!(
        "user login success\n\nSSH资源(5) :\n{}\n\n> ",
        menu(15)
    ));
    assert_eq!(done(p).await, "SSH资源(");
}

#[tokio::test]
async fn wait_for_text_matches_literal_text_followed_by_long_multi_line_burst() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_text(&t("SSH资源("), 1000, None));
    b.append(&format!("SSH资源(5) :\n{}", x(600)));
    assert_eq!(done(p).await, "SSH资源(");
}

#[tokio::test]
async fn wait_for_regex_matches_core_followed_by_long_multi_line_burst() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_regex(&t(".*SSH资源\\(.*"), 1000, None));
    let burst = format!("SSH资源(5) :\n{}", x(600));
    b.append(&burst);
    assert_eq!(done(p).await, burst);
}

#[tokio::test]
async fn wait_for_any_matches_pattern_followed_by_long_multi_line_burst() {
    let b = buf();
    let p = tokio::spawn(b.wait_for_any(&[t("账户:"), t("密码:")], 1000, None, false));
    b.append(&format!("资源'[Empty]'账户:\n{}", x(600)));
    assert_eq!(done(p).await, 0);
}

#[tokio::test]
async fn waits_survive_buffer_trimming_while_waiting() {
    for kind in ["text", "regex", "any"] {
        let b = OutputBuffer::with_capacity("s1", 1024);
        b.append(&x(1000));
        let target = t("TARGET");
        let handle = match kind {
            "text" => tokio::spawn(b.wait_for_text(&target, 1000, None)),
            "regex" => tokio::spawn(b.wait_for_regex(&target, 1000, None)),
            _ => {
                let any = b.wait_for_any(std::slice::from_ref(&target), 1000, None, false);
                tokio::spawn(async move { any.await.map(|i| i.to_string()) })
            }
        };
        b.append(&format!("{}TARGET{}", "y".repeat(100), "z".repeat(500)));
        let expected = if kind == "any" { "0" } else { "TARGET" };
        assert_eq!(done(handle).await, expected, "{kind}");
    }
}

#[tokio::test]
async fn wait_for_still_rejects_pre_registration_scrollback_beyond_tail_slack() {
    let b = buf();
    b.append(&format!("TARGET{}", x(600)));
    let p = pending(b.wait_for(&t("TARGET"), 200, None)).await;
    b.append("\nTARGET");
    assert_eq!(done(p).await, "TARGET");
}

#[tokio::test]
async fn replace_with_visible_screen_makes_the_whole_viewport_waitable() {
    let b = buf();
    let body = (0..40)
        .map(|i| format!("  [{i}] host-{i} {}", x(20)))
        .collect::<Vec<_>>()
        .join("\n");
    let screen = format!("Welcome\n\nSSH资源(5) :\n{body}\n");
    assert!(screen.len() > 512);
    b.replace_with_visible_screen(&screen, "", "");
    assert_eq!(
        b.wait_for_regex(&t("SSH资源\\s*\\(\\d+\\)\\s*:"), 200, None)
            .await
            .unwrap(),
        "SSH资源(5) :"
    );
}

#[tokio::test]
async fn replace_with_visible_screen_keeps_trailing_fresh_output_from_sync_race() {
    let b = buf();
    b.replace_with_visible_screen(&format!("SSH资源(5) :\n{}\n", x(600)), "\x07\x07", "");
    assert_eq!(
        b.wait_for_regex(&t("SSH资源\\s*\\(\\d+\\)\\s*:"), 200, None)
            .await
            .unwrap(),
        "SSH资源(5) :"
    );
    assert!(b.text().ends_with("\x07\x07"));
}

#[tokio::test]
async fn seeded_viewport_does_not_make_mid_screen_prompts_waitable_via_wait_for_prompt() {
    let b = buf();
    let mut lines = vec![
        "user@host:~$ ".to_string(),
        "running long job...".to_string(),
    ];
    lines.extend((0..30).map(|i| format!("output line {i} {}", x(20))));
    let screen = lines.join("\n");
    assert!(screen.len() > 512);
    b.replace_with_visible_screen(&screen, "", "");
    let p = pending(b.wait_for_any(&shell_prompt_patterns(), 200, None, true)).await;
    b.append("\nuser@host:~$ ");
    assert_eq!(done(p).await, 1);
}

#[tokio::test]
async fn seeded_viewport_keeps_generic_wait_for_any_matches_outside_the_live_tail() {
    let b = buf();
    let body = (0..40)
        .map(|i| format!("filler {i} {}", x(20)))
        .collect::<Vec<_>>()
        .join("\n");
    let screen = format!("Option A\nOption B\n{body}\n");
    assert!(screen.len() > 512);
    b.replace_with_visible_screen(&screen, "", "");
    assert_eq!(
        b.wait_for_any(&[t("Option A"), t("Option B")], 200, None, false)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn seeded_viewport_still_preserves_a_live_tail_prompt_for_wait_for_prompt() {
    let b = buf();
    b.replace_with_visible_screen(&format!("menu header\n{}\nroot@host:~# ", x(600)), "", "");
    assert_eq!(
        b.wait_for_any(&shell_prompt_patterns(), 1000, None, true)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn consuming_startup_prompt_also_consumes_seeded_viewport_above_it() {
    let b = buf();
    b.replace_with_visible_screen(
        &format!("old READY marker\n{}\nuser@host:~$ ", x(80)),
        "",
        "",
    );
    assert_eq!(
        b.wait_for_any(&shell_prompt_patterns(), 1000, None, true)
            .await
            .unwrap(),
        1
    );
    let p = pending(b.wait_for_text(&t("READY"), 200, None)).await;
    b.append("\nfresh READY\n");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn consuming_startup_prompt_also_consumes_seeded_text_after_the_prompt() {
    let b = buf();
    b.replace_with_visible_screen("root@host:~# \nold READY\n", "", "");
    assert_eq!(
        b.wait_for_any(&shell_prompt_patterns(), 1000, None, true)
            .await
            .unwrap(),
        0
    );
    let p = pending(b.wait_for_text(&t("READY"), 200, None)).await;
    b.append("fresh READY\n");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn wait_for_prompt_does_not_consume_sync_race_trailing_fresh() {
    let b = buf();
    b.replace_with_visible_screen("root@host:~# ", "\nfresh READY\n", "");
    assert_eq!(
        b.wait_for_any(&shell_prompt_patterns(), 1000, None, true)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
}

#[tokio::test]
async fn does_not_duplicate_trailing_fresh_already_in_blank_padded_viewport() {
    let b = buf();
    b.replace_with_visible_screen("READY\n\n\n", "READY\n", "");
    assert_eq!(b.text(), "READY\n\n\n");
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
    let p = pending(b.wait_for_text(&t("READY"), 200, None)).await;
    b.append("\nfresh READY\n");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn trims_partial_overlap_from_sync_race_trailing_fresh() {
    let b = buf();
    b.replace_with_visible_screen("READY\n", "READY\nNEXT\n", "");
    assert_eq!(b.text(), "READY\nNEXT\n");
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
    assert_eq!(
        b.wait_for_text(&t("NEXT"), 200, None).await.unwrap(),
        "NEXT"
    );
    let p = pending(b.wait_for_text(&t("READY"), 200, None)).await;
    b.append("\nfresh READY\n");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn trims_blank_padded_partial_overlap_from_trailing_fresh() {
    let b = buf();
    b.replace_with_visible_screen("READY\n\n", "READY\nNEXT\n", "");
    assert_eq!(b.text(), "READY\n\nNEXT\n");
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
    assert_eq!(
        b.wait_for_text(&t("NEXT"), 200, None).await.unwrap(),
        "NEXT"
    );
    let p = pending(b.wait_for_text(&t("READY"), 200, None)).await;
    b.append("\nfresh READY\n");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn keeps_duplicate_trailing_fresh_when_snapshot_is_still_pre_sync() {
    let b = buf();
    b.replace_with_visible_screen("READY\n", "READY\n", "READY\n");
    assert_eq!(b.text(), "READY\nREADY\n");
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
}

#[tokio::test]
async fn keeps_duplicate_trailing_fresh_when_stale_viewport_is_a_sync_start_suffix() {
    let b = buf();
    b.replace_with_visible_screen("READY\n", "READY\nNEXT\n", "banner\nREADY\n");
    assert_eq!(b.text(), "READY\nREADY\nNEXT\n");
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
    assert_eq!(
        b.wait_for_text(&t("NEXT"), 200, None).await.unwrap(),
        "NEXT"
    );
}

#[tokio::test]
async fn invalidate_startup_seed_blocks_seeded_waits_after_input() {
    let b = buf();
    b.replace_with_visible_screen("root@host:~# \nold READY\n", "", "");
    b.invalidate_startup_seed();
    let prompt = tokio::spawn(b.wait_for_any(&shell_prompt_patterns(), 200, None, true));
    let text = tokio::spawn(b.wait_for_text(&t("READY"), 200, None));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!prompt.is_finished());
    assert!(!text.is_finished());
    b.append("command output\nroot@host:~# ");
    assert_eq!(done(prompt).await, 0);
    b.append("\nfresh READY\n");
    assert_eq!(done(text).await, "READY");
}

#[tokio::test]
async fn invalidate_startup_seed_also_consumes_pre_input_trailing_fresh() {
    let b = buf();
    b.replace_with_visible_screen("root@host:~# ", "\nfresh READY\n", "");
    b.invalidate_startup_seed();
    let p = pending(b.wait_for_text(&t("READY"), 200, None)).await;
    b.append("\npost-command READY\n");
    assert_eq!(done(p).await, "READY");
}

#[tokio::test]
async fn wait_for_prompt_keeps_long_sync_race_trailing_fresh_matchable() {
    let b = buf();
    b.replace_with_visible_screen("root@host:~# ", &format!("\nREADY\n{}", x(600)), "");
    assert_eq!(
        b.wait_for_any(&shell_prompt_patterns(), 1000, None, true)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
}

#[tokio::test]
async fn wait_for_prompt_does_not_rematch_short_seeded_prompt_after_live_output() {
    let b = buf();
    b.replace_with_visible_screen("root@host:~# ", "", "");
    b.append("echo hi\nhi\n");
    let p = pending(b.wait_for_any(&shell_prompt_patterns(), 200, None, true)).await;
    b.append("root@host:~# ");
    assert_eq!(done(p).await, 0);
}

#[tokio::test]
async fn wait_for_prompt_ignores_preserved_prompt_after_newer_output_is_consumed() {
    let b = buf();
    b.replace_with_visible_screen("root@host:~# ", "\nfresh READY\n", "");
    assert_eq!(
        b.wait_for_text(&t("READY"), 200, None).await.unwrap(),
        "READY"
    );
    assert!(b.scan_offset() > 0);
    let p = pending(b.wait_for_any(&shell_prompt_patterns(), 200, None, true)).await;
    b.append("root@host:~# ");
    assert_eq!(done(p).await, 0);
}

#[tokio::test]
async fn timeouts_aborts_and_disposal_reject_with_electron_messages() {
    let b = buf();
    let err = b.wait_for(&t("never"), 30, None).await.unwrap_err();
    assert_eq!(err.message(), "waitFor timed out after 30ms");
    let err = b.wait_for_text(&t("never"), 30, None).await.unwrap_err();
    assert_eq!(err.message(), "waitForText timed out after 30ms");
    let err = b
        .wait_for_any(&[t("never")], 30, None, false)
        .await
        .unwrap_err();
    assert_eq!(err.message(), "waitForAny timed out after 30ms");

    let handle = tokio::spawn(b.wait_for(&t("never"), 5_000, None));
    tokio::time::sleep(Duration::from_millis(20)).await;
    b.abort_waiters("Stopped by user");
    assert_eq!(
        handle.await.unwrap().unwrap_err().message(),
        "Stopped by user"
    );

    let handle = tokio::spawn(b.wait_for(&t("never"), 5_000, Some(std::sync::Arc::new(|| true))));
    assert_eq!(
        handle.await.unwrap().unwrap_err().message(),
        "Script stopped"
    );

    let handle = tokio::spawn(b.wait_for(&t("never"), 5_000, None));
    tokio::time::sleep(Duration::from_millis(20)).await;
    b.dispose();
    assert_eq!(
        handle.await.unwrap().unwrap_err().message(),
        "Session output buffer disposed"
    );
    assert_eq!(b.waiter_count(), 0);

    let err = b.wait_for_any(&[], 30, None, false).await.unwrap_err();
    assert_eq!(
        err.message(),
        "waitForAny requires a non-empty patterns array"
    );
}
