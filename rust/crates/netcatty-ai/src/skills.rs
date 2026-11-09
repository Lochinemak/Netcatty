//! User-managed skills (Electron: `electron/bridges/ai/userSkills.cjs`).
//!
//! `<data dir>/Skills/<Skill Name>/SKILL.md` with a small YAML front matter
//! (`name`, `description`). The scan reports every folder with warnings;
//! ready skills can be injected into a prompt, either explicitly selected
//! (`/slug`) or matched against the prompt text, within a fixed budget.
//! Lengths are counted in characters (Electron: UTF-16 code units; identical
//! for the BMP text these limits are tuned for).

use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const USER_SKILLS_DIR_NAME: &str = "Skills";
pub const USER_SKILLS_README_NAME: &str = "README.txt";
const MAX_SKILL_BYTES: u64 = 24 * 1024;
const MAX_DESCRIPTION_LENGTH: usize = 500;
const MAX_INDEX_SKILLS: usize = 8;
const MAX_INDEX_DESCRIPTION_CHARS: usize = 160;
const MAX_INDEX_LINE_CHARS: usize = 1400;
const MAX_EXPLICIT_SKILLS: usize = 4;
const MAX_MATCHED_SKILLS: usize = 2;
const MAX_MATCHED_SKILL_CHARS: usize = 6000;
const MAX_TOTAL_INJECTED_SKILL_CHARS: usize = 12000;

pub const USER_SKILLS_README_CONTENT: &str = "Netcatty user skills

Add one folder per skill inside this directory.
Each skill folder must contain a SKILL.md file.

Example layout:
  Skills/
    My Skill/
      SKILL.md

Minimal SKILL.md:
  ---
  name: My Skill
  description: Short summary of what this skill helps with.
  ---

  Write the skill instructions here.

After adding or editing a skill, reopen the AI settings page or start a new chat to refresh the list.
";

const STOPWORDS: &[&str] = &[
    "the", "and", "for", "with", "that", "this", "from", "into", "when", "then", "only", "your", "will", "should",
    "have", "has", "had", "using", "use", "agent", "skill", "skills", "task", "file", "files", "user", "about",
];

static FRONTMATTER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n)?").unwrap());
static NON_SLUG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// One skill folder as the renderer sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSkill {
    pub id: String,
    pub slug: String,
    pub directory_name: String,
    pub directory_path: String,
    pub skill_path: String,
    pub name: String,
    pub description: String,
    /// `"ready"` or `"warning"`.
    pub status: String,
    pub warnings: Vec<String>,
}

/// Public scan result (`toPublicUserSkillsStatus`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSkillsStatus {
    pub directory_path: String,
    pub ready_count: usize,
    pub warning_count: usize,
    pub skills: Vec<UserSkill>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ReadySkill {
    slug: String,
    name: String,
    directory_name: String,
    description: String,
    body: String,
}

/// Full scan: public status plus the ready skills' bodies.
#[derive(Debug, Clone)]
pub struct SkillsScan {
    pub status: UserSkillsStatus,
    ready: Vec<ReadySkill>,
}

fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    let quoted = trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"')) || (trimmed.starts_with('\'') && trimmed.ends_with('\'')));
    if quoted {
        trimmed[1..trimmed.len() - 1].to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Lowercase ASCII slug (`My Skill` → `my-skill`); non-ASCII-only names give `""`.
pub fn slugify_skill(value: &str) -> String {
    let lower = value.trim().to_lowercase();
    NON_SLUG.replace_all(&lower, "-").trim_matches('-').to_owned()
}

fn tokenize(value: &str) -> Vec<String> {
    value
        .to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 3 && !STOPWORDS.contains(t))
        .map(str::to_owned)
        .collect()
}

fn truncate_inline_text(value: &str, max_chars: usize) -> String {
    let normalized = WHITESPACE.replace_all(value, " ").trim().to_owned();
    if normalized.chars().count() <= max_chars {
        return normalized;
    }
    let head: String = normalized.chars().take(max_chars.saturating_sub(3)).collect();
    format!("{}...", head.trim_end())
}

fn contains_plaintext_phrase(prompt: &str, phrase: &str) -> bool {
    let phrase = phrase.trim();
    if phrase.is_empty() {
        return false;
    }
    // `(^|\s)<phrase>(?=$|\s|[.,!?;:])`, case-insensitive.
    let pattern = format!(r"(?i)(?:^|\s){}(?:$|[\s.,!?;:])", regex::escape(phrase));
    Regex::new(&pattern).is_ok_and(|re| re.is_match(prompt))
}

struct Frontmatter {
    attributes: HashMap<String, String>,
    body: String,
    has_frontmatter: bool,
}

fn parse_frontmatter(content: &str) -> Frontmatter {
    let Some(captures) = FRONTMATTER.captures(content) else {
        return Frontmatter { attributes: HashMap::new(), body: content.to_owned(), has_frontmatter: false };
    };
    let mut attributes = HashMap::new();
    for raw_line in captures[1].split('\n') {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(colon) = line.find(':') else { continue };
        if colon == 0 {
            continue;
        }
        let key = line[..colon].trim();
        if !key.is_empty() {
            attributes.insert(key.to_owned(), strip_quotes(line[colon + 1..].trim()));
        }
    }
    let whole = captures.get(0).map(|m| m.end()).unwrap_or(0);
    Frontmatter { attributes, body: content[whole..].to_owned(), has_frontmatter: true }
}

fn summarize_skill_slugs(slugs: &[String], max_items: usize) -> String {
    let values: Vec<String> = slugs.iter().filter(|s| !s.is_empty()).map(|s| format!("/{s}")).collect();
    if values.len() <= max_items {
        return values.join(", ");
    }
    format!("{}, and {} more", values[..max_items].join(", "), values.len() - max_items)
}

/// `<data dir>/Skills`.
pub fn user_skills_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(USER_SKILLS_DIR_NAME)
}

/// Create the folder and, when it is empty, the instructions file.
pub fn ensure_user_skills_readme(data_dir: &Path) -> std::io::Result<PathBuf> {
    let dir = user_skills_dir(data_dir);
    std::fs::create_dir_all(&dir)?;
    if std::fs::read_dir(&dir)?.next().is_none() {
        std::fs::write(dir.join(USER_SKILLS_README_NAME), USER_SKILLS_README_CONTENT)?;
    }
    Ok(dir)
}

fn format_read_warning(error: &std::io::Error) -> String {
    let code = match error.kind() {
        std::io::ErrorKind::PermissionDenied => Some("EACCES"),
        std::io::ErrorKind::NotFound => Some("ENOENT"),
        _ => None,
    };
    match code {
        Some(code) => format!("Failed to read SKILL.md ({code}: {error})."),
        None => format!("Failed to read SKILL.md ({error})."),
    }
}

/// Scan the skills folder (creating it on first use).
pub fn scan_user_skills(data_dir: &Path) -> std::io::Result<SkillsScan> {
    let skills_dir = ensure_user_skills_readme(data_dir)?;
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(&skills_dir)?.filter_map(Result::ok).collect();
    entries.sort_by_key(|e| e.file_name());
    let mut skills: Vec<(UserSkill, Option<String>)> = Vec::new();
    let mut warnings = Vec::new();

    for entry in entries {
        // Only real directories; symlinks are skipped for security.
        let Ok(file_type) = entry.file_type() else { continue };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        if dir_name.contains('/') || dir_name.contains('\\') || dir_name == ".." || dir_name == "." {
            continue;
        }
        let skill_dir = skills_dir.join(&dir_name);
        let skill_path = skill_dir.join("SKILL.md");
        let mut item = UserSkill {
            id: dir_name.clone(),
            slug: slugify_skill(&dir_name),
            directory_name: dir_name.clone(),
            directory_path: skill_dir.to_string_lossy().into_owned(),
            skill_path: skill_path.to_string_lossy().into_owned(),
            name: dir_name.clone(),
            description: String::new(),
            status: "warning".into(),
            warnings: Vec::new(),
        };
        let warn = |item: &mut UserSkill, warnings: &mut Vec<String>, text: String, summary: Option<&str>| {
            warnings.push(format!("{dir_name}: {}", summary.unwrap_or(&text)));
            item.warnings.push(text);
        };

        // `fs.access` follows symlinks: a dangling link counts as missing.
        if std::fs::metadata(&skill_path).is_err() {
            warn(&mut item, &mut warnings, "Missing SKILL.md".into(), None);
            skills.push((item, None));
            continue;
        }
        let meta = match std::fs::symlink_metadata(&skill_path) {
            Ok(meta) => meta,
            Err(err) => {
                warn(&mut item, &mut warnings, format_read_warning(&err), None);
                skills.push((item, None));
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            warn(&mut item, &mut warnings, "SKILL.md must not be a symbolic link.".into(), None);
            skills.push((item, None));
            continue;
        }
        if !meta.is_file() {
            warn(&mut item, &mut warnings, "SKILL.md must be a regular file.".into(), None);
            skills.push((item, None));
            continue;
        }
        if meta.len() > MAX_SKILL_BYTES {
            warn(
                &mut item,
                &mut warnings,
                format!("SKILL.md is too large ({} bytes > {MAX_SKILL_BYTES} bytes).", meta.len()),
                Some("SKILL.md is too large."),
            );
            skills.push((item, None));
            continue;
        }
        let content = match std::fs::read(&skill_path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(err) => {
                warn(&mut item, &mut warnings, format_read_warning(&err), None);
                skills.push((item, None));
                continue;
            }
        };
        let fm = parse_frontmatter(&content);
        let name = strip_quotes(fm.attributes.get("name").map(String::as_str).unwrap_or("")).trim().to_owned();
        let description = strip_quotes(fm.attributes.get("description").map(String::as_str).unwrap_or("")).trim().to_owned();
        let usable_slug = slugify_skill(if name.is_empty() { &dir_name } else { &name });
        let mut local = Vec::new();
        if !fm.has_frontmatter {
            local.push("Missing YAML frontmatter.".to_owned());
        }
        if name.is_empty() {
            local.push("Missing frontmatter field: name.".to_owned());
        }
        let description_len = description.chars().count();
        if description.is_empty() {
            local.push("Missing frontmatter field: description.".to_owned());
        } else if description_len > MAX_DESCRIPTION_LENGTH {
            local.push(format!("Description is too long ({description_len} chars > {MAX_DESCRIPTION_LENGTH})."));
        }
        if usable_slug.is_empty() {
            local.push("Skill name must include ASCII letters or digits to generate a usable slug.".to_owned());
        }
        item.slug = usable_slug;
        item.description = description;
        if !local.is_empty() {
            warnings.extend(local.iter().map(|w| format!("{dir_name}: {w}")));
            item.warnings = local;
            if !name.is_empty() {
                item.name = name;
            }
            skills.push((item, None));
            continue;
        }
        item.name = name;
        item.status = "ready".into();
        skills.push((item, Some(fm.body)));
    }

    // Duplicate normalized slugs are downgraded on every copy.
    let mut by_slug: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, (skill, _)) in skills.iter().enumerate() {
        if skill.status == "ready" && !skill.slug.is_empty() {
            by_slug.entry(skill.slug.clone()).or_default().push(index);
        }
    }
    let mut duplicate_slugs: Vec<(&String, &Vec<usize>)> = by_slug.iter().filter(|(_, v)| v.len() > 1).collect();
    duplicate_slugs.sort();
    for (slug, indices) in duplicate_slugs {
        let message = format!("Duplicate skill slug \"{slug}\". Rename the skill or change its frontmatter name.");
        for &index in indices {
            let skill = &mut skills[index].0;
            skill.status = "warning".into();
            skill.warnings.push(message.clone());
            warnings.push(format!("{}: {message}", skill.directory_name));
        }
    }

    let ready: Vec<ReadySkill> = skills
        .iter()
        .filter(|(s, _)| s.status == "ready")
        .map(|(s, body)| ReadySkill {
            slug: s.slug.clone(),
            name: s.name.clone(),
            directory_name: s.directory_name.clone(),
            description: s.description.clone(),
            body: body.clone().unwrap_or_default(),
        })
        .collect();
    let ready_count = ready.len();
    let warning_count = skills.iter().filter(|(s, _)| s.status == "warning").count();
    Ok(SkillsScan {
        status: UserSkillsStatus {
            directory_path: skills_dir.to_string_lossy().into_owned(),
            ready_count,
            warning_count,
            skills: skills.into_iter().map(|(s, _)| s).collect(),
            warnings,
        },
        ready,
    })
}

/// 50 for a plain-text name / folder mention, else the keyword overlap.
fn score_skill_match(prompt: &str, skill: &ReadySkill) -> usize {
    if contains_plaintext_phrase(prompt, &skill.name) || contains_plaintext_phrase(prompt, &skill.directory_name) {
        return 50;
    }
    let prompt_tokens: HashSet<String> = tokenize(prompt).into_iter().collect();
    tokenize(&format!("{} {}", skill.name, skill.description))
        .iter()
        .filter(|t| prompt_tokens.contains(*t))
        .count()
}

/// Build the prompt context for `prompt` with the explicitly selected slugs.
pub fn build_user_skills_context(scan: &SkillsScan, prompt: &str, selected_skill_slugs: &[String]) -> String {
    let ready = &scan.ready;
    let prompt = prompt.trim();
    if ready.is_empty() {
        return String::new();
    }

    let index_skills = &ready[..ready.len().min(MAX_INDEX_SKILLS)];
    let mut remaining_count = ready.len() - index_skills.len();
    let mut index_entries: Vec<String> = Vec::new();
    let mut index_chars = 0;
    for skill in index_skills {
        let entry = format!("{}: {}", skill.name, truncate_inline_text(&skill.description, MAX_INDEX_DESCRIPTION_CHARS));
        let separator = if index_entries.is_empty() { 0 } else { 2 };
        let entry_len = entry.chars().count();
        if index_chars + separator + entry_len > MAX_INDEX_LINE_CHARS {
            remaining_count += index_skills.len() - index_entries.len();
            break;
        }
        index_entries.push(entry);
        index_chars += separator + entry_len;
    }
    let index_line = index_entries.join("; ");

    let mut ordered_explicit: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for raw in selected_skill_slugs {
        let slug = slugify_skill(raw);
        if slug.is_empty() || !seen.insert(slug.clone()) {
            continue;
        }
        ordered_explicit.push(slug);
    }
    let additional_explicit = ordered_explicit.len().saturating_sub(MAX_EXPLICIT_SKILLS);
    let capped: Vec<String> = ordered_explicit.into_iter().take(MAX_EXPLICIT_SKILLS).collect();
    let capped_set: HashSet<&String> = capped.iter().collect();
    let by_slug: HashMap<&str, &ReadySkill> = ready.iter().map(|s| (s.slug.as_str(), s)).collect();
    let mut explicit: Vec<&ReadySkill> = Vec::new();
    let mut unavailable: Vec<String> = Vec::new();
    for slug in &capped {
        match by_slug.get(slug.as_str()) {
            Some(skill) => explicit.push(skill),
            None => unavailable.push(slug.clone()),
        }
    }

    let mut scored: Vec<(&ReadySkill, usize)> = ready
        .iter()
        .filter(|s| !capped_set.contains(&s.slug))
        .map(|s| (s, score_skill_match(prompt, s)))
        .filter(|(_, score)| *score >= 2)
        .collect();
    // Stable sort, highest score first (Array#sort is stable).
    scored.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    let matched: Vec<&ReadySkill> = scored.into_iter().take(MAX_MATCHED_SKILLS).map(|(s, _)| s).collect();
    let final_skills: Vec<&ReadySkill> = explicit.into_iter().chain(matched).collect();

    let mut parts = vec![
        "User-managed skills are installed in Netcatty.".to_owned(),
        format!(
            "Available user skills: {index_line}{}",
            if remaining_count > 0 { format!("; and {remaining_count} more.") } else { ".".to_owned() }
        ),
        "Use a user-managed skill only when it clearly matches the current request.".to_owned(),
    ];
    if additional_explicit > 0 {
        parts.push(format!(
            "The user selected {additional_explicit} additional Netcatty user skills that were omitted to stay within the prompt budget."
        ));
    }
    if !unavailable.is_empty() {
        parts.push(format!(
            "The user explicitly selected these Netcatty user skills for this request, but their content is currently unavailable: {}.",
            summarize_skill_slugs(&unavailable, 4)
        ));
    }

    if !final_skills.is_empty() {
        let mut sections: Vec<String> = Vec::new();
        let mut omitted: Vec<usize> = Vec::new();
        let mut truncated: Vec<usize> = Vec::new();
        let mut remaining_chars = MAX_TOTAL_INJECTED_SKILL_CHARS;
        let mut budget_stop = final_skills.len();
        for (index, skill) in final_skills.iter().enumerate() {
            let heading = format!("### {}\n", skill.name);
            let heading_len = heading.chars().count();
            let max_body = MAX_MATCHED_SKILL_CHARS.min(remaining_chars.saturating_sub(heading_len));
            if max_body == 0 {
                omitted.push(index);
                continue;
            }
            let raw_body = skill.body.trim();
            if raw_body.is_empty() {
                omitted.push(index);
                continue;
            }
            let raw_len = raw_body.chars().count();
            if raw_len > max_body && !sections.is_empty() {
                omitted.push(index);
                budget_stop = index;
                continue;
            }
            let body: String = raw_body.chars().take(max_body).collect();
            let body_len = body.chars().count();
            sections.push(format!("{heading}{body}"));
            remaining_chars -= heading_len + body_len;
            if body_len < raw_len {
                truncated.push(index);
                budget_stop = index + 1;
                break;
            }
        }
        parts.push("Matched user-managed skills for this request:".to_owned());
        parts.extend(sections);
        for index in budget_stop..final_skills.len() {
            if !omitted.contains(&index) && !truncated.contains(&index) {
                omitted.push(index);
            }
        }
        let slugs = |indices: &[usize]| indices.iter().map(|&i| final_skills[i].slug.clone()).collect::<Vec<_>>();
        if !truncated.is_empty() {
            parts.push(format!(
                "Some matched user-managed skill content was truncated to stay within the prompt budget: {}.",
                summarize_skill_slugs(&slugs(&truncated), 4)
            ));
        }
        if !omitted.is_empty() {
            parts.push(format!(
                "Additional matched user-managed skills were omitted to stay within the prompt budget: {}.",
                summarize_skill_slugs(&slugs(&omitted), 4)
            ));
        }
    }
    parts.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Def<'a> {
        dir: &'a str,
        name: &'a str,
        description: &'a str,
        body: String,
    }

    fn def<'a>(dir: &'a str, name: &'a str, description: &'a str, body: &str) -> Def<'a> {
        Def { dir, name, description, body: body.to_owned() }
    }

    fn with_skills(defs: &[Def<'_>]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let skills = root.path().join("Skills");
        std::fs::create_dir_all(&skills).unwrap();
        for d in defs {
            let dir = skills.join(d.dir);
            std::fs::create_dir_all(&dir).unwrap();
            let content = format!("---\nname: {}\ndescription: {}\n---\n\n{}\n", d.name, d.description, d.body);
            std::fs::write(dir.join("SKILL.md"), content).unwrap();
        }
        root
    }

    fn context(root: &Path, prompt: &str, slugs: &[&str]) -> String {
        let scan = scan_user_skills(root).unwrap();
        build_user_skills_context(&scan, prompt, &slugs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn does_not_auto_match_from_an_absolute_path_segment() {
        let root = with_skills(&[def("Tmp Helper", "tmp", "Helper for scratch space workflows.", "Body for tmp")]);
        let ctx = context(root.path(), "please inspect /tmp/netcatty.log", &[]);
        assert!(!ctx.contains("Matched user-managed skills for this request:"));
        assert!(!ctx.contains("Body for tmp"));
    }

    #[test]
    fn keeps_every_explicitly_selected_skill() {
        let root = with_skills(&[
            def("Alpha One", "Alpha One", "Alpha helper.", "Body for Alpha One"),
            def("Beta Two", "Beta Two", "Beta helper.", "Body for Beta Two"),
            def("Gamma Three", "Gamma Three", "Gamma helper.", "Body for Gamma Three"),
        ]);
        let ctx = context(root.path(), "plain prompt", &["alpha-one", "beta-two", "gamma-three"]);
        for body in ["Body for Alpha One", "Body for Beta Two", "Body for Gamma Three"] {
            assert!(ctx.contains(body), "{body}");
        }
    }

    #[test]
    fn long_descriptions_route_without_injecting_the_full_index_text() {
        let long = "Use when the user needs a detailed workflow for operating Netcatty through SDK skills and CLI. Includes platform launcher guidance, scoped command execution, recovery behavior, and constraints. This intentionally exceeds the older short description budget so routing has enough signal. It also names edge cases such as unavailable optional shells, strict chat-session scoping, and fallback-only history replay so the agent can choose the skill without reading the whole body first.";
        assert!(long.len() > 320);
        let root = with_skills(&[def("Detailed Router", "Detailed Router", long, "Detailed router body")]);
        let scan = scan_user_skills(root.path()).unwrap();
        assert_eq!(scan.status.ready_count, 1);
        assert_eq!(scan.status.warning_count, 0);
        let ctx = build_user_skills_context(&scan, "Need fallback-only history replay guidance for SDK recovery.", &[]);
        assert!(ctx.contains("### Detailed Router"));
        assert!(ctx.contains("Detailed router body"));
        assert!(!ctx.contains(long));
    }

    #[test]
    fn caps_the_available_skills_index() {
        let long = "signal ".repeat(65);
        let descriptions: Vec<String> = (1..=8).map(|i| format!("{long}{i}")).collect();
        let names: Vec<String> = (1..=8).map(|i| format!("Skill {i}")).collect();
        let defs: Vec<Def<'_>> = (0..8).map(|i| def(&names[i], &names[i], &descriptions[i], &format!("Body {}", i + 1))).collect();
        let root = with_skills(&defs);
        let ctx = context(root.path(), "plain prompt", &[]);
        let line = ctx.lines().find(|l| l.starts_with("Available user skills: ")).expect("index line");
        assert!(line.chars().count() < 1800, "{}", line.len());
    }

    #[test]
    fn preserves_an_unavailable_explicit_selection() {
        let root = with_skills(&[def("Beta", "Beta", "Beta helper.", "Body for Beta")]);
        let ctx = context(root.path(), "plain prompt", &["missing-skill"]);
        assert!(ctx.contains("Available user skills: Beta: Beta helper."));
        assert!(ctx.contains("/missing-skill"));
        assert!(ctx.contains("explicitly selected"));
        assert!(ctx.contains("unavailable"));
    }

    #[test]
    fn empty_directory_gets_only_an_instructions_file() {
        let root = with_skills(&[]);
        let scan = scan_user_skills(root.path()).unwrap();
        assert!(scan.status.skills.is_empty());
        assert_eq!(scan.status.ready_count, 0);
        let entries: Vec<String> = std::fs::read_dir(&scan.status.directory_path)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["README.txt"]);
        // A data dir without a Skills folder is created on demand.
        let fresh = tempfile::tempdir().unwrap();
        assert!(scan_user_skills(fresh.path()).unwrap().status.directory_path.ends_with("Skills"));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_skill_becomes_a_warning() {
        use std::os::unix::fs::PermissionsExt;
        // Root ignores file modes.
        if std::env::var("USER").as_deref() == Ok("root") {
            return;
        }
        let root = with_skills(&[
            def("Working Skill", "Working Skill", "A valid skill.", "Working body"),
            def("Broken Skill", "Broken Skill", "This file will be unreadable.", "Broken body"),
        ]);
        let broken = root.path().join("Skills/Broken Skill/SKILL.md");
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o000)).unwrap();
        let scan = scan_user_skills(root.path()).unwrap();
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(scan.status.ready_count, 1);
        assert_eq!(scan.status.warning_count, 1);
        let broken = scan.status.skills.iter().find(|s| s.directory_name == "Broken Skill").unwrap();
        assert_eq!(broken.status, "warning");
        assert!(broken.warnings[0].contains("Failed to read SKILL.md"), "{:?}", broken.warnings);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_skill_file_is_never_injected() {
        let root = with_skills(&[def("Working Skill", "Working Skill", "A valid skill.", "Working body")]);
        let skills = root.path().join("Skills");
        let linked = skills.join("Linked Skill");
        std::fs::create_dir_all(&linked).unwrap();
        let outside = root.path().join("outside-secret.md");
        std::fs::write(&outside, "---\nname: Linked Skill\ndescription: Linked helper.\n---\n\nTOPSECRET\n").unwrap();
        std::os::unix::fs::symlink(&outside, linked.join("SKILL.md")).unwrap();
        let scan = scan_user_skills(root.path()).unwrap();
        let ctx = build_user_skills_context(&scan, "plain prompt", &["linked-skill".into()]);
        let skill = scan.status.skills.iter().find(|s| s.directory_name == "Linked Skill").unwrap();
        assert_eq!(scan.status.ready_count, 1);
        assert_eq!(scan.status.warning_count, 1);
        assert_eq!(skill.status, "warning");
        assert!(skill.warnings[0].contains("symbolic link"));
        assert!(!ctx.contains("TOPSECRET"));
        assert!(ctx.contains("linked-skill"));
        assert!(ctx.contains("unavailable"));
    }

    #[test]
    fn duplicate_slugs_are_downgraded() {
        let root = with_skills(&[
            def("Foo Bar", "Foo Bar", "First skill.", "Body for Foo Bar"),
            def("foo-bar", "foo-bar", "Second skill.", "Body for foo-bar"),
        ]);
        let scan = scan_user_skills(root.path()).unwrap();
        let ctx = build_user_skills_context(&scan, "plain prompt", &["foo-bar".into()]);
        assert_eq!(scan.status.ready_count, 0);
        assert_eq!(scan.status.warning_count, 2);
        assert!(scan.status.skills.iter().all(|s| s.status == "warning"
            && s.warnings.iter().any(|w| w.contains("Duplicate skill slug \"foo-bar\""))));
        assert!(!ctx.contains("Body for Foo Bar"));
        assert!(!ctx.contains("Body for foo-bar"));
    }

    #[test]
    fn non_ascii_names_without_slug_are_warnings() {
        let root = with_skills(&[def("部署助手", "部署助手", "Deployment helper.", "Body")]);
        let scan = scan_user_skills(root.path()).unwrap();
        assert_eq!(scan.status.ready_count, 0);
        assert_eq!(scan.status.warning_count, 1);
        assert_eq!(scan.status.skills[0].slug, "");
        assert!(scan.status.skills[0].warnings[0].contains("usable slug"));
    }

    #[test]
    fn explicit_selections_are_capped() {
        let names = ["Skill One", "Skill Two", "Skill Three", "Skill Four", "Skill Five"];
        let bodies: Vec<String> = ["ONE", "TWO", "THREE", "FOUR", "FIVE"]
            .iter()
            .enumerate()
            .map(|(i, tag)| format!("BODY_{tag}_{}", ((b'a' + i as u8) as char).to_string().repeat(3500)))
            .collect();
        let defs: Vec<Def<'_>> = names.iter().zip(&bodies).map(|(n, b)| def(n, n, "Helper.", b)).collect();
        let root = with_skills(&defs);
        let ctx = context(root.path(), "plain prompt", &["skill-one", "skill-two", "skill-three", "skill-four", "skill-five"]);
        assert!(ctx.contains("BODY_ONE_"));
        assert!(ctx.contains("BODY_TWO_"));
        assert!(ctx.contains("BODY_THREE_"));
        assert!(!ctx.contains("BODY_FOUR_"));
        assert!(!ctx.contains("BODY_FIVE_"));
        assert!(ctx.contains("prompt budget"));
    }

    #[test]
    fn helpers() {
        assert_eq!(slugify_skill("  My Skill!! v2 "), "my-skill-v2");
        assert_eq!(strip_quotes(" 'x' "), "x");
        assert_eq!(strip_quotes("\""), "\"");
        assert_eq!(truncate_inline_text("a  b\n c", 100), "a b c");
        assert_eq!(truncate_inline_text("abcdefghij", 6), "abc...");
        assert!(contains_plaintext_phrase("use my skill, please", "My Skill"));
        assert!(!contains_plaintext_phrase("use myskill", "my skill"));
        assert_eq!(summarize_skill_slugs(&["a".into(), "b".into(), "c".into()], 2), "/a, /b, and 1 more");
    }
}
