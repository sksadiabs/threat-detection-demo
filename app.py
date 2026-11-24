import os
import re
import tempfile
from collections import Counter

import gradio as gr

# ----------------------------------------------------------------------
# PART 1: Rule-based detector
# Think of this as a security guard with a checklist. Each rule is one
# item on the checklist. If a log line matches an item, it earns points.
# Each rule: (name, pattern to look for, points, plain-English reason)
# ----------------------------------------------------------------------
RULES = [
    ("Failed login", r"failed (password|login)", 3,
     "Someone tried to sign in and got the password wrong"),
    ("Repeated attempts", r"attempts?\s*[=:]?\s*([5-9]|\d{2,})", 2,
     "Many tries in a short time, like someone guessing a lock's code"),
    ("Admin account", r"\b(root|admin|administrator)\b", 2,
     "An attempt on a powerful account that can change everything"),
    ("Unknown user", r"invalid user", 2,
     "Someone tried a username that doesn't exist"),
    ("SQL injection", r"(\bor\b\s+1\s*=\s*1|union\s+select|;\s*drop\s+table)", 5,
     "Text designed to trick a database into revealing its secrets"),
    ("Command injection", r"(;|\||&&)\s*(cat|ls|whoami|id|wget|curl|nc)\b|\|\s*(sh|bash)\b", 5,
     "Text that tries to sneak extra system commands into an input box"),
    ("Cross-site scripting", r"<script|onerror\s*=|javascript:", 4,
     "Code hidden in a web input that could run in other people's browsers"),
    ("Path traversal", r"\.\./|%2e%2e", 4,
     "Trying to climb out of the allowed folder into system files"),
    ("Port scan", r"(port scan|nmap|syn flood)", 4,
     "Someone walking the building testing every door handle"),
    ("Privilege escalation", r"sudo su|chmod\s+777|added to (the )?sudoers|usermod .*sudo|setuid", 4,
     "An attempt to gain more power than the account was given"),
    ("Attacker tool", r"(mimikatz|netcat|nc -e|powershell -enc)", 5,
     "A tool attackers commonly use to break in or move around"),
    ("New account created", r"new user|useradd|account created", 2,
     "A new account appeared, which attackers often create to return later"),
    ("Data upload site", r"pastebin\.com|transfer\.sh|ngrok\.io", 4,
     "Traffic to a site often used to move stolen data out"),
    ("Ransomware hint", r"ransom|\.locked\b|files? (were )?encrypted", 6,
     "Signs of software that locks files and demands payment"),
    ("Logs cleared", r"log (was )?cleared|history -c|wevtutil\s+cl|auditd.*stopped", 5,
     "Someone tried to erase their tracks"),
    ("Odd hours", r"(?<![\d:])(0[0-4]|2[2-3]):\d{2}", 1,
     "Activity at an unusual hour, when most people are asleep"),
    ("Missing page", r"\b404\b", 1,
     "A missing page; many in a row can mean someone is searching for weak spots"),
]

# A special rule that looks across ALL lines, not just one.
IP_PATTERN = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
FAILED_PATTERN = r"failed (password|login)"
IP_RULE_NAME = "Repeat failures from one IP"
IP_RULE_POINTS = 3
IP_RULE_WHY = ("This address keeps failing to log in, which suggests "
               "password guessing across the whole batch")
WATCHLIST_LABEL = "Your watchlist word"

ALL_RULE_NAMES = [rule[0] for rule in RULES] + [IP_RULE_NAME]
LEVELS = ["OK", "LOW", "MEDIUM", "HIGH"]


def level_for(score, medium_at, high_at):
    """Turn a total score into a label, using the sensitivity settings."""
    if score >= high_at:
        return "HIGH"
    if score >= medium_at:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "OK"


def analyze_logs(text, enabled, medium_at, high_at, ip_limit,
                 min_level, watch_words, watch_points, trusted_ips):
    """Check every non-empty line using the controls the user chose."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "Paste at least one log line first.", {}

    # Step A: count failed logins per IP address across all lines.
    # Trusted addresses (like your office network) are never counted.
    failures_per_ip = Counter()
    for line in lines:
        if re.search(FAILED_PATTERN, line, re.IGNORECASE):
            failures_per_ip.update(
                ip for ip in re.findall(IP_PATTERN, line) if ip not in trusted_ips
            )
    risky_ips = {ip for ip, count in failures_per_ip.items() if count >= ip_limit}

    # Step B: score each line.
    blocks = []
    counts = Counter()
    for line in lines:
        score = 0
        reasons = []
        for name, pattern, points, why in RULES:
            if name in enabled and re.search(pattern, line, re.IGNORECASE):
                score += points
                reasons.append(f"{name}: {why}")
        if IP_RULE_NAME in enabled and any(
            ip in risky_ips for ip in re.findall(IP_PATTERN, line)
        ):
            score += IP_RULE_POINTS
            reasons.append(f"{IP_RULE_NAME}: {IP_RULE_WHY}")
        for word in watch_words:
            if word in line.lower():
                score += watch_points
                reasons.append(f"{WATCHLIST_LABEL} '{word}': you asked to flag this word")

        level = level_for(score, medium_at, high_at)
        counts[level] += 1
        if LEVELS.index(level) < LEVELS.index(min_level):
            continue

        detail = "\n    ".join(reasons) if reasons else "No warning signs found."
        blocks.append(f"[{level}] (score {score})\n{line}\n    {detail}")

    summary = (f"Lines checked: {len(lines)} | HIGH: {counts['HIGH']} | "
               f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']} | "
               f"OK: {counts['OK']}")
    report = "\n\n".join(blocks) if blocks else "No lines to show with these settings."
    return summary + "\n\n" + report, counts


def parse_list(text):
    """Turn 'a, b, c' into ['a', 'b', 'c'] (lowercase, no blanks)."""
    return [item.strip().lower() for item in text.split(",") if item.strip()]


# ----------------------------------------------------------------------
# PART 2: Optional AI summary
# The AI reads the log lines and the rule results, then explains the
# risk in plain English. It only runs if an API key is provided through
# a "secret" setting, so the key never appears in the code.
# ----------------------------------------------------------------------
def ai_summary(logs, rule_results):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return ("AI summary is off. Add an ANTHROPIC_API_KEY secret "
                "in your hosting settings to turn it on.")
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        prompt = (
            "You are a security analyst explaining things to a beginner. "
            "In plain English with a simple analogy, summarize the risk in "
            "these log lines and suggest one next step.\n\n"
            f"Log lines:\n{logs}\n\nRule results:\n{rule_results}"
        )
        message = client.messages.create(
            model="claude-haiku-5-5",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except Exception as error:
        return f"The AI summary could not be created: {error}"


# ----------------------------------------------------------------------
# PART 3: The web page
# ----------------------------------------------------------------------
SAMPLE_LOGS = """Jan 10 09:14:02 server sshd: Accepted password for user1 from 198.51.100.20
Jan 10 02:11:45 server sshd: Failed password for root from 203.0.113.5 port 52244
Jan 10 02:11:47 server sshd: Failed password for root from 203.0.113.5 port 52246 attempts=8
Jan 10 02:11:50 server sshd: Failed password for admin from 203.0.113.5 port 52250
Jan 10 02:12:01 web app: GET /search?q=' OR 1=1 --
Jan 10 02:13:19 web app: GET /files?path=../../etc/passwd
Jan 10 02:14:05 web app: GET /shop?item=5;cat /etc/passwd
Jan 10 09:30:00 web app: GET /index.html 200
Jan 10 10:02:44 server sudo: user1 : user NOT in sudoers ; sudo su"""

DEFAULTS = {
    "enabled": ALL_RULE_NAMES,
    "medium_at": 3,
    "high_at": 6,
    "ip_limit": 3,
    "min_level": "OK",
    "watch_text": "",
    "watch_points": 4,
    "trusted_text": "",
}


def run_demo(text, enabled, medium_at, high_at, ip_limit,
             min_level, watch_text, watch_points, trusted_text):
    if not text.strip():
        return "Paste at least one log line first.", "Nothing to summarize yet.", None

    report, _ = analyze_logs(
        text, enabled, medium_at, high_at, ip_limit, min_level,
        parse_list(watch_text), watch_points, set(parse_list(trusted_text)),
    )
    ai_text = ai_summary(text, report)

    # Save the report as a text file the user can download.
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     prefix="threat_report_") as handle:
        handle.write(report)
        report_path = handle.name

    return report, ai_text, report_path


def reset_controls():
    d = DEFAULTS
    return (d["enabled"], d["medium_at"], d["high_at"], d["ip_limit"],
            d["min_level"], d["watch_text"], d["watch_points"], d["trusted_text"])


with gr.Blocks(title="AI Threat Detection Demo") as demo:
    gr.Markdown(
        "# AI Threat Detection Demo\n"
        "Paste computer log lines below. The detector checks each line "
        "like a security guard checking visitor badges, then flags the "
        "suspicious ones."
    )
    logs_box = gr.Textbox(
        label="Log lines",
        lines=10,
        placeholder="Paste one log entry per line here...",
    )

    with gr.Accordion("Rule controls", open=True):
        enabled_box = gr.CheckboxGroup(
            choices=ALL_RULE_NAMES,
            value=DEFAULTS["enabled"],
            label="Rules to use (uncheck a rule to ignore it)",
        )
        with gr.Row():
            medium_slider = gr.Slider(
                1, 10, value=DEFAULTS["medium_at"], step=1,
                label="Points needed for MEDIUM (lower = more sensitive)",
            )
            high_slider = gr.Slider(
                2, 20, value=DEFAULTS["high_at"], step=1,
                label="Points needed for HIGH (lower = more sensitive)",
            )
            ip_slider = gr.Slider(
                2, 10, value=DEFAULTS["ip_limit"], step=1,
                label="Failed logins from one IP before flagging it",
            )

    with gr.Accordion("Your own settings", open=True):
        watch_box = gr.Textbox(
            value=DEFAULTS["watch_text"],
            label="Watchlist words to flag (comma-separated, e.g. payroll, backup)",
        )
        watch_points_slider = gr.Slider(
            1, 10, value=DEFAULTS["watch_points"], step=1,
            label="Points added for each watchlist word found",
        )
        trusted_box = gr.Textbox(
            value=DEFAULTS["trusted_text"],
            label="Trusted IP addresses to ignore (comma-separated, e.g. 198.51.100.20)",
        )
        min_level_box = gr.Dropdown(
            choices=LEVELS,
            value=DEFAULTS["min_level"],
            label="Show lines at this level and above",
        )

    with gr.Row():
        sample_button = gr.Button("Load sample logs")
        reset_button = gr.Button("Reset controls")
        analyze_button = gr.Button("Analyze", variant="primary")

    rules_box = gr.Textbox(label="Results", lines=18)
    ai_box = gr.Textbox(label="AI summary", lines=6)
    file_box = gr.File(label="Download report (.txt)")

    sample_button.click(lambda: SAMPLE_LOGS, outputs=logs_box)
    reset_button.click(
        reset_controls,
        outputs=[enabled_box, medium_slider, high_slider, ip_slider,
                 min_level_box, watch_box, watch_points_slider, trusted_box],
    )
    analyze_button.click(
        run_demo,
        inputs=[logs_box, enabled_box, medium_slider, high_slider, ip_slider,
                min_level_box, watch_box, watch_points_slider, trusted_box],
        outputs=[rules_box, ai_box, file_box],
    )

if __name__ == "__main__":
    demo.launch()
