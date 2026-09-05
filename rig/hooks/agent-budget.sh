#!/bin/bash
# PreToolUse hook on Task. Enforces AGENT-MODEL.md section 7 mechanically,
# because every attempt to enforce it by writing it down has failed.
#
# WHY THIS EXISTS. 2026-09-03: a session ran eight subagents, all on Opus, for
# ~650,000 tokens against Adam's 5-hour window -- and made nine commits, none
# of which touched a module. CLAUDE.md said Haiku for long reads and Opus only
# for falsification. AGENT-MODEL.md section 7 ranked the rules by measured
# impact. Both were in the repository. Neither was read.
#
# It gates on FACTS -- the model, and how many have run -- not on the prompt.
# Prompt wording is the part a session can talk itself around; a counter is not.
#
# It is deliberately weak in one direction and says so: Adam can lift any of
# this by editing the caps below. An agent must ASK him, which is the point.
set -u
STATE_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude"
payload=$(cat)
sid=$(printf '%s' "$payload" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("session_id","nosession"))' 2>/dev/null)
model=$(printf '%s' "$payload" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("tool_input") or {}).get("model") or "default")' 2>/dev/null)
tally="$STATE_DIR/.agent-tally-$sid"
touch "$tally" 2>/dev/null
total=$(wc -l < "$tally" 2>/dev/null | tr -d ' '); total=${total:-0}
opus=$(grep -c '^opus$' "$tally" 2>/dev/null); opus=${opus:-0}

MAX_TOTAL=2
MAX_OPUS=1

# Past the cap we ASK Adam rather than refusing. He said: "let the session
# prompt me to add another subagent if that need is crucial." So the cap is a
# checkpoint that puts him in the loop, not a wall -- and crucially it is HIS
# decision, made in the moment, not a number an agent talked itself past.
# Each spawn beyond the cap asks again; approval is per-agent, never a raised
# ceiling for the rest of the session.
ask() {
	python3 -c 'import json,sys; print(json.dumps({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":sys.argv[1]}}))' "$1"
	exit 0
}

if [ "$model" = "opus" ] && [ "$opus" -ge "$MAX_OPUS" ]; then
	ask "AGENT BUDGET: $opus Opus subagents already ran this session (cap $MAX_OPUS).
Opus is for FALSIFICATION only -- AGENT-MODEL.md section 7, 'cheapest model per role'.
A librarian is Sonnet; a long read is Haiku. Re-spawn with one of those, or ask
Adam whether this one is crucial. Do not work around this by rewording the
prompt or downgrading the model to dodge the check -- the cap is on the model,
deliberately. Say what it is FOR and why a cheaper model will not do."
fi

if [ "$total" -ge "$MAX_TOTAL" ]; then
	ask "AGENT BUDGET: $total subagents already ran this session (cap $MAX_TOTAL).
On 2026-09-03 eight of them cost ~650k tokens of Adam's window and moved zero modules.
Before spawning another, answer: would reading it myself be cheaper
(under a few hundred lines it is, by ~16x), and does this move a module?
If you still need it, say what it is FOR and let Adam decide. Approving one
does not raise the cap -- the next will ask him again."
fi

printf '%s\n' "$model" >> "$tally"
printf 'agent-budget: %s, #%d this session (opus %d/%d, total %d/%d)\n' \
	"$model" "$((total+1))" \
	"$([ "$model" = opus ] && echo $((opus+1)) || echo "$opus")" "$MAX_OPUS" \
	"$((total+1))" "$MAX_TOTAL"
exit 0
