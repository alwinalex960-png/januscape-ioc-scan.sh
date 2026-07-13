#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# ic-5866-januscape-ioc-scan.sh
# IOC scan for IC-5866 "januscape" nested-KVM host denial-of-service exploit
# (2026-07-08).
# Attack chain: guest-controlled race condition in the host kernel's shadow
#   MMU code (arch/x86/kvm/mmu/mmu.c), triggered from an unprivileged nested
#   L2 guest, crashes or soft-locks the host kernel (host-level DoS; no
#   privesc, persistence, or C2 is involved).
# Zero runtime dependencies beyond bash 4.x and standard Linux utilities.
# ---------------------------------------------------------------------------

TOOL="ic-5866-januscape"
TOOL_VERSION="0.1.0"

# ---------------------------------------------------------------------------
# Path/command overrides (environment variables used by test suite)
# ---------------------------------------------------------------------------
TMP_DIR="${TMP_DIR:-/tmp}"
IOC_LEDGER_DIR="${IOC_LEDGER_DIR:-/var/tmp/${TOOL}-ioc}"
FORENSIC_ROOT="${FORENSIC_ROOT:-/root}"
# IOC_TEST_MODE=1 disables ledger writes requiring root (used by bats tests)
IOC_TEST_MODE="${IOC_TEST_MODE:-0}"

# Command used to read the live kernel ring buffer. Override to a fixture
# reader for tests, e.g. DMESG_CMD='cat testdata/dmesg-soft-lockup.txt'
DMESG_CMD="${DMESG_CMD:-dmesg}"
# Command used to read the persistent kernel journal. Override similarly,
# e.g. JOURNALCTL_CMD='cat testdata/journal.txt'
JOURNALCTL_CMD="${JOURNALCTL_CMD:-journalctl -k --no-pager}"
# Persistent kernel log fallbacks (not all modern hosts retain these).
KERN_LOG_FILE="${KERN_LOG_FILE:-/var/log/kern.log}"
MESSAGES_LOG_FILE="${MESSAGES_LOG_FILE:-/var/log/messages}"
# sysfs root, overridable so --full forensic context collection (nested KVM
# module parameters) is testable against a fixture tree.
SYS_DIR="${SYS_DIR:-/sys}"

# Per-source wall-clock cap (seconds) for reading dmesg/journalctl/kern.log/
# messages. A host actively hitting this exploit can have a huge or slow
# journal (or, in the worst case, a genuinely stuck kernel); this bounds the
# scan instead of letting it hang. A source that times out is skipped and
# flagged with a review-severity signal rather than aborting the scan.
LOG_READ_TIMEOUT="${LOG_READ_TIMEOUT:-30}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
MODE="triage"
FLAG_FULL=0
FLAG_QUIET=0
FLAG_SUMMARY=0
FLAG_JSON=0
FLAG_CSV=0
FLAG_LOCAL_ONLY=0
FLAG_JSONL=0
OPT_UPLOAD_URL=""
TELEMETRY_MODE=0
TELEMETRY_URL=""
TELEMETRY_TOKEN=""
TELEMETRY_TIMEOUT=15
TELEMETRY_RETRY=2
TELEMETRY_MAX_BYTES=$((5 * 1024 * 1024))
CHAIN_ON_ALL=0
DO_UPLOAD=0
INTAKE_TOKEN=""

_usage() {
    cat <<'EOF'
Usage: ic-5866-januscape-ioc-scan.sh [OPTIONS]
Revised: 2026-07-08 UTC

IOC scanner for the IC-5866 "januscape" nested-KVM host DoS exploit.
Attack chain: guest-controlled race condition in the host kernel's shadow
  MMU code (arch/x86/kvm/mmu/mmu.c) -> host kernel soft lockup/crash.
This is a host-level denial-of-service exploit, not a privesc/persistence/C2
compromise: there is no dropped binary, no attacker IP, and no user-homedir
artifact to check. Detection is limited to matching known exploit-effect and
PoC-tool strings in kernel/journal logs (dmesg, journalctl -k, kern.log,
messages), per incident analyst guidance. The scan also reports the current
nested-virtualization module state (kvm_intel/kvm_amd `nested` parameter) as
an informational advisory, independent of verdict scoring, so fleet sweeps
can distinguish mitigated hosts (nested=N) from still-vulnerable ones
(nested=Y) without needing --full.

MUST BE RUN AS ROOT (or a user in the systemd-journal group with read access
to kern.log/messages). Unprivileged `dmesg` fails instantly under the default
kernel.dmesg_restrict=1, and /var/log/journal is normally root:systemd-journal
0640 — an unprivileged run silently sees zero log sources and reports a false
CLEAN rather than erroring.

EXIT CODES
  0  CLEAN       no IOCs detected
  3  SUSPICIOUS  soft indicators present, manual review needed
  4  COMPROMISED confirmed IOC match

OUTPUT OPTIONS (mutually exclusive; default is human-readable to stdout)
  --jsonl          per-finding JSONL matching SessionScribe schema (area/severity/key/weight/note)
                     one line per IOC hit, plus a trailing "meta" envelope line
                     matches the --jsonl format of iworx-gsocket-ioc-scan.sh
  --summary        one JSON object per host (verdict/score/counts); simpler fleet aggregation
  --json           JSON array (single host)
  --csv            CSV with header row
  --quiet          suppress stderr log lines (still emits selected output format)

SCAN OPTIONS
  --full           collect forensic bundle in addition to triage checks:
                     phase_defense  kernel version + loaded KVM module names (log only;
                                    nested-virt state itself is reported every run, see below)
                     phase_offense  kern.log/messages mtimes for timeline context (log only)
                     phase_bundle   raw dmesg/journalctl/kern.log/messages capture +
                                    ioc-scan-envelope.json -> FORENSIC_ROOT
                   ioc-scan-envelope.json is sessionscribe-compatible (same field layout as
                   sessionscribe-ioc-scan.sh write_json(): signals[], advisories[],
                   software_digest, score/verdict/exit_code)
  --local-only     run --full but skip upload even if --upload-url is set
  --upload-url URL upload URL for forensic bundle
                     with --upload-token: PUT bundle dir as outer .upload.tgz with
                       X-Upload-Token header (matches sessionscribe upload format exactly)
                     without --upload-token: presigned PUT of the outer tarball
  --upload-token T X-Upload-Token header value for bundle PUT; also triggers
                   sessionscribe-compatible outer tarball wrapping of the bundle dir

TELEMETRY OPTIONS (SessionScribe collector-compatible)
  --telemetry            POST ioc-scan-envelope.json to --telemetry-url after scan.
                           If --full/--chain-on-all also set, reads the envelope written
                           by phase_bundle. Otherwise writes a temp envelope for the POST.
                           POSTed body is the full sessionscribe-format envelope (not the
                           thin --jsonl meta line), so the collector sees the same JSON
                           structure it receives from sessionscribe-ioc-scan.sh.
                           Failure is advisory: warns to stderr, does not change exit code.
  --telemetry-url URL    POST target (must start with http:// or https://)
  --telemetry-token TOK  Authorization: Bearer header on telemetry POST
  --telemetry-timeout N  per-attempt HTTP timeout in seconds (default: 15)
  --telemetry-retry N    retry count on transient failure, expo backoff 2^N s (default: 2)
  --telemetry-max-bytes B  cap envelope size; skip POST if exceeded (default: 5MB)
  --chain-on-all         always run full forensic collection regardless of verdict
                           (implies --full; use for fleet sweep where every host ships
                           an envelope regardless of CLEAN/SUSPICIOUS/COMPROMISED)
  --chain-upload         run full forensic + upload bundle (implies --full)

ENVIRONMENT OVERRIDES (path/command defaults for test environments)
  DMESG_CMD          command to read the kernel ring buffer   (default: dmesg)
                       override for tests, e.g. DMESG_CMD='cat testdata/dmesg.txt'
  JOURNALCTL_CMD     command to read the kernel journal        (default: journalctl -k --no-pager)
                       override for tests, e.g. JOURNALCTL_CMD='cat testdata/journal.txt'
  KERN_LOG_FILE      persistent kernel log fallback            (default: /var/log/kern.log)
  MESSAGES_LOG_FILE  persistent syslog fallback                (default: /var/log/messages)
  LOG_READ_TIMEOUT   per-source read timeout in seconds         (default: 30)
                       a source exceeding this is skipped (not aborted) and
                       flagged with a review-severity signal; guards against
                       a huge/unvacuumed journal or a host under active load
  SYS_DIR            sysfs root for nested-KVM module state    (default: /sys)
  TMP_DIR            temp directory                            (default: /tmp)
  IOC_LEDGER_DIR     append-only run ledger directory          (default: /var/tmp/ic-5866-januscape-ioc)
  FORENSIC_ROOT      parent dir for forensic bundles           (default: /root)
  IOC_TEST_MODE      set to 1 to skip ledger writes             (default: 0)

EXAMPLES
  # Triage, human output
  bash ic-5866-januscape-ioc-scan.sh

  # Fleet sweep — per-finding JSONL (SessionScribe compat), filter to strong hits
  bash ic-5866-januscape-ioc-scan.sh --jsonl --quiet | jq 'select(.severity == "strong")'

  # Fleet sweep — host summary only, filter to compromised hosts
  bash ic-5866-januscape-ioc-scan.sh --summary --quiet | jq 'select(.verdict == "COMPROMISED")'

  # Full forensic collection with upload
  bash ic-5866-januscape-ioc-scan.sh --full --upload-url "https://s3.example.com/..."

  # Test against fixture kernel-log content instead of the live host
  DMESG_CMD='cat testdata/dmesg-soft-lockup.txt' JOURNALCTL_CMD='cat /dev/null' \
    KERN_LOG_FILE=/nonexistent MESSAGES_LOG_FILE=/nonexistent \
    bash ic-5866-januscape-ioc-scan.sh --jsonl --quiet

  # Fleet sweep with SessionScribe telemetry collector
  bash ic-5866-januscape-ioc-scan.sh \
    --telemetry --telemetry-url 'https://pubfiles.nexcess.net/sessionscribe/collector.php' \
    --telemetry-token 'TOKEN' \
    --chain-on-all --chain-upload \
    --upload-url 'https://pubfiles.nexcess.net/sessionscribe/collector.php' \
    --upload-token 'TOKEN' \
    --quiet --jsonl
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)        FLAG_FULL=1 ;;
        --quiet)       FLAG_QUIET=1 ;;
        --jsonl)       FLAG_JSONL=1 ;;
        --summary)     FLAG_SUMMARY=1 ;;
        --json)        FLAG_JSON=1 ;;
        --csv)         FLAG_CSV=1 ;;
        --local-only)           FLAG_LOCAL_ONLY=1 ;;
        --upload-url)           OPT_UPLOAD_URL="${2:-}"; shift ;;
        --upload-token)         INTAKE_TOKEN="${2:-}"; shift ;;
        --telemetry)            TELEMETRY_MODE=1 ;;
        --telemetry-url)        TELEMETRY_URL="${2:-}"; shift ;;
        --telemetry-token)      TELEMETRY_TOKEN="${2:-}"; shift ;;
        --telemetry-timeout)    TELEMETRY_TIMEOUT="${2:-15}"; shift ;;
        --telemetry-retry)      TELEMETRY_RETRY="${2:-2}"; shift ;;
        --telemetry-max-bytes)  TELEMETRY_MAX_BYTES="${2:-5242880}"; shift ;;
        --chain-on-all)         CHAIN_ON_ALL=1; FLAG_FULL=1 ;;
        --chain-upload)         DO_UPLOAD=1; FLAG_FULL=1 ;;
        --help|-h)              _usage; exit 0 ;;
        *) ;;
    esac
    shift
done

[[ "${FLAG_FULL}" -eq 1 ]] && MODE="full"

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
ioc_critical=0
ioc_review=0
advisory=0
host_verdict="CLEAN"
score=0
exit_code=0
run_id=""
SIGNALS=()
ts=""
detail_json="{}"

forensic_dir=""
upload_status="false"
bundle_path_json="null"
ENVELOPE_PATH=""

# ---------------------------------------------------------------------------
# IC-5866 "januscape" kernel-log IOC strings.
# Source: security analyst (Rob Rosson) — dmesg/journalctl/kern.log/messages
# string matches are the only available evidence for this exploit; there is
# no dropped binary, C2 IP, or persistence mechanism for this incident.
# All 9 strings are treated as critical severity (weight 10) — each is highly
# specific to this exploit with no plausible benign explanation.
# ---------------------------------------------------------------------------
IOC_PATTERN_KEYS=(
    soft_lockup
    mmu_warning
    mmu_bug
    return_thunk
    shadow_root_role
    poc_step1
    poc_step2
    poc_step3
    poc_step4
)

declare -A IOC_PATTERN_MODE=(
    [soft_lockup]="literal"
    [mmu_warning]="regex"
    [mmu_bug]="literal"
    [return_thunk]="literal"
    [shadow_root_role]="literal"
    [poc_step1]="literal"
    [poc_step2]="literal"
    [poc_step3]="literal"
    [poc_step4]="literal"
)

declare -A IOC_PATTERN_TEXT=(
    [soft_lockup]='watchdog: BUG: soft lockup'
    [mmu_warning]='WARNING: CPU: [0-9]+.*at arch/x86/kvm/mmu/mmu\.c'
    [mmu_bug]='kernel BUG at arch/x86/kvm/mmu/mmu.c'
    [return_thunk]='Unpatched return thunk in use. This should not happen!'
    [shadow_root_role]='kvm_calc_shadow_root_page_role_common'
    [poc_step1]='[*] poc step 1/4: backend=VMX/EPT ready (rmmod kvm_intel done)'
    [poc_step2]='[*] poc step 2/4: nested page tables + L3 guest image built'
    [poc_step3]='[*] poc step 3/4: launching 8 kthreads (1 writer + 7 faulters)'
    [poc_step4]='[*] poc step 4/4: race live -- host DoS triggering'
)

declare -A IOC_PATTERN_NOTE=(
    [soft_lockup]="kernel watchdog soft lockup (strongest single indicator per incident analyst)"
    [mmu_warning]="kernel WARNING at arch/x86/kvm/mmu/mmu.c"
    [mmu_bug]="kernel BUG at arch/x86/kvm/mmu/mmu.c"
    [return_thunk]="unpatched return-thunk warning surfaced during exploit-triggered crash"
    [shadow_root_role]="kvm_calc_shadow_root_page_role_common present in kernel backtrace"
    [poc_step1]="januscape PoC step 1/4 string observed (VMX/EPT backend setup)"
    [poc_step2]="januscape PoC step 2/4 string observed (nested page tables + L3 guest build)"
    [poc_step3]="januscape PoC step 3/4 string observed (writer/faulter kthreads launched)"
    [poc_step4]="januscape PoC step 4/4 string observed (race live, host DoS triggering)"
)

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

_log() {
    [[ "${FLAG_QUIET}" -eq 1 ]] && return 0
    printf '[%s] %s\n' "${TOOL}" "$*" >&2
}

_warn() {
    [[ "${FLAG_QUIET}" -eq 1 ]] && return 0
    printf '[%s] WARN: %s\n' "${TOOL}" "$*" >&2
}

_inc() {
    local varname="$1"
    eval "${varname}=\$(( ${varname} + 1 ))"
}

# _signal level key note [k v ...]
# Unified finding emitter: increments the right counter, logs to stderr,
# accumulates in SIGNALS[], and streams per-signal JSONL when --signals is set.
# level: critical | review | advisory
# Extra k/v pairs are included in the --signals JSON output. Pass area=<val>
# to override the default area (offense for critical/review, defense for advisory).
_signal() {
    local level="$1" key="$2" note="$3"
    shift 3

    local sev area weight
    case "${level}" in
        critical) _inc ioc_critical; sev="strong";  area="offense"; weight=10 ;;
        review)   _inc ioc_review;   sev="warning"; area="offense"; weight=4  ;;
        advisory) _inc advisory;     sev="info";    area="defense"; weight=0  ;;
        *)        sev="info";        area="offense"; weight=0 ;;
    esac

    local extra_kv=""
    while [[ $# -ge 2 ]]; do
        local _k="$1" _v="${2//\"/\\\"}"
        shift 2
        if [[ "${_k}" == "area" ]]; then
            area="${_v}"
        else
            extra_kv="${extra_kv},\"${_k}\":\"${_v}\""
        fi
    done

    [[ "${FLAG_QUIET}" -eq 0 ]] && printf '[%s] %s: %s\n' "${TOOL}" "${key}" "${note}" >&2

    SIGNALS+=("${area}|${sev}|${weight}|${key}|${note}")

    if [[ "${FLAG_JSONL}" -eq 1 ]]; then
        local _host
        _host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
        printf '{"host":"%s","run_id":"%s","area":"%s","id":"%s","severity":"%s","key":"%s","weight":%d,"note":"%s"%s}\n' \
            "${_host}" "${run_id}" "${area}" "${key}" "${sev}" "${key}" \
            "${weight}" "${note//\"/\\\"}" "${extra_kv}"
    fi
}

_json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

_generate_run_id() {
    local date_part hex_part
    date_part="$(date -u '+%Y%m%d-%H%M%S')"
    hex_part="$(head -c 2 /dev/urandom | od -A n -t x1 | tr -d ' \n' | head -c 4)"
    echo "${date_part}-${hex_part}"
}

# _read_with_timeout SECS CMD [ARGS...]
# Runs CMD bounded by `timeout` (falls back to running unbounded if the
# `timeout` binary itself is unavailable). Exit code 124 means CMD was
# killed for exceeding SECS — callers check for that specifically since a
# log source that's too slow to read is itself worth flagging on this
# incident (host may be under active load from the exploit).
_read_with_timeout() {
    local secs="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "${secs}" "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# check_kernel_log_iocs() — scan dmesg, journalctl -k, and the persistent
# kern.log/messages fallbacks for the 9 januscape exploit indicator strings.
# Every hit is emitted as its own critical _signal with a key of the form
# "<pattern>_<source>" so downstream JSONL/signals consumers can tell which
# pattern matched in which log source (e.g. soft_lockup_dmesg,
# poc_step3_journal, mmu_bug_kernlog, return_thunk_messages).
# ---------------------------------------------------------------------------
check_kernel_log_iocs() {
    _log "check_kernel_log_iocs: scanning dmesg/journalctl/kern.log/messages for januscape IOC strings"

    # Build the 8 literal patterns once as -e args for a single grep -F pass;
    # the 1 regex pattern gets its own grep -E pass. Two full-file grep scans
    # (fast, in C) per source, instead of loading the whole source into a
    # bash string and re-scanning it via a heredoc once per pattern (9x) --
    # on a large /var/log/messages the latter is what actually caused
    # multi-minute runtimes in the field, not a stuck read.
    local -a lit_grep_args=()
    local pkey
    for pkey in "${IOC_PATTERN_KEYS[@]}"; do
        [[ "${IOC_PATTERN_MODE[${pkey}]}" == "literal" ]] && lit_grep_args+=(-e "${IOC_PATTERN_TEXT[${pkey}]}")
    done
    local regex_pattern="${IOC_PATTERN_TEXT[mmu_warning]}"

    local -a src_keys=() src_labels=() src_paths=() src_cleanup=()
    local rc tmpfile

    local dmesg_bin="${DMESG_CMD%% *}"
    if command -v "${dmesg_bin}" >/dev/null 2>&1; then
        tmpfile="$(mktemp "${TMP_DIR}/${TOOL}-dmesg.XXXXXX")"
        rc=0; _read_with_timeout "${LOG_READ_TIMEOUT}" ${DMESG_CMD} > "${tmpfile}" 2>/dev/null || rc=$?
        if [[ "${rc}" -eq 124 ]]; then
            _signal review "log_source_timeout_dmesg" "dmesg read timed out after ${LOG_READ_TIMEOUT}s (host may be under active load from this exploit); source skipped"
            rm -f "${tmpfile}"
        else
            src_keys+=("dmesg"); src_labels+=("dmesg"); src_paths+=("${tmpfile}"); src_cleanup+=("${tmpfile}")
        fi
    else
        _log "check_kernel_log_iocs: '${dmesg_bin}' not available, skipping dmesg source"
    fi

    local journalctl_bin="${JOURNALCTL_CMD%% *}"
    if command -v "${journalctl_bin}" >/dev/null 2>&1; then
        tmpfile="$(mktemp "${TMP_DIR}/${TOOL}-journal.XXXXXX")"
        rc=0; _read_with_timeout "${LOG_READ_TIMEOUT}" ${JOURNALCTL_CMD} > "${tmpfile}" 2>/dev/null || rc=$?
        if [[ "${rc}" -eq 124 ]]; then
            _signal review "log_source_timeout_journal" "journalctl -k read timed out after ${LOG_READ_TIMEOUT}s (large/unvacuumed journal or host under active load); source skipped"
            rm -f "${tmpfile}"
        else
            src_keys+=("journal"); src_labels+=("journalctl -k"); src_paths+=("${tmpfile}"); src_cleanup+=("${tmpfile}")
        fi
    else
        _log "check_kernel_log_iocs: '${journalctl_bin}' not available, skipping journalctl source (expected on hosts without persistent journald)"
    fi

    [[ -f "${KERN_LOG_FILE}" ]] && { src_keys+=("kernlog"); src_labels+=("${KERN_LOG_FILE}"); src_paths+=("${KERN_LOG_FILE}"); }
    [[ -f "${MESSAGES_LOG_FILE}" ]] && { src_keys+=("messages"); src_labels+=("${MESSAGES_LOG_FILE}"); src_paths+=("${MESSAGES_LOG_FILE}"); }

    if [[ "${#src_keys[@]}" -eq 0 ]]; then
        _warn "check_kernel_log_iocs: no log sources available (no dmesg, no journalctl, no kern.log/messages, or all timed out)"
        return 0
    fi

    local found=0
    local i src_key src_label path lit_out regex_out matched_lines note mode pattern rc1 rc2
    for (( i=0; i<"${#src_keys[@]}"; i++ )); do
        src_key="${src_keys[$i]}"
        src_label="${src_labels[$i]}"
        path="${src_paths[$i]}"
        [[ -s "${path}" ]] || continue

        rc1=0; lit_out="$(_read_with_timeout "${LOG_READ_TIMEOUT}" grep -hF "${lit_grep_args[@]}" -- "${path}" 2>/dev/null)" || rc1=$?
        rc2=0; regex_out="$(_read_with_timeout "${LOG_READ_TIMEOUT}" grep -hE -- "${regex_pattern}" "${path}" 2>/dev/null)" || rc2=$?

        if [[ "${rc1}" -eq 124 || "${rc2}" -eq 124 ]]; then
            _signal review "log_source_timeout_${src_key}" "${src_label} read timed out after ${LOG_READ_TIMEOUT}s; source skipped"
            continue
        fi

        matched_lines="${lit_out}"$'\n'"${regex_out}"
        [[ -z "${matched_lines//$'\n'/}" ]] && continue

        for pkey in "${IOC_PATTERN_KEYS[@]}"; do
            mode="${IOC_PATTERN_MODE[${pkey}]}"
            pattern="${IOC_PATTERN_TEXT[${pkey}]}"
            note="${IOC_PATTERN_NOTE[${pkey}]}"

            if [[ "${mode}" == "regex" ]]; then
                grep -qE -- "${pattern}" <<< "${matched_lines}" || continue
            else
                grep -qF -- "${pattern}" <<< "${matched_lines}" || continue
            fi

            _signal critical "${pkey}_${src_key}" "${note} [source=${src_label}]"
            found=1
        done
    done

    for tmpfile in "${src_cleanup[@]+"${src_cleanup[@]}"}"; do
        rm -f "${tmpfile}"
    done

    if [[ "${found}" -eq 0 ]]; then
        _log "check_kernel_log_iocs: no januscape IOC strings found in any source"
    fi
}

# ---------------------------------------------------------------------------
# check_nested_virt_state() — report whether nested virtualization is
# currently enabled on the host. This is NOT an IOC by itself (an enabled
# config isn't evidence of exploitation), but it's the exact knob the IC-5866
# mitigation flips off, so this is how a fleet sweep tells mitigated hosts
# (nested=N) from still-vulnerable ones (nested=Y) via --jsonl/--summary/--csv
# without needing --full forensic collection. Runs every scan, not just
# --full, since that's the point of the check.
# ---------------------------------------------------------------------------
check_nested_virt_state() {
    _log "check_nested_virt_state: reading kvm_intel/kvm_amd nested parameter"

    local mod nested_path nested_val found_module=0
    for mod in kvm_intel kvm_amd; do
        nested_path="${SYS_DIR}/module/${mod}/parameters/nested"
        [[ -f "${nested_path}" ]] || continue
        found_module=1
        nested_val="$(cat "${nested_path}" 2>/dev/null || echo unknown)"

        case "${nested_val}" in
            Y|1)
                _signal advisory "nested_virt_enabled_${mod}" "nested virtualization enabled on ${mod} (host not mitigated for IC-5866/CVE-2026-53359)"
                ;;
            N|0)
                _signal advisory "nested_virt_disabled_${mod}" "nested virtualization disabled on ${mod} (host mitigated for IC-5866/CVE-2026-53359)"
                ;;
            *)
                _signal advisory "nested_virt_unknown_${mod}" "nested virtualization state for ${mod} could not be determined (raw value: ${nested_val})"
                ;;
        esac
    done

    if [[ "${found_module}" -eq 0 ]]; then
        _signal advisory "nested_virt_module_not_loaded" "no kvm_intel/kvm_amd module loaded; nested virtualization state not applicable"
    fi
}

# ---------------------------------------------------------------------------
# Scoring + verdict
# ---------------------------------------------------------------------------
compute_verdicts() {
    score=$(( ioc_critical * 10 + ioc_review * 5 + advisory * 1 ))

    if (( score >= 10 )); then
        host_verdict="COMPROMISED"
    elif (( score >= 5 )); then
        host_verdict="SUSPICIOUS"
    else
        host_verdict="CLEAN"
    fi
}

derive_exit_code() {
    case "${host_verdict}" in
        COMPROMISED) exit_code=4 ;;
        SUSPICIOUS)  exit_code=3 ;;
        *)           exit_code=0 ;;
    esac
}

# ---------------------------------------------------------------------------
# Ledger writer (append-only)
# ---------------------------------------------------------------------------
write_ledger() {
    [[ "${IOC_TEST_MODE}" == "1" ]] && return 0

    local upload="${1:-false}"
    local bundle_path="${2:-null}"

    mkdir -p "${IOC_LEDGER_DIR}"
    local ts_safe="${ts//:/-}"
    local ledger_file="${IOC_LEDGER_DIR}/${ts_safe}-${run_id}.json"

    printf '{"run_id":"%s","ts":"%s","tool_version":"%s","mode":"%s","verdict":"%s","score":%d,"upload":%s,"bundle_path":%s}\n' \
        "${run_id}" "${ts}" "${TOOL_VERSION}" "${MODE}" \
        "${host_verdict}" "${score}" \
        "${upload}" "${bundle_path}" >> "${ledger_file}"
}

# ---------------------------------------------------------------------------
# Output emitters
# ---------------------------------------------------------------------------
emit_summary() {
    local host
    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    printf '{"host":"%s","os":"linux/amd64","tool":"ioc-scan","tool_version":"%s","incident":"%s","run_id":"%s","ts":"%s","exit_code":%d,"verdict":"%s","score":%d,"detail":%s}\n' \
        "${host}" "${TOOL_VERSION}" "${TOOL}" \
        "${run_id}" "${ts}" "${exit_code}" \
        "${host_verdict}" "${score}" "${detail_json}"
}

emit_csv() {
    local host
    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    printf 'host,os,tool,tool_version,incident,run_id,ts,exit_code,verdict,score\n'
    printf '%s,linux/amd64,ioc-scan,%s,%s,%s,%s,%d,%s,%d\n' \
        "${host}" "${TOOL_VERSION}" "${TOOL}" \
        "${run_id}" "${ts}" "${exit_code}" \
        "${host_verdict}" "${score}"
}

emit_signals_meta() {
    local host
    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    printf '{"kind":"meta","host":"%s","tool":"%s","tool_version":"%s","incident":"%s","run_id":"%s","ts":"%s","verdict":"%s","score":%d,"ioc_critical":%d,"ioc_review":%d,"advisory":%d,"exit_code":%d}\n' \
        "${host}" "${TOOL}" "${TOOL_VERSION}" "${TOOL}" \
        "${run_id}" "${ts}" \
        "${host_verdict}" "${score}" "${ioc_critical}" "${ioc_review}" "${advisory}" "${exit_code}"
}

emit_human() {
    [[ "${FLAG_QUIET}" -eq 1 ]] && return 0
    local host
    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    printf '\n=== %s | incident: %s | run_id: %s ===\n' "${host}" "${TOOL}" "${run_id}"
    printf '  verdict:  %s\n' "${host_verdict}"
    printf '  score:    %d\n' "${score}"
    printf '  critical: %d\n' "${ioc_critical}"
    printf '  review:   %d\n' "${ioc_review}"
    printf '  advisory: %d\n' "${advisory}"
    printf '  ts:       %s\n' "${ts}"
    printf '  mode:     %s\n' "${MODE}"
}

# ---------------------------------------------------------------------------
# write_envelope() — write a sessionscribe-compatible ioc-scan-envelope.json.
# Produces the same top-level structure as sessionscribe's write_json():
# tool/version/run_id/host/ts, verdicts, score, summary counts, advisories[],
# signals[], software_digest, software_inventory fields (empty where not
# applicable to this tool). Collectors that parse sessionscribe envelopes
# accept this output without modification.
# ---------------------------------------------------------------------------
write_envelope() {
    local out="$1"
    local host
    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"

    local kernel_running pkgmgr_kind
    kernel_running="$(uname -r 2>/dev/null || echo unknown)"
    if command -v rpm >/dev/null 2>&1; then
        pkgmgr_kind="rpm"
    elif command -v dpkg >/dev/null 2>&1; then
        pkgmgr_kind="dpkg"
    else
        pkgmgr_kind="unknown"
    fi

    local first=1 entry _area _sev _weight _key _note
    {
        printf '{\n'
        printf '  "tool": "%s",\n'         "${TOOL}"
        printf '  "tool_version": "%s",\n' "${TOOL_VERSION}"
        printf '  "run_id": "%s",\n'       "${run_id}"
        printf '  "host": "%s",\n'         "$(_json_esc "${host}")"
        printf '  "ts": "%s",\n'           "${ts}"
        printf '  "code_verdict": "%s",\n'       "${host_verdict}"
        printf '  "host_root_verdict": "%s",\n'  "${host_verdict}"
        printf '  "host_user_verdict": "%s",\n'  "${host_verdict}"
        printf '  "host_user_summary": {"total_users":0,"compromised":0,"suspect":0,"clean_or_unknown":0},\n'
        printf '  "users": [],\n'
        printf '  "users_truncated": false,\n'
        printf '  "users_truncated_count": 0,\n'
        printf '  "score": %d,\n'     "${score}"
        printf '  "exit_code": %d,\n' "${exit_code}"
        printf '  "summary": {"strong":%d,"fixed":0,"inconclusive":0,"ioc_critical":%d,"ioc_review":%d,"compromise_critical":0,"compromise_critical_live":0,"compromise_critical_quarantine":0,"advisories":%d,"probe_artifacts":0,"persist_count":0,"persist_score":0,"persist_multiplier":1,"persist_patterns":"","session_tiered_count":0,"session_max_reasons":0},\n' \
            "${ioc_critical}" "${ioc_critical}" "${ioc_review}" "${advisory}"
        printf '  "advisories": [\n'
        first=1
        for entry in "${SIGNALS[@]+"${SIGNALS[@]}"}"; do
            IFS='|' read -r _area _sev _weight _key _note <<< "${entry}"
            [[ "${_sev}" == "info" ]] || continue
            (( first )) || printf ',\n'
            first=0
            printf '    {"id":"%s","key":"%s","note":"%s"}' \
                "$(_json_esc "${_key}")" "$(_json_esc "${_key}")" "$(_json_esc "${_note}")"
        done
        printf '\n  ],\n'
        printf '  "signals": [\n'
        first=1
        for entry in "${SIGNALS[@]+"${SIGNALS[@]}"}"; do
            IFS='|' read -r _area _sev _weight _key _note <<< "${entry}"
            (( first )) || printf ',\n'
            first=0
            printf '    {"host":"%s","area":"%s","id":"%s","severity":"%s","key":"%s","weight":%d}' \
                "$(_json_esc "${host}")" "$(_json_esc "${_area}")" "$(_json_esc "${_key}")" \
                "$(_json_esc "${_sev}")" "$(_json_esc "${_key}")" "${_weight}"
        done
        printf '\n  ],\n'
        printf '  "software_digest": {"kernel_running":"%s","kernel_full":"%s","kernel_latest_installed":"","kernel_reboot_pending":0,"kernel_tainted":"","pkgmgr_kind":"%s","pkgmgr_health":"","pkgmgr_health_note":"","pkgmgr_last_txn_epoch":"","disk_health":"","disk_full_mounts":"","disk_inode_full_mounts":"","boot_free_mb":""},\n' \
            "$(_json_esc "${kernel_running}")" "$(_json_esc "${kernel_running}")" "$(_json_esc "${pkgmgr_kind}")"
        printf '  "software_inventory_b64gz": "",\n'
        printf '  "software_inventory_meta": {"sha256":"","raw_bytes":0,"encoded_bytes":0,"encoding":"gzip+base64","note":"not collected"}\n'
        printf '}\n'
    } > "${out}"
}

# ---------------------------------------------------------------------------
# Forensic collection phases (--full only)
# ---------------------------------------------------------------------------
phase_defense() {
    _log "phase_defense: collecting host kernel/virtualization context"

    _log "phase_defense: uname -r=$(uname -r 2>/dev/null || echo unknown)"

    if command -v lsmod >/dev/null 2>&1; then
        _log "phase_defense: lsmod kvm modules: $(lsmod 2>/dev/null | grep -i kvm | tr '\n' ';')"
    fi
}

phase_offense() {
    _log "phase_offense: recording log-source timestamps for timeline context"

    local f mtime
    for f in "${KERN_LOG_FILE}" "${MESSAGES_LOG_FILE}"; do
        [[ -f "${f}" ]] || continue
        mtime="$(date -r "${f}" -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)"
        _log "phase_offense: log file ${f} mtime=${mtime}"
    done
    _log "phase_offense: dmesg/journalctl captured at ${ts} (live/volatile sources, no persistent mtime)"
}

phase_bundle() {
    local dir="${1}"
    _log "phase_bundle: collecting kernel/journal evidence into ${dir}"

    mkdir -p "${dir}/evidence"

    local dmesg_bin="${DMESG_CMD%% *}"
    if command -v "${dmesg_bin}" >/dev/null 2>&1; then
        _read_with_timeout "${LOG_READ_TIMEOUT}" ${DMESG_CMD} > "${dir}/evidence/dmesg.txt" 2>/dev/null || \
            _warn "phase_bundle: dmesg capture timed out or failed after ${LOG_READ_TIMEOUT}s"
    fi

    local journalctl_bin="${JOURNALCTL_CMD%% *}"
    if command -v "${journalctl_bin}" >/dev/null 2>&1; then
        _read_with_timeout "${LOG_READ_TIMEOUT}" ${JOURNALCTL_CMD} > "${dir}/evidence/journalctl-k.txt" 2>/dev/null || \
            _warn "phase_bundle: journalctl -k capture timed out or failed after ${LOG_READ_TIMEOUT}s"
    fi

    [[ -f "${KERN_LOG_FILE}" ]] && \
        _read_with_timeout "${LOG_READ_TIMEOUT}" cat "${KERN_LOG_FILE}" > "${dir}/evidence/kern.log" 2>/dev/null
    [[ -f "${MESSAGES_LOG_FILE}" ]] && \
        _read_with_timeout "${LOG_READ_TIMEOUT}" cat "${MESSAGES_LOG_FILE}" > "${dir}/evidence/messages" 2>/dev/null

    {
        printf 'uname -r: %s\n' "$(uname -r 2>/dev/null || echo unknown)"
        printf 'uname -a: %s\n' "$(uname -a 2>/dev/null || echo unknown)"
        printf -- '--- lsmod | grep -i kvm ---\n'
        lsmod 2>/dev/null | grep -i kvm || true
        local mod nested_path
        for mod in kvm_intel kvm_amd; do
            nested_path="${SYS_DIR}/module/${mod}/parameters/nested"
            [[ -f "${nested_path}" ]] && printf '%s nested=%s\n' "${mod}" "$(cat "${nested_path}" 2>/dev/null || echo unknown)"
        done
    } > "${dir}/evidence/kvm-context.txt"

    local bundle="${dir}/bundle-001.tar.gz"
    tar -czf "${bundle}" -C "${dir}" evidence 2>/dev/null || touch "${bundle}"

    local sha256 size_bytes
    sha256="$(sha256sum "${bundle}" 2>/dev/null | awk '{print $1}')"
    size_bytes="$(stat -c %s "${bundle}" 2>/dev/null || echo 0)"

    local host
    host="${HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
    printf '{"run_id":"%s","host":"%s","tool_version":"%s","ts":"%s","tarballs":[{"file":"bundle-001.tar.gz","sha256":"%s","size_bytes":%s}],"excluded_paths":[]}\n' \
        "${run_id}" "${host}" "${TOOL_VERSION}" "${ts}" \
        "${sha256}" "${size_bytes}" \
        > "${dir}/manifest.json"

    _log "phase_bundle: bundle=${bundle} sha256=${sha256} size=${size_bytes}"

    write_envelope "${dir}/ioc-scan-envelope.json"
    ENVELOPE_PATH="${dir}/ioc-scan-envelope.json"
    _log "phase_bundle: envelope written to ${ENVELOPE_PATH}"
}

phase_upload() {
    local dir="${1}"

    if [[ "${FLAG_LOCAL_ONLY}" -eq 1 ]]; then
        _warn "NO_UPLOAD: --local-only set; bundle retained at ${dir}"
        upload_status="false"
        return 0
    fi

    if [[ -z "${OPT_UPLOAD_URL}" ]]; then
        _warn "NO_UPLOAD: --upload-url not provided; bundle retained locally"
        upload_status="false"
        return 0
    fi

    # Wrap the bundle directory in an outer tarball — mirrors sessionscribe's
    # phase_upload exactly: tar -C <parent> -czf <dir>.upload.tgz <basename>.
    # This produces one upload artifact per host with valid gzip magic on the
    # outer wrapper and lets the collector unpack the full evidence tree.
    local outer="${dir}.upload.tgz"
    local dir_parent="${dir%/*}"
    local dir_basename="${dir##*/}"
    if ! tar -C "${dir_parent}" -czf "${outer}" "${dir_basename}" 2>/dev/null; then
        _warn "phase_upload: outer tarball build failed; bundle retained at ${dir}"
        upload_status="false"
        return 0
    fi
    chmod 0600 "${outer}" 2>/dev/null

    if [[ -n "${INTAKE_TOKEN}" ]]; then
        _log "phase_upload: uploading ${outer} with token auth"
        local resp http_code rc=0
        resp="$(curl --silent --show-error \
            --max-time 1800 \
            -H "X-Upload-Token: ${INTAKE_TOKEN}" \
            -T "${outer}" \
            -w '\n__INTAKE_HTTP__=%{http_code}' \
            "${OPT_UPLOAD_URL}" 2>&1)" || rc=$?
        http_code="$(printf '%s' "${resp}" | grep -oE '__INTAKE_HTTP__=[0-9]+' | tail -1 | cut -d= -f2)"
        if (( rc == 0 )) && [[ "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
            upload_status="true"
            _log "phase_upload: upload confirmed (http=${http_code})"
            rm -f "${outer}"
        else
            _warn "phase_upload: upload failed (rc=${rc} http=${http_code:-?}); outer tarball preserved at ${outer}"
            upload_status="false"
        fi
    else
        _log "phase_upload: uploading ${outer} to presigned URL"
        if curl -fS -X PUT --upload-file "${outer}" "${OPT_UPLOAD_URL}" 2>/dev/null; then
            upload_status="true"
            _log "phase_upload: upload confirmed"
            rm -f "${outer}"
        else
            _warn "phase_upload: curl PUT failed; outer tarball preserved at ${outer}"
            upload_status="false"
        fi
    fi
}

# ---------------------------------------------------------------------------
# phase_telemetry_post() — POST meta envelope JSON to telemetry collector.
# Transport: curl > wget. Retry with exponential backoff. Failure is advisory
# (warns to stderr but does not change exit_code or verdict).
# ---------------------------------------------------------------------------
phase_telemetry_post() {
    [[ "${TELEMETRY_MODE}" -eq 0 ]] && return 0
    [[ -z "${TELEMETRY_URL}" ]] && return 0

    # Resolve envelope source. If phase_bundle ran, ENVELOPE_PATH is set.
    # Otherwise write the envelope to a temp file for this POST only.
    local env_src="${ENVELOPE_PATH:-}"
    local _tmp_envelope=""
    if [[ -z "${env_src}" || ! -f "${env_src}" ]]; then
        _tmp_envelope="$(mktemp "${TMP_DIR}/${TOOL}-envelope.XXXXXX")"
        write_envelope "${_tmp_envelope}"
        env_src="${_tmp_envelope}"
    fi

    local env_size=0
    env_size="$(stat -c %s "${env_src}" 2>/dev/null || echo 0)"
    if (( env_size == 0 )); then
        _warn "phase_telemetry_post: envelope is empty; skipping POST"
        rm -f "${_tmp_envelope}"
        return 0
    fi
    if (( env_size > TELEMETRY_MAX_BYTES )); then
        _warn "phase_telemetry_post: envelope size ${env_size} exceeds cap ${TELEMETRY_MAX_BYTES}; skipping POST"
        rm -f "${_tmp_envelope}"
        return 0
    fi

    _log "phase_telemetry_post: POSTing ${env_size}B envelope to ${TELEMETRY_URL}"

    local attempt=0 max_attempts=$(( TELEMETRY_RETRY + 1 )) rc=0 http_code="" backoff=0
    if (( max_attempts > 11 )); then max_attempts=11; fi

    while (( attempt < max_attempts )); do
        attempt=$(( attempt + 1 ))
        rc=0; http_code=""

        if command -v curl >/dev/null 2>&1; then
            local curl_args=(
                --silent --show-error
                --max-time "${TELEMETRY_TIMEOUT}"
                -X POST
                -H "Content-Type: application/json"
                -H "User-Agent: ${TOOL}/${TOOL_VERSION}"
                -w '%{http_code}'
                -o /dev/null
                --data-binary "@${env_src}"
            )
            [[ -n "${TELEMETRY_TOKEN}" ]] && \
                curl_args+=(-H "Authorization: Bearer ${TELEMETRY_TOKEN}")
            http_code="$(curl "${curl_args[@]}" "${TELEMETRY_URL}" 2>/dev/null)" || rc=$?
        elif command -v wget >/dev/null 2>&1; then
            local wget_args=(
                --tries=1
                --timeout="${TELEMETRY_TIMEOUT}"
                --header="Content-Type: application/json"
                --header="User-Agent: ${TOOL}/${TOOL_VERSION}"
                --post-file="${env_src}"
                -O /dev/null -q
            )
            [[ -n "${TELEMETRY_TOKEN}" ]] && \
                wget_args+=(--header="Authorization: Bearer ${TELEMETRY_TOKEN}")
            wget "${wget_args[@]}" "${TELEMETRY_URL}" 2>/dev/null && http_code="200" || rc=$?
        else
            _warn "phase_telemetry_post: no HTTP transport available (need curl or wget)"
            rm -f "${_tmp_envelope}"
            return 0
        fi

        if (( rc == 0 )) && [[ "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
            _log "phase_telemetry_post: POST ok (http=${http_code} attempt=${attempt})"
            rm -f "${_tmp_envelope}"
            return 0
        fi

        _warn "phase_telemetry_post: attempt ${attempt}/${max_attempts} failed (rc=${rc} http=${http_code:-?})"
        if (( attempt < max_attempts )); then
            backoff=$(( 1 << attempt ))
            sleep "${backoff}"
        fi
    done

    _warn "phase_telemetry_post: all attempts failed; envelope not delivered to ${TELEMETRY_URL}"
    rm -f "${_tmp_envelope}"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    run_id="$(_generate_run_id)"
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    _log "starting IOC scan (mode=${MODE}, run_id=${run_id})"

    check_nested_virt_state
    check_kernel_log_iocs

    compute_verdicts
    derive_exit_code

    detail_json="$(printf '{"ioc_critical":%d,"ioc_review":%d,"advisory":%d}' \
        "${ioc_critical}" "${ioc_review}" "${advisory}")"

    if [[ "${FLAG_FULL}" -eq 1 ]]; then
        local ts_safe="${ts//:/-}"
        forensic_dir="${FORENSIC_ROOT}/.${TOOL}-forensic/${ts_safe}-${run_id}"
        mkdir -p "${forensic_dir}"

        phase_defense
        phase_offense
        phase_bundle "${forensic_dir}"
        phase_upload "${forensic_dir}"

        bundle_path_json="\"${forensic_dir}\""
    fi

    write_ledger "${upload_status}" "${bundle_path_json}"

    if [[ "${FLAG_JSONL}" -eq 1 ]]; then
        emit_signals_meta
    elif [[ "${FLAG_SUMMARY}" -eq 1 ]]; then
        emit_summary
    elif [[ "${FLAG_JSON}" -eq 1 ]]; then
        printf '['
        emit_summary
        printf ']\n'
    elif [[ "${FLAG_CSV}" -eq 1 ]]; then
        emit_csv
    else
        emit_human
    fi

    [[ "${TELEMETRY_MODE}" -eq 1 ]] && [[ -n "${TELEMETRY_URL}" ]] && phase_telemetry_post

    exit "${exit_code}"
}

main
