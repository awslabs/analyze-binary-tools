#!/usr/bin/env bash
# Copyright (C) 2019 Amazon.com, Inc. or its affiliates.
# Author: Pawel Wieczorkiewicz <wipawel@amazon.de>
#

# fail early, fail hard
set -E -e -u

declare -ir NO_EXEC_SECTION_RC=3
declare -ir NO_DISAS_SECTION_RC=4

declare -i TERMINAL_COLORS=0

trap '[ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"' EXIT
TMP_DIR="$(readlink -e "$(mktemp -d)")"
declare -r TMP_DIR

declare -i VERBOSE=0

log ()
{
    local -i LEVEL=$1
    shift

    if [ $VERBOSE -ge "$LEVEL" ]; then
        echo -e "$*"
    fi
}

err ()
{
    local RED=''
    local NC=''

    if [ $TERMINAL_COLORS -eq 1 ]; then
	RED='\033[0;31m'
	NC='\033[0m' # Default terminal's colors
    fi

    log 0 "${RED}$*${NC}"
}

warn ()
{
    local -i LEVEL=$1
    shift

    local YELLOW=''
    local NC=''

    if [ $TERMINAL_COLORS -eq 1 ]; then
	YELLOW='\033[1;33m'
	NC='\033[0m' # Default terminal's colors
    fi

    log $LEVEL "${YELLOW}$*${NC}"
}

usage ()
{
    cat<<EOF
Script checking whether any specified sections' (by default: .init) objects
are referenced by any other sections' (by default: non-init) functions.

Usage: $0 [OPTIONS] <FILE>

  - FILE: input binary with symbols (e.g. vmlinux).
  - Options
    -h ......... Print this help.
    -c ......... Enable terminal colors.
    -f FILE..... File with grep-supported patterns (one per line)
                 to filter out.
    -v ......... Increase verbosity level (can be specified multiple times).
    -s PATTERN.. Section name pattern to be checked against.
    -w FILE..... Whitelisted symbols file with entries (one per line)
                 to be excluded from analysis.
    -W FILE..... Append whitelist entries to a specified file for all
                 current findings.

  Example:
     $0 ~/xen-syms
     $0 ~/git/linux/vmlinux
EOF
}

detect_file_type ()
{
    local -r FILE="$1"

    readelf -Wh "$FILE" | awk '/^[[:blank:]]*Class:/ {print $NF}'
}

get_section_by_flag ()
{
    local -r FILE="$1"
    local -r FLAG="$2"

    readelf -W -t "$FILE" | grep -E " \[.*\] |ALLOC" | grep -B1 "$FLAG" | awk '/[.*]/ {print $NF}'
}

get_section_symbols ()
{
    local -r SECTION="$1"
    local -r FILE="$2"
    local -r TYPE="$3"
    local INVAL_SYM_PATTERN=

    case $TYPE in
    ELF32) INVAL_SYM_PATTERN=00000000 ;;
    ELF64) INVAL_SYM_PATTERN=0000000000000000 ;;
    esac

    objdump -w -t -j "$SECTION" "$FILE" | grep -v $INVAL_SYM_PATTERN | \
        awk '/SYMBOL TABLE:/ {seen = 1; next} seen && $NF {printf "%s:%s\n",$1,$NF}'
}

is_whitelisted ()
{
    local -r FILE="$1"
    local -r NO_MATCH_SEC="$2"
    local -r NO_MATCH_FUNC="$3"
    local -r MATCH_SYM="$4"
    local -r MATCH_SEC="$5"

    local -r ENTRY_PATTERN="${NO_MATCH_SEC}[[:blank:]]+${NO_MATCH_FUNC}[[:blank:]]+${MATCH_SYM}[[:blank:]]+${MATCH_SEC}"
    [ -z "$FILE" ] && return 1

    # Whitelist entry example: .text csched_global_init register_cpu_notifier .init.text
    grep -qE "$ENTRY_PATTERN" "$FILE"
}

filter_out_patterns ()
{
    local -r PATTERN_FILE="$1"

    grep -v -E "$(grep -v -E '^#' "$PATTERN_FILE")"
}

find_references ()
{
    local -r FILE="$1"
    local -r PATTERN_FILE="$2"
    local -r REF="$3"

    grep -E "<.*>:|$REF" "$FILE" | ([ -n "$PATTERN_FILE" ] && filter_out_patterns "$PATTERN_FILE" || cat) | grep -B1 "$REF"
}

#
# Handle input parameters
#
SEC_PATTERN="init"
WHITELIST_FILE=
OUTPUT_WHITELIST_FILE=
FILTER_PATTERNS_FILE=
while getopts "hcf:vs:w:W:" OPT
do
    case $OPT in
        h)
            usage
            exit 0
            ;;
        c)
            TERMINAL_COLORS=1
            ;;
        f)
            FILTER_PATTERNS_FILE=$(readlink -e "$OPTARG")
            if [ ! -s "$FILTER_PATTERNS_FILE" ]; then
                log 0 "Error: Unknown patterns file: $FILTER_PATTERNS_FILE."
                exit 2
            fi
            ;;
        v)
            VERBOSE+=1
            ;;
        s)
            SEC_PATTERN="$OPTARG"
            ;;
        w)
            WHITELIST_FILE=$(readlink -f "$OPTARG")
            if [ ! -s "$WHITELIST_FILE" ]; then
                log 0 "Error: Unknown whitelist file: $WHITELIST_FILE."
                exit 2
            fi
            ;;
        W)
            OUTPUT_WHITELIST_FILE=$(readlink -f "$OPTARG")
            if [ -e "$OUTPUT_WHITELIST_FILE" ] && [ ! -w "$OUTPUT_WHITELIST_FILE" ]; then
                log 0 "Error: Unable to write to the whitelist file: $OUTPUT_WHITELIST_FILE."
                exit 2
            fi
            ;;
        \?)
            log 0 "Invalid option: -$OPT"
            exit 2
            ;;
        :)
            log 0 "Option -$OPT requires an argument."
            exit 2
            ;;
    esac
done

shift $(( OPTIND - 1 ))

if [ $# -ne 1 ]; then
    usage
    exit 2
fi

SYM_FILE="$(readlink -e "$1")"
declare -r SYM_FILE
if [ ! -s "$SYM_FILE" ]; then
    log 0 "Error: Unable to find binary file: $SYM_FILE."
    exit 2
fi

if [[ $(file "$SYM_FILE") != *"not stripped" ]]; then
    log 0 "Error: Specified binary file does not have symbols: $SYM_FILE."
    exit 2
fi

declare -r FILE_TYPE=$(detect_file_type "$SYM_FILE")
if [ "$FILE_TYPE" != "ELF64" ] && [ "$FILE_TYPE" != "ELF32" ]; then
    log 0 "Error: Unsupported file format: $FILE_TYPE for $SYM_FILE. Only ELF64|32 binaries are supported."
    exit 2
fi

warn 2 "Analyzing file: $SYM_FILE ($FILE_TYPE)"

pushd "$TMP_DIR" > /dev/null || exit 1
warn 1 "Working directory: $TMP_DIR"

# Get all code sections NOT matching the specified name pattern
read -r -a NO_MATCH_EXEC_SECTIONS <<< $(get_section_by_flag "$SYM_FILE" EXEC | grep -v "$SEC_PATTERN")
if [ "${#NO_MATCH_EXEC_SECTIONS[@]}" -eq 0 ]; then
    log 0 "Error: No exec section found in $SYM_FILE."
    exit $NO_EXEC_SECTION_RC
fi
warn 2 "No match exec sections: ${NO_MATCH_EXEC_SECTIONS[*]}"

# Get all sections matching the specified name pattern
read -r -a MATCH_SECTIONS <<< $(get_section_by_flag "$SYM_FILE" ALLOC | grep "$SEC_PATTERN")
if [ "${#MATCH_SECTIONS[@]}" -eq 0 ]; then
    log 1 "No match section found in $SYM_FILE. Ignoring..."
    exit 0
fi
warn 2 "Match sections: ${MATCH_SECTIONS[*]}"

# Counter limiting number of child processes created to what bash supports.
declare -i COUNTER=0
declare -i BASH_PROC_LIMIT=32

# Proactively disassemble the non-matching code sections (this saves time later).
for ni_sec in "${NO_MATCH_EXEC_SECTIONS[@]}"; do
    objdump -w -r -D -j "$ni_sec" "$SYM_FILE" > "$ni_sec.txt" 2> /dev/null &
    # Limit number of background child processes to $BASH_PROC_LIMIT
    COUNTER=$((COUNTER + 1))
    if [ $COUNTER -eq $BASH_PROC_LIMIT ]; then
        COUNTER=0
        wait
    fi
done

wait

# Check if objdump is able to disassemble
for ni_sec in "${NO_MATCH_EXEC_SECTIONS[@]}"; do
    if ! grep -q -F "Disassembly" "$ni_sec.txt"; then
        log 0 "Error: objdump unable to disassemble section $ni_sec of $SYM_FILE"
        exit $NO_DISAS_SECTION_RC
    fi
done

COUNTER=0

# Process all specified matching sections, looking for references
# from the non-matching sections.
for sec in "${MATCH_SECTIONS[@]}"; do
    # Get all symbols for the currently processed matching section
    readarray -t MATCH_SYMBOLS < <(get_section_symbols "$sec" "$SYM_FILE" "$FILE_TYPE")

    # Ignore the section, when there is no symbols.
    [ "${#MATCH_SYMBOLS[@]}" -eq 0 ] && continue

    # Check if any of the section's symbols is referenced by
    # other non-matching sections.
    for sym in "${MATCH_SYMBOLS[@]}"; do
        # Get symbol's address and name
        read -r -a SPLIT <<< ${sym//:/ }
        SYM_ADDR=${SPLIT[0]}
        SYM_NAME=${SPLIT[1]}

        # Look for references in all non-matching sections.
        for ni_sec in "${NO_MATCH_EXEC_SECTIONS[@]}"; do
            # If nothing found, ignore the section...
            FOUND=$(find_references "$ni_sec.txt" "$FILTER_PATTERNS_FILE" "$SYM_ADDR") || continue

            # ... otherwise, grab all function names...
            FUNC=$(echo "$FOUND" | xargs -n1 | grep -E '<.*>:' | xargs | tr -d '<>:')
            OUTPUT_FILE=$(mktemp -p "$TMP_DIR" --suffix=.out)

            # ... and check whether, given function-symbol combination has been whitelisted.
            for f in $FUNC; do
                if is_whitelisted "$WHITELIST_FILE" "$ni_sec" "$f" "$SYM_NAME" "$sec"; then
                    log 2 "Ignoring: $f [$ni_sec] <- $SYM_NAME [$sec]"
                    continue
                else
                    # Display finding.
                    err "$SYM_FILE: In $ni_sec $f found $SYM_NAME from $sec"
                    log 1 "$(echo "$FOUND" | sed -n "/<$f>:/,/--/p" | grep -v -E '^[-]+$')"

                    # Append to an output whitelist file (if specified).
                    [ -n "$OUTPUT_WHITELIST_FILE" ] && echo "$ni_sec $f $SYM_NAME $sec" >> "$OUTPUT_WHITELIST_FILE"

                    touch fail
                fi
            done > "$OUTPUT_FILE"
        done &
        # Limit number of background child processes to $BASH_PROC_LIMIT
        COUNTER=$((COUNTER + 1))
        if [ $COUNTER -eq $BASH_PROC_LIMIT ]; then
            COUNTER=0
            wait
        fi
    done
    wait
done

# Collect all output files created in parallel and display content.
find "$TMP_DIR" -name \*.out -exec cat {} ';'

# Script return code variable
declare -i RET=0

[ -f fail ] && RET=1
popd > /dev/null
exit $RET
