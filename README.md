## Tool: [check-init](https://github.com/awslabs/analyze-binary-tools/tree/master/check-init)

This script analyzes input ELF binary and checks if any of the specified sections contain objects that are also referenced by functions from any other sections.
By default the script checks for `.init` sections references from non-init sections.

### Usage

```text
Usage: ./check-init-references.sh [OPTIONS] <FILE>

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
```

#### Example

* Basic usage
  - `./check-init-references.sh ~/xen-syms`

  - `./check-init-references.sh ~/git/linux/vmlinux`

---

## Tool: [IDA Plugin check-init](https://github.com/awslabs/analyze-binary-tools/tree/master/check-init/ida_plugin)

This IDA plugin opens a window with a generated list of all references from non-init sections' functions to .init     sections. Each function referencing .init sections' symbols is preceded with a list of its own callers.

### Output format

```
SECTION    ADDRESS    CALLER
    SECTION    ADDRESS    FUNCTION_REFERENCING_INIT_SYMBOL
        ADDRESS    INSTRUCTION_WITH_SYMBOL    SYMBOL_SECTION    SYMBOL_ADDRESS
```

### Example

![IDA plugin example](https://github.com/awslabs/analyze-binary-tools/blob/master/check-init/ida_plugin/ida_plugin.png)

### Usage

Either run the plugin `Check .init references` from `Edit / Plugins` or use shortcut `Alt + F8`.

All addresses and symbol names are double-clickable (jump to corresponding disassembly).

### Installation

**Only IDA v7.4 or later is supported**

Just copy the `check-init-references.py` to (either/or):
  * IDA's plugin directory
  * your user's plugin directory (e.g. `~/.idapro/plugins`).

---

## License

This project is licensed under the Apache-2.0 License.
