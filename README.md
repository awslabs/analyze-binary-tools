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

## License

This project is licensed under the Apache-2.0 License.
