# Cross-platform Behavior

Runtime requires Python 3.11+ and uses only the standard library. All business calls use `-B` and explicit UTF-8 serialization.

- Windows prefers a verified `python`, with `py -3.11` only as a launcher fallback before the business command.
- POSIX prefers `python3.11`, then another verified 3.11+ executable.
- The script path comes from the installed Skill root; project root comes from invocation CWD/Git.
- All subprocess calls use argv lists and `shell=False`.
- Path handling covers cross-drive containment, UNC/device paths, NTFS ADS, reserved names, trailing spaces/dots, symlinks, junction/reparse points and hardlinks.
- Temporary test files use the system temporary directory; runtime creates no temporary request, cache, digest or report file.
