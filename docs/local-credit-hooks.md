# Local commit-credit hooks

The local pre-push entry runs the commit-ancestry audit directly, before any file-based hook selection. An empty file diff does not select the audit out. The guard's identity, message and ancestry rules are unchanged.

The installer accepts the reviewed configuration with no remaining pre-push jobs. It preserves existing application pre-commit and commit-message checks. The earlier pre-push shim is archived as evidence, not dispatched recursively. An unexpected configuration or downstream job needs review.

## Installation revisions

Installation preserves earlier hooks, guard files and receipts in an exclusive revision archive. A durable pending marker and rejecting pre-push sentinel precede active changes. New dependencies and the receipt are durable before the final wrapper replaces that sentinel. An interrupted revision stays blocked and requires review; it does not fall back to the earlier audit-skipping route. The pinned runner generates remaining hooks and authentic scheduler state in private staging with exact target config bytes and mtime. Only independently admitted deterministic shim outputs and authentic scheduler bytes are installed under the rejecting sentinel, then the wrapper is installed last. No generic reinstall runs over active hooks. Old hook semantics remain; old bytes and scheduler state are archived.

The generated wrapper binds its manifest and admission module. It opens bounded ordinary files without following their final symlink component and executes the verified module bytes. The manifest binds configuration, dependencies and host tools. Receipts describe those bindings; editing a receipt cannot authorize different hashes. Local overrides and custom hook paths are rejected.

The publishing procedure must independently admit the wrapper and host interpreter before invoking Git. A local hook cannot prove its own interpreter trustworthy or prevent someone with write access from replacing or bypassing the hook. This is a checked-publishing-checkout safeguard, not universal tamper prevention. Server protection remains a separate boundary.

## Qualification

Run the integration module with `CREDIT_TEST_LEFTHOOK` naming the reviewed Lefthook executable:

    python3 .credit-guard/test_prepush_admission.py

The module uses disposable repositories to exercise the generated hook, same-tree candidate ancestry, rejected identities, malformed input, post-install changes and interrupted migration. Run the applicable repository lint, formatting, type and ordinary tests as well. A source description is not evidence that checks passed. Preserve failures and review the exact candidate before publication.

## Checked installation caller

This repair migrates a complete previously qualified installation. A missing or unknown earlier installation is refused, not recreated by observing current files. The caller must supply independently reviewed expected source/tool hashes, repository path, earlier hook and guard hashes, the exact earlier configuration bytes and reviewed new configuration hash. The caller first verifies the installer itself and its Python/YAML runtime against that external review. Do not generate expected production hashes from the files about to be trusted. Test fixtures deliberately supply their own prior-state expectations before mutation.

The earlier stable commit-message guard launcher and its per-use dependency checks are preserved and included in the new runtime manifest; generated scheduler shims use independently expected new bytes. Earlier configuration comes from the admitted prior receipt lineage, not the already edited working configuration. The new receipt has its own wrapper-bound expected hash; changing or removing it blocks admission without letting it choose trusted pins.

Directory components are opened relative to no-follow directory descriptors. Reads verify ordinary bounded final descriptors and before/after file identity/size/timestamp. The controlled checkout and its private installation must be exclusively held while publication runs. Hostile concurrent writers and replacement of host executables after external admission are outside this guarantee; hashing a file does not freeze a later subprocess pathname open. No arbitrary-concurrent-writer claim is made.

## Normal commit synchronization

The runtime manifest binds the remaining generated hook bytes and scheduler checksum state, not only pre-push. Private generation uses the exact admitted runner path so legitimate normal commit execution does not change embedded fallback paths. The real runner produces the scheduler checksum; the installer never fabricates it or disables automatic synchronization. Config mtime is copied to private staging for authentic timestamp semantics. A later change to configuration, scheduler or hook bytes still fails closed and needs a reviewed installation revision. Qualification includes old scheduler state, differing historical fallback path, migration, a normal positive commit with all applicable hooks and then actual pre-push entry admission, plus cache generation and changed scheduler rejection.

## Git hook environment

Git exports its built-in executable directory as GIT_EXEC_PATH and prepends it to PATH when invoking hooks. Admission accepts only the exact built-in directory queried from the independently pinned Git with that inherited variable removed. A PATH-resolved git in that directory must have the same pinned executable bytes. Other values, similarly named overrides and changed executables fail closed. Other override checks are unchanged. Qualification performs a real ordinary push to a disposable local bare repository, verifies the automatic full-ancestry audit and received tip, and rejects a changed executable-directory override with no remote ref created. This fixture does not publish externally.
