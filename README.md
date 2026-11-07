/ram helps the user see which processes are using RAM unnecessarily, so they can close them and keep RAM for the needs of the moment. App names, RAM use, purpose details and closing guidance help you decide what to keep running.

# pi-ram-meters

A Windows RAM dashboard and process-control picker for [pi](https://pi.dev/).

Run /ram to inspect memory and choose app/root process trees to close. Every program uses the same process-identity and tree logic. Names, descriptions and danger colours are display guidance; there is no supported-program list or product-specific stop command.

Descriptions use available program labels, entrypoints and local agent or folder context. Unknown work stays caution; labels do not authorize closure.

![Process picker with synthetic demo data](assets/ram-demo.png)

The image contains synthetic data rendered by the extension, with no live process or session information.

## Install

    pi install git:github.com/Quigleybits/pi-ram-meters-extension@v0.2.0

Restart Pi after installing or updating. A running session can retain an older command handler after `/reload`.

Requirements: Windows, Windows PowerShell 5.1 and Node.js 22.19 or newer. No program-specific tools are required. Linux and macOS are not supported. Distribution is through GitHub; this version is not published on npm.

## Choose app/root trees

    /ram
    /ram --read-only

The table shows eligible app/root trees in descending RAM order in one scrolling list, with names, purposes, working-set sums, private-byte footprints and relative bars. PID and process-count columns are omitted from the list; the actual identities and counts remain in the closure review.

Space checks a group. Up and Down move through the list, and `/` searches it. Selections remain checked across search and scrolling. Tab or End jumps to Kill; Enter there reviews the selected roots and offers End task or End process tree. Tab itself does not select or close anything. A separate unsaved-data confirmation starts on Cancel. Esc cancels. There is no automatic ancestor expansion.

Row text uses green for lower closing risk, orange for caution and red for high risk. Colours are guidance, not a guarantee that an app has no unsaved work. Save documents, forms and other work before confirming. The Pi process running this command and its controlling ancestors cannot be selected.

Each row is a verified process tree, not a promise that every member belongs to one product. Independent instances stay separate. Known OS shell, service, critical, controller and other-user scopes are excluded; missing identity, access or role facts withhold the whole group. A group can contain other programs launched by its root.

| Mode | Effect |
| --- | --- |
| End task | Requests closure of the confirmed roots' windows, then forcibly terminates original roots that remain after fresh safety checks. A save prompt or no visible window does not prevent the confirmed fallback. Children are not directly forced and can remain. |
| End process tree | Forcibly terminates confirmed roots and all verified descendants in their scope, including GUI processes and newly verified children. Parents stop before children. There is no save opportunity. |

Both modes can lose unsaved work or interrupt active tasks. Review the root PIDs, counts and scope before confirming. The confirmed roots do not expand to an ancestor, unrelated instance or entire Windows session.

## Memory figures

GB uses decimal bytes: 1 GB = 1,000,000,000 bytes.

- Free / total RAM is available physical memory and total physical memory.
- Working set is the sum over unique group members, including shared pages, and is not exclusive physical RAM.
- Private bytes are a separate process allocation measure. Any release estimate derived from them is not guaranteed recovered physical RAM, especially when End task leaves children.
- Unknown measurements remain unknown. Different measures are not added together.

## Results and limits

The extension validates PID, birth, image, session and account facts and uses retained process handles. Generic OS critical-process, permission and controller checks apply. The active RAM controller and its controlling ancestors are protected; other programs do not receive name-based exemptions. There is no automatic elevation.

Tree mode adopts only newly verified descendants of confirmed roots while its bounded operation is healthy. Unrelated roots are excluded. Missing ancestry, denied access, reused PIDs, unsafe descendants or exhausted budgets produce partial or unconfirmed results instead of silently pruning a tree and claiming success. No automatic retry follows a failed or uncertain result.

After execution, separated read-only process samples report survivors, new verified lineage and incomplete observation over a stated bounded interval. If an outside supervisor starts a replacement after all known lineage ends, ancestry may not prove that association. The tool does not infer respawn from an image or program name, promise semantic application shutdown, or detect every later or short-lived restart.

Read-only and noninteractive/RPC use display measurements without close actions. There is no background cleanup, polling, telemetry, saved process log or agent-callable termination tool. Local command-line entrypoints may supply display labels; raw arguments are discarded and never authorize closure. Optional local Herdr metadata supplies agent or folder context. Pi itself has separate configuration and behavior.

## License

MIT. Copyright 2026 quigleybits.
