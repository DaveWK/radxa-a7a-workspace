# Port-bound FEL transactions

`scripts/fel_session.py` owns the transaction; `scripts/xfel-port` selects
one device for one command. Invoke the boot/reset callers rather than the
selector directly during a transaction. A boot or reset takes an exclusive
lease at `~/.cache/a7a-fel-locks/<port>.lock` under the Unix account's home
(not `$HOME`). Use the same bench account for every transaction. The lease
is independent of receipt and state paths. Different ports can run in
parallel; use private, separate state and receipt paths. Changes to other
ports are logged in the receipt, with the latest 16 retained in
`peer_history`, and cannot block the target.

```text
unverified -- discovered at requested port + A733 version ACK --> live epoch 1
live epoch -- ordinary ACK on the same port and devnum --> same live epoch
live epoch -- ACKed WDT trigger or watchdog-returning Entry 2 --> pending
pending -- new devnum on same port + A733 version ACK --> next live epoch
pending -- failed or wrong-identity probe --> still pending, abort transaction
live epoch -- ACKed workspace Entry 2 --> check mailbox/disconnect and serial
```

Attempt, ACK and verified epoch events are separate. Once the command timeout
expires, the session waits for the selector child to exit before releasing the
lease; a late exit does not count as an ACK. Do not resubmit Entry 2 to recover
from uncertain handover. Only the authorized watchdog helper sends WDT0 writes.

## Cached memtest

Use the active board's registered log and pin the reviewed SHA256 of the set's
`SHA256SUMS`. Do not copy a bench loader. Preflight verifies the closed set,
checks its load addresses, writes and reads back SRAM, runs Entry 1 and waits
for the ready mailbox. It stops before uploading any DRAM payload:

```sh
scripts/a7a-cached-run --stage preflight --port "$FEL_PORT" --state "$run/fel-state" \
    --set "$set" --expect-set-sha256 "$set_sha256" \
    --receipt "$run/receipt.json" --serial-log "$log"
scripts/a7a-cached-run --stage resume --receipt "$run/receipt.json" \
    --identity-cleared "$log:$start-$end:$slice_sha256" --expect-board "$board"
```

A bounded transaction child keeps the same lease and verified staged bytes
across both calls. From the receipt's `identity_window_start`, name exactly
the byte range containing the complete strap and size lines, and hash
`[start,end)`. Use `4g` (`CXMT 4GB` / `4096 MiB`) or `6g` (`CXMT 6GB` /
`6144 MiB`). Resume within 120 seconds of the ready mailbox using the same
receipt and its `.sha256` sidecar. The runner checks the sealed receipt,
capture generation, identity, epoch and mailbox before loading the payload.
Failure, expiry and completion all end the transaction; a receipt is not
replayable.

Resume records the Entry 2 ACK separately from its watchdog reconnect.
Reconnect alone does not confirm handover. To verify the closed serial
window offline, without another FEL command:

```sh
python3 -I scripts/fel_session.py verify-handover --receipt "$run/receipt.json"
```

## Capture boundaries

The registered log for `3-3.4` is `2026-11-18-1725-4g-luckfox.log`; for
`3-6` it is `2026-11-18-1725-6g-luckfox.log`, both under
`~/src/radxa-a7a/serial-logs/`. No tty or pty is opened. Each cursor records
device, inode, offset and SHA256 of the last 4 KiB before that offset (all
available earlier bytes if shorter). Reads reject a changed inode, a size
below the cursor or a changed prefix, including detectable copytruncate and
regrowth. Entry 2 begins its serial window at the first host cursor captured
after the ACK. Only bytes before that window's recorded end count. One RVBAR
for `00000000:40000000` must precede `main>`. Reset/failure/refusal markers,
fresh DRAM identity markers and duplicate Entry 2, warm-reset announcements
or RVBAR markers before `main>` invalidate the evidence. The expected single
`done in …, warm reset into AArch64` announcement before RVBAR is not a
failure. Fast messages received before the host's post-ACK cursor may be
excluded; do not expand the window to claim them.

An identical-prefix copytruncate and regrowth or an unmarked reset is not
observable from these long-lived regular files. This is not a producer
generation or a firmware attempt token; a separate per-boot identity gate
still applies to all cached runs.

## Exit classes

The receipt retains the selector's original exit. A nonzero selector exit
never confirms submission. After a validated Entry 2 ACK, explicit loss
during a workspace handover may still be confirmed by the bounded serial
window; no other selector failure is treated as handover.

| Session exit | Meaning | Selector origin, if applicable |
|---:|---|---|
| 0 | Requested stage, reset, or serial verification succeeded | `0` is a validated response, not proof of a later state |
| 2 | Invalid input or unready receipt or mailbox | `2` usage |
| 3 | Serial handover unconfirmed | An ACK or reconnect alone is insufficient |
| 4 | Device lost before a submission was ACKed | `66` |
| 5 | Device lost after an ACKed submission; no successful reconnect | `66`, or no new enumeration |
| 6 | ACK failure | `65` malformed or `76` rejected |
| 7 | Timeout with a live child; child reaped before return | Host deadline |
| 8 | Identity refusal | `125`, or invalid A733 identity/epoch |
| 9 | Port already leased | Local lease refusal |
| 10 | Transfer/setup I/O or unexpected selector exit | `74`, signal, or unrecognized exit |
