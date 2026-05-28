# Publisher descriptor-regen units

`anon-service publish` reads `descriptor.bin` once at start and never rewrites
it. Without periodic regeneration the on-disk descriptor expires (default
24 h lifetime) and clients can no longer route to the service even though
the publisher process is healthy. That's what bit us on 2026-05-23 when
both `anona4y4...anon` (outer) and `6njbnyc...anon` (inner, chained) silently
went stale.

These templates wire a systemd timer that re-runs `anon-service init` on
a schedule, restarts the publisher to pick up the new bytes, and (for the
outer case) re-triggers the HSDir upload.

## Layout

  * `regen-outer-script.template` — for docker-based publisher (e.g. the
    `anon-publisher-anona4y4` container from `deploy/compose/`).
  * `regen-inner-script.template` — for host-based publisher (e.g. the
    `anon-inner-publisher.service` on the content origin).
  * `*.service.template` / `*.timer.template` — install into
    `/etc/systemd/system/` after substituting paths/IDs.

## IP fingerprint policy

Both scripts read the IP fingerprint from the existing `descriptor.bin`
and reuse it. This preserves continuity (clients with cached descriptors
still find the service at the same intro point) and avoids needing
operator config. If that relay is no longer in the consensus, `init`
will fail loudly — fix by picking a fresh fingerprint manually.

## Schedule

12 h interval pairs with the 24 h default lifetime — at most 12 h
between renewals, so the descriptor is always less than 12 h into its
lifetime when re-uploaded. Tune `OnUnitActiveSec=` if you change the
descriptor lifetime.
