//! 60.42 --credit-pace: no upload CONTINUE while the stream's own target is parked on its client's output
//! (Target::blocked: the client's pending output reached out_high, or its socket was full after a splice). A full-duplex
//! stream whose download is limited by the client (echo, a proxied bidirectional bulk transfer) then cannot push more
//! upload into the loop than its download drains: without it the target, its peer and our target socket fill with
//! replies the client has not taken (echo 10x10 on a 2-vCPU / 3.8 GB box: 215 MiB of kernel socket memory, host
//! tcp_mem pressure for the whole run, the client sockets' send buffers moderated to ~10 KiB, 30.19 Notes).
//! Release rule (strict): a held grant is re-decided when the target, resumed after its client's output drained below
//! out_low, reads without parking again (to EAGAIN under out_high, or its read budget ran out). Every unpark goes through
//! Worker::resume, so that is the only release point (no list, no per-turn scan). Releasing when the client merely drained the output queued at the hold, or after a timer
//! without client progress, kept the pressure (spike, docs/summaries/60.42-credit-pace.md).
//! Deadlock check (bench/probes/writeall.py): a client that stops reading its socket cannot receive a CONTINUE in either
//! build (it waits behind the unread DATA), so pacing stalls no transfer that completes without it.
//! Upload-only and download-only streams never hold: a stream without replies never parks, one without upload has no
//! grant due. The park is per connection (the client's whole pending output), so a stream that receives data is also
//! paced while other streams' downloads fill that connection's output (review r1 P3: documented, by design). Off: the side vectors stay empty; after_write tests one Config bool.

use super::*;

/// per target slot (Worker::cpace_st, a side vector: Target unchanged); `g1` = the target's generation + 1 (0 = never)
#[derive(Clone, Copy, Default)]
pub(super) struct PaceSt {
    pub(super) g1: u32,
    pub(super) held: bool, // a grant is held until the target runs again (pace_resume)
    rel: bool,             // pace_resume is re-deciding a held grant (PACE_RELEASED)
}

pub(super) const PACE_GO: u8 = 0;
pub(super) const PACE_HOLD: u8 = 1;
pub(super) const PACE_RELEASED: u8 = 2;

impl Worker {
    /// at a due grant of TCP stream `ti`: PACE_HOLD = hold it (its target is parked; pace_resume re-decides it),
    /// PACE_RELEASED = grant, re-decided by pace_resume after a hold (the client ran dry because of us: credit v2 must
    /// not count it as starvation, which would grow the window, review r1 P2), PACE_GO = grant
    pub(super) fn pace_hold(&mut self, ti: u32) -> u8 {
        let tg = self.targets.gen(ti);
        let blocked = self.targets.at(ti).blocked;
        let i = ti as usize;
        if self.cpace_st.len() <= i {
            self.cpace_st.resize(i + 1, PaceSt::default());
        }
        let s = &mut self.cpace_st[i];
        let g1 = tg.wrapping_add(1);
        if s.g1 != g1 {
            *s = PaceSt { g1, held: false, rel: false };
        }
        if !blocked {
            s.held = false;
            return if std::mem::take(&mut s.rel) { PACE_RELEASED } else { PACE_GO };
        }
        if !s.held {
            s.held = true;
            self.stats.cpace_holds.bump();
        }
        PACE_HOLD
    }

    /// after a parked target was resumed (Worker::resume): if it read without parking again (drained to EAGAIN under
    /// out_high, or its read budget ran out), re-decide its held grant
    pub(super) fn pace_resume(&mut self, ti: u32, tg: u32) {
        let Some(t) = self.targets.get(ti, tg) else { return };
        if t.blocked {
            return; // (parked again: after_write would hold it again anyway; this skips the call)
        }
        let Some(s) = self.cpace_st.get_mut(ti as usize) else { return };
        if s.g1 != tg.wrapping_add(1) || !s.held {
            return;
        }
        (s.held, s.rel) = (false, true);
        self.after_write(ti); // (may hold again)
        if let Some(s) = self.cpace_st.get_mut(ti as usize) {
            s.rel = false; // (no grant was due: the next one is an ordinary decision)
        }
    }
}
