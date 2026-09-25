//! Optional multi-threaded tree computation (pqctoday-hsm addition, feature `parallel`).
//!
//! Signing and key generation are dominated by building Merkle subtrees, and most of those
//! subtrees are independent of one another:
//!
//! * every FORS authentication node depends only on SK.seed, PK.seed, ADRS and the digest;
//! * every hypertree authentication node on layer `j` depends only on SK.seed, PK.seed and
//!   that layer's tree/leaf index, both taken straight from the message digest. Only the
//!   WOTS+ signature of layer `j` needs the root of layer `j − 1`, and that part (at most
//!   `len` chains per layer) stays serial;
//! * the top-layer tree built by key generation splits into independent subtrees.
//!
//! This module computes those nodes on several threads BEFORE the unchanged serial algorithm
//! runs; the serial code then takes each node from the table instead of computing it
//! (`fors::fors_sign` and `hypertree::ht_sign` take an `auth_node` provider for this). Every
//! node is computed by the same function, with the same address, as the serial path would
//! use, so the output is byte-identical; only the order of the hash calls changes.
//!
//! Without the feature (`no_std`, e.g. wasm32) the entry points return `None` and the serial
//! path runs exactly as before.
//!
//! With it, threads come from ONE process-wide core budget of `available_parallelism()`
//! (owner decision 2026-09-24): every SLH-DSA keygen/sign in flight counts its own calling
//! thread against the budget for its whole duration ([`enter`]), and an operation may add
//! an extra worker thread only while `callers + extra threads` stays within the budget. So
//! when one signature runs alone it gets every spare core, and when as many operations as
//! cores run at once they all run serially instead of oversubscribing the machine. Tokens are
//! taken one at a time and without blocking, each time the calling thread picks its next
//! subtree, and a helper returns its token as soon as there is no work left for it — so a
//! token freed by one finished signature goes to whichever one is still running.
//! `FIPS205_THREADS`, when a positive integer, caps the threads of ONE operation (caller
//! included); `FIPS205_THREADS=1` always runs the original serial path.

#[cfg(not(feature = "parallel"))]
use crate::hashers::{Hashers, PkSeed};
#[cfg(not(feature = "parallel"))]
use crate::types::Adrs;


/// Authentication paths of one signature, computed ahead of the serial algorithm:
/// `fors[i][z]` is FORS tree `i`'s node at height `z`, `ht[j][z]` hypertree layer `j`'s.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))] // only built with `parallel`
pub(crate) struct SignNodes<
    const A: usize,
    const D: usize,
    const HP: usize,
    const K: usize,
    const N: usize,
> {
    pub(crate) fors: [[[u8; N]; A]; K],
    pub(crate) ht: [[[u8; N]; HP]; D],
}


#[cfg(not(feature = "parallel"))]
#[allow(clippy::similar_names, clippy::too_many_arguments)]
pub(crate) fn sign_nodes<
    const A: usize,
    const D: usize,
    const H: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const M: usize,
    const N: usize,
>(
    _hashers: &Hashers<K, LEN, M, N>, _md: &[u8], _sk_seed: &[u8], _pk_seed: &PkSeed<N>,
    _fors_adrs: &Adrs, _idx_tree: u64, _idx_leaf: u32,
) -> Result<Option<SignNodes<A, D, HP, K, N>>, &'static str> {
    Ok(None)
}


#[cfg(not(feature = "parallel"))]
#[allow(clippy::similar_names)]
pub(crate) fn xmss_root<
    const H: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const M: usize,
    const N: usize,
>(
    _hashers: &Hashers<K, LEN, M, N>, _sk_seed: &[u8], _pk_seed: &PkSeed<N>, _adrs: &Adrs,
) -> Option<[u8; N]> {
    None
}


/// Registration of one keygen/sign in progress (no-op without the `parallel` feature).
#[cfg(not(feature = "parallel"))]
pub(crate) struct CallerGuard;

/// Registers the calling thread of one keygen/sign against the core budget until the
/// returned guard is dropped (no-op without the `parallel` feature).
#[cfg(not(feature = "parallel"))]
pub(crate) fn enter() -> CallerGuard { CallerGuard }


#[cfg(feature = "parallel")]
pub(crate) use threaded::{enter, sign_nodes, xmss_root};

#[cfg(feature = "parallel")]
pub use threaded::budget_stats;


#[cfg(feature = "parallel")]
mod threaded {
    use super::SignNodes;
    use crate::hashers::{Hashers, PkSeed};
    use crate::helpers::base_2b;
    use crate::types::Adrs;
    use crate::{fors, xmss};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::vec::Vec;


    /// Size of the process-wide budget (0 = not yet read; then `available_parallelism()`).
    static BUDGET: AtomicUsize = AtomicUsize::new(0);
    /// Calling threads of operations in flight plus the extra workers they hold.
    static IN_USE: AtomicUsize = AtomicUsize::new(0);
    /// Instrumentation for tests and diagnostics: largest `IN_USE` right after a grant of
    /// extra threads, and the largest number of extra worker threads alive at once.
    static MAX_AT_GRANT: AtomicUsize = AtomicUsize::new(0);
    static LIVE_EXTRA: AtomicUsize = AtomicUsize::new(0);
    static PEAK_EXTRA: AtomicUsize = AtomicUsize::new(0);

    fn budget() -> usize {
        match BUDGET.load(Ordering::Relaxed) {
            0 => {
                let n = std::thread::available_parallelism().map_or(1, core::num::NonZeroUsize::get);
                // Racing first readers compute the same value; keep whichever lands first.
                let _ = BUDGET.compare_exchange(0, n, Ordering::Relaxed, Ordering::Relaxed);
                BUDGET.load(Ordering::Relaxed)
            }
            n => n,
        }
    }

    /// Threads ONE operation may use at most (caller included): the budget, capped by
    /// `FIPS205_THREADS` when that is a positive integer.
    fn per_operation_cap() -> usize {
        let budget = budget();
        match std::env::var("FIPS205_THREADS").ok().and_then(|v| v.trim().parse::<usize>().ok()) {
            Some(n) if n >= 1 => n.min(budget),
            _ => budget,
        }
    }


    /// The calling thread of one keygen/sign, counted against the budget until dropped.
    pub(crate) struct CallerGuard(());

    impl Drop for CallerGuard {
        fn drop(&mut self) { let _ = IN_USE.fetch_sub(1, Ordering::AcqRel); }
    }

    /// Registers the calling thread of one keygen/sign against the budget. Never blocks and
    /// never fails: a caller always runs, at worst serially.
    pub(crate) fn enter() -> CallerGuard {
        let _ = IN_USE.fetch_add(1, Ordering::AcqRel);
        CallerGuard(())
    }


    /// Extra worker threads taken from the budget; returned when dropped.
    struct ExtraGrant(usize);

    impl Drop for ExtraGrant {
        fn drop(&mut self) {
            if self.0 > 0 {
                let _ = IN_USE.fetch_sub(self.0, Ordering::AcqRel);
            }
        }
    }

    /// Takes ONE extra-thread token if `IN_USE` (callers registered by [`enter`], this one
    /// included, plus every extra thread held) is below the budget. Non-blocking.
    fn take_one() -> Option<ExtraGrant> {
        let budget = budget();
        let mut cur = IN_USE.load(Ordering::Acquire);
        loop {
            if cur >= budget {
                return None;
            }
            match IN_USE.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    let _ = MAX_AT_GRANT.fetch_max(cur + 1, Ordering::Relaxed);
                    return Some(ExtraGrant(1));
                }
                Err(actual) => cur = actual,
            }
        }
    }


    /// Test and diagnostic hooks for the process-wide core budget (pqctoday-hsm). Not part of
    /// the FIPS 205 API; the numbers are process-global.
    #[doc(hidden)]
    pub mod budget_stats {
        use super::{BUDGET, IN_USE, LIVE_EXTRA, MAX_AT_GRANT, PEAK_EXTRA};
        use core::sync::atomic::Ordering;

        /// Overrides the budget size (normally `available_parallelism()`); for tests.
        pub fn set_budget(n: usize) { BUDGET.store(n.max(1), Ordering::Relaxed); }

        /// Resets the peak counters.
        pub fn reset() {
            MAX_AT_GRANT.store(0, Ordering::Relaxed);
            PEAK_EXTRA.store(0, Ordering::Relaxed);
        }

        /// Largest (callers + extra threads) in use right after any grant of extra threads.
        #[must_use]
        pub fn max_in_use_at_grant() -> usize { MAX_AT_GRANT.load(Ordering::Relaxed) }

        /// Largest number of extra worker threads alive at the same time.
        #[must_use]
        pub fn peak_extra_threads() -> usize { PEAK_EXTRA.load(Ordering::Relaxed) }

        /// Callers plus extra threads currently counted against the budget.
        #[must_use]
        pub fn in_use() -> usize { IN_USE.load(Ordering::Relaxed) }

        /// Extra worker threads alive right now.
        #[must_use]
        pub fn live_extra_threads() -> usize { LIVE_EXTRA.load(Ordering::Relaxed) }
    }


    /// Computes `job(i)` for every `i` in `0..n` and returns the results in index order. The
    /// calling thread works through the jobs itself and, before each one, adds a helper thread
    /// for every spare token the budget has (at most `max_extra` helpers in total). A helper keeps
    /// its token only until the job queue is empty. Tokens therefore flow to whichever
    /// operation is still running when another finishes, instead of being fixed at the start.
    /// Jobs are handed out one at a time from a shared counter, so callers order them
    /// largest-job-first.
    fn map_indexed<T: Send, F: Fn(usize) -> T + Sync>(n: usize, max_extra: usize, job: F) -> Vec<T> {
        let next = AtomicUsize::new(0);
        let run_one = || {
            let i = next.fetch_add(1, Ordering::Relaxed);
            (i < n).then(|| (i, job(i)))
        };
        let helper = |grant: ExtraGrant| {
            let live = LIVE_EXTRA.fetch_add(1, Ordering::AcqRel) + 1;
            let _ = PEAK_EXTRA.fetch_max(live, Ordering::Relaxed);
            let mut done = Vec::new();
            while let Some(r) = run_one() {
                done.push(r);
            }
            let _ = LIVE_EXTRA.fetch_sub(1, Ordering::AcqRel);
            drop(grant); // token back to the budget as soon as this helper runs dry
            done
        };
        let parts: Vec<Vec<(usize, T)>> = std::thread::scope(|s| {
            let mut handles = Vec::new();
            let mut mine = Vec::new();
            loop {
                // Top up with every spare token before each job (not one per job: the first
                // jobs are the largest subtrees, so a slow ramp-up would serialise them).
                while handles.len() < max_extra && next.load(Ordering::Relaxed) + 1 < n {
                    let Some(grant) = take_one() else { break };
                    let helper = &helper;
                    handles.push(s.spawn(move || helper(grant)));
                }
                match run_one() {
                    Some(r) => mine.push(r),
                    None => break,
                }
            }
            let mut parts = Vec::with_capacity(handles.len() + 1);
            parts.push(mine);
            for handle in handles {
                parts.push(handle.join().unwrap_or_else(|e| std::panic::resume_unwind(e)));
            }
            parts
        });
        let mut slots: Vec<Option<T>> = (0..n).map(|_| None).collect();
        for (i, value) in parts.into_iter().flatten() {
            slots[i] = Some(value);
        }
        slots.into_iter().map(|v| v.expect("each index is claimed by exactly one worker")).collect()
    }


    /// One independent Merkle node, identified by its tree, height `z` and node index.
    #[derive(Clone, Copy)]
    enum Job {
        Fors { i: u32, z: u32, index: u32 },
        Xmss { layer: u32, z: u32, index: u32 },
    }


    /// FORS and hypertree authentication nodes for one signature. `None` when only one
    /// thread may be used; the caller then computes every node inline, as before.
    ///
    /// `md` is the FORS message digest and `fors_adrs` the address `slh_sign_internal` hands
    /// to `fors_sign` (tree `idx_tree`, type `FORS_TREE`, key pair `idx_leaf`).
    #[allow(clippy::similar_names, clippy::too_many_arguments, clippy::cast_possible_truncation)]
    pub(crate) fn sign_nodes<
        const A: usize,
        const D: usize,
        const H: usize,
        const HP: usize,
        const K: usize,
        const LEN: usize,
        const M: usize,
        const N: usize,
    >(
        hashers: &Hashers<K, LEN, M, N>, md: &[u8], sk_seed: &[u8], pk_seed: &PkSeed<N>,
        fors_adrs: &Adrs, idx_tree: u64, idx_leaf: u32,
    ) -> Result<Option<SignNodes<A, D, HP, K, N>>, &'static str> {
        // FIPS205_THREADS=1: the original serial path, untouched.
        let max_extra = per_operation_cap().saturating_sub(1);
        if max_extra == 0 {
            return Ok(None);
        }
        let (a32, k32, hp32) = (A as u32, K as u32, HP as u32);

        // fors_sign step 2: indices ← base_2b(md, a, k)
        let mut indices = [0u32; K];
        base_2b(md, a32, k32, &mut indices);

        // Per-layer (idx_leaf, idx_tree), exactly as ht_sign steps 2, 7 and 8 derive them.
        let mut leaf = [0u32; D];
        let mut tree = [0u64; D];
        leaf[0] = idx_leaf;
        tree[0] = idx_tree;
        for j in 1..D {
            leaf[j] = (tree[j - 1] & ((1u64 << hp32) - 1)) as u32;
            tree[j] = tree[j - 1] >> hp32;
        }
        // ht_sign's ADRS for layer j: layer address j, tree address tree[j], rest zero.
        let layer_adrs = |layer: u32| {
            let mut adrs = Adrs::default();
            adrs.set_layer_address(layer);
            adrs.set_tree_address(tree[layer as usize]);
            adrs
        };

        // Every node, largest first. A height-z node costs 2^z leaves; an XMSS leaf (a WOTS+
        // public key, about len·w hashes) is far dearer than a FORS leaf (PRF + F).
        let mut jobs: Vec<(u64, Job)> = Vec::with_capacity(K * A + D * HP);
        for i in 0..k32 {
            for z in 0..a32 {
                // fors_sign steps 6-7: s ← indices[i]/2^z xor 1, node i·2^{a−z} + s
                let index = (i << (a32 - z)) + ((indices[i as usize] >> z) ^ 1);
                jobs.push(((1u64 << z) * 3, Job::Fors { i, z, index }));
            }
        }
        for layer in 0..(D as u32) {
            for z in 0..hp32 {
                // xmss_sign step 2: k ← idx/2^z xor 1
                let index = (leaf[layer as usize] >> z) ^ 1;
                jobs.push(((1u64 << z) * (LEN as u64) * 16, Job::Xmss { layer, z, index }));
            }
        }
        jobs.sort_by(|a, b| b.0.cmp(&a.0));

        let results = map_indexed(jobs.len(), max_extra, |n| match jobs[n].1 {
            Job::Fors { z, index, .. } => {
                fors::fors_node::<A, K, LEN, M, N>(hashers, sk_seed, index, z, pk_seed, fors_adrs)
            }
            Job::Xmss { layer, z, index } => Ok(xmss::xmss_node::<H, HP, K, LEN, M, N>(
                hashers,
                sk_seed,
                index,
                z,
                pk_seed,
                &layer_adrs(layer),
            )),
        });

        let mut nodes = SignNodes { fors: [[[0u8; N]; A]; K], ht: [[[0u8; N]; HP]; D] };
        for ((_, job), node) in jobs.iter().zip(results) {
            match *job {
                Job::Fors { i, z, .. } => nodes.fors[i as usize][z as usize] = node?,
                Job::Xmss { layer, z, .. } => nodes.ht[layer as usize][z as usize] = node?,
            }
        }
        Ok(Some(nodes))
    }


    /// Root of the height-`h′` XMSS tree at `adrs` (key generation's `xmss_node(SK.seed, 0,
    /// h′, PK.seed, ADRS)`): the `2^s` subtrees below the top `s` levels are built in
    /// parallel, then the top `s` levels are combined serially with the same `xmss_parent`
    /// step Algorithm 9 uses. `None` when only one thread may be used.
    #[allow(clippy::similar_names, clippy::cast_possible_truncation)]
    pub(crate) fn xmss_root<
        const H: usize,
        const HP: usize,
        const K: usize,
        const LEN: usize,
        const M: usize,
        const N: usize,
    >(
        hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8], pk_seed: &PkSeed<N>, adrs: &Adrs,
    ) -> Option<[u8; N]> {
        let max_extra = per_operation_cap().saturating_sub(1);
        if max_extra == 0 {
            return None;
        }
        let hp32 = HP as u32;
        let split = hp32.min(6); // at most 64 subtrees
        let base = hp32 - split;
        let mut level = map_indexed(1usize << split, max_extra, |i| {
            xmss::xmss_node::<H, HP, K, LEN, M, N>(hashers, sk_seed, i as u32, base, pk_seed, adrs)
        });
        for z in (base + 1)..=hp32 {
            level = (0..level.len() / 2)
                .map(|i| {
                    let (l, r) = (&level[2 * i], &level[2 * i + 1]);
                    xmss::xmss_parent(hashers, l, r, i as u32, z, pk_seed, adrs)
                })
                .collect();
        }
        level.first().copied()
    }
}
