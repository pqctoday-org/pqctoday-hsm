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
//! path runs exactly as before. With it, one operation uses `available_parallelism()` threads,
//! capped by the environment variable `FIPS205_THREADS` when that is a positive integer;
//! `FIPS205_THREADS=1` restores the original serial path.

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


#[cfg(feature = "parallel")]
pub(crate) use threaded::{sign_nodes, xmss_root};


#[cfg(feature = "parallel")]
mod threaded {
    use super::SignNodes;
    use crate::hashers::{Hashers, PkSeed};
    use crate::helpers::base_2b;
    use crate::types::Adrs;
    use crate::{fors, xmss};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::vec::Vec;


    /// Threads one operation may use: `available_parallelism()`, capped by `FIPS205_THREADS`.
    fn thread_count() -> usize {
        let available =
            std::thread::available_parallelism().map_or(1, core::num::NonZeroUsize::get);
        match std::env::var("FIPS205_THREADS").ok().and_then(|v| v.trim().parse::<usize>().ok()) {
            Some(n) if n >= 1 => n.min(available),
            _ => available,
        }
    }


    /// Computes `job(i)` for every `i` in `0..n` on up to `threads` scoped threads (the
    /// calling thread included) and returns the results in index order. Indices are handed
    /// out one at a time from a shared counter, so callers order them largest-job-first.
    fn map_indexed<T: Send, F: Fn(usize) -> T + Sync>(n: usize, threads: usize, job: F) -> Vec<T> {
        let workers = threads.min(n);
        if workers <= 1 {
            return (0..n).map(job).collect();
        }
        let next = AtomicUsize::new(0);
        let run = || {
            let mut done = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break done;
                }
                done.push((i, job(i)));
            }
        };
        let parts: Vec<Vec<(usize, T)>> = std::thread::scope(|s| {
            let handles: Vec<_> = (1..workers).map(|_| s.spawn(&run)).collect();
            let mut parts = Vec::with_capacity(workers);
            parts.push(run());
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
        let threads = thread_count();
        if threads <= 1 {
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

        let results = map_indexed(jobs.len(), threads, |n| match jobs[n].1 {
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
        let threads = thread_count();
        if threads <= 1 {
            return None;
        }
        let hp32 = HP as u32;
        let split = hp32.min(6); // at most 64 subtrees
        let base = hp32 - split;
        let mut level = map_indexed(1usize << split, threads, |i| {
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
