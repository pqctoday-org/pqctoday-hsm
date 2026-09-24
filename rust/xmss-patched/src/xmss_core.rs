use zeroize::Zeroize;

use crate::error::{Error, XmssResult};
use crate::hash::{hash_message, prf, thash_h};
use crate::hash_address::*;
use crate::params::XmssParams;
use crate::utils::{bytes_to_ull, ull_to_bytes};
use crate::wots::wots_sign;
use crate::tree_cache;
use crate::xmss_commons::gen_leaf_wots;

/// For a given leaf index, computes the authentication path and the resulting
/// root node using Merkle's TreeHash algorithm.
fn treehash(
    params: &XmssParams,
    root: &mut [u8],
    auth_path: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    leaf_idx: u32,
    subtree_addr: &[u32; 8],
) -> XmssResult<()> {
    // pqctoday-hsm `hw-accel`: the hashsig engine builds the tree when it
    // claims this parameter set (see hw_accel.rs); otherwise it is built here.
    #[cfg(feature = "hw-accel")]
    if crate::hw_accel::treehash(params, root, auth_path, sk_seed, pub_seed, leaf_idx, subtree_addr) {
        return Ok(());
    }
    let n = params.n as usize;
    let tree_height = params.tree_height as usize;
    let mut stack = vec![0u8; (tree_height + 1) * n];
    let mut heights = vec![0u32; tree_height + 1];
    let mut offset: usize = 0;

    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    copy_subtree_addr(&mut ots_addr, subtree_addr);
    copy_subtree_addr(&mut ltree_addr, subtree_addr);
    copy_subtree_addr(&mut node_addr, subtree_addr);

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    let num_leaves: u32 = 1 << params.tree_height;
    for idx in 0..num_leaves {
        set_ltree_addr(&mut ltree_addr, idx);
        set_ots_addr(&mut ots_addr, idx);
        gen_leaf_wots(
            params,
            &mut stack[offset * n..(offset + 1) * n],
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        )?;
        offset += 1;
        heights[offset - 1] = 0;

        if (leaf_idx ^ 0x1) == idx {
            auth_path[..n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
        }

        while offset >= 2 && heights[offset - 1] == heights[offset - 2] {
            let tree_idx = idx >> (heights[offset - 1] + 1);

            set_tree_height(&mut node_addr, heights[offset - 1]);
            set_tree_index(&mut node_addr, tree_idx);
            let tmp = stack[(offset - 2) * n..offset * n].to_vec();
            thash_h(
                params,
                &mut stack[(offset - 2) * n..(offset - 1) * n],
                &tmp,
                pub_seed,
                &mut node_addr,
            )?;
            offset -= 1;
            heights[offset - 1] += 1;

            if ((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx {
                let h = heights[offset - 1] as usize;
                auth_path[h * n..(h + 1) * n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
            }
        }
    }
    root[..n].copy_from_slice(&stack[..n]);
    Ok(())
}

/// Given a set of parameters, this function returns the size of the secret key.
pub fn xmss_xmssmt_core_sk_bytes(params: &XmssParams) -> u64 {
    params.index_bytes as u64 + 4 * params.n as u64
}

/// Derives a XMSSMT key pair from a given seed.
/// Seed must be 3*n long.
/// Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
/// Format pk: [root || PUB_SEED] omitting algorithm OID.
pub fn xmssmt_core_seed_keypair(
    params: &XmssParams,
    pk: &mut [u8],
    sk: &mut [u8],
    seed: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;
    let tree_height = params.tree_height as usize;
    let mut auth_path = vec![0u8; tree_height * n];
    let mut top_tree_addr = [0u32; 8];
    set_layer_addr(&mut top_tree_addr, params.d - 1);

    for b in sk[..idx_bytes].iter_mut() {
        *b = 0;
    }

    sk[idx_bytes..idx_bytes + 2 * n].copy_from_slice(&seed[..2 * n]);

    sk[idx_bytes + 3 * n..idx_bytes + 4 * n].copy_from_slice(&seed[2 * n..3 * n]);
    pk[n..2 * n].copy_from_slice(&sk[idx_bytes + 3 * n..idx_bytes + 4 * n]);

    // Copy pub_seed since pk is mutably borrowed by treehash.
    let pub_seed_copy = pk[n..2 * n].to_vec();
    // pqctoday-hsm: same root as upstream `treehash`, and the top subtree lands in the
    // in-memory cache (tree_cache.rs), so the key's first signature does not rebuild it.
    tree_cache::root_and_auth(
        params,
        pk,
        &mut auth_path,
        &sk[idx_bytes..],
        &pub_seed_copy,
        0,
        &top_tree_addr,
        false,
    )?;
    sk[idx_bytes + 2 * n..idx_bytes + 3 * n].copy_from_slice(&pk[..n]);

    Ok(())
}

/// Generates a XMSSMT key pair for a given parameter set.
/// Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
/// Format pk: [root || PUB_SEED] omitting algorithm OID.
pub fn xmssmt_core_keypair<R: rand::CryptoRng>(
    params: &XmssParams,
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut seed = vec![0u8; 3 * n];

    rng.fill_bytes(&mut seed[..]);
    let result = xmssmt_core_seed_keypair(params, pk, sk, &seed);
    seed.zeroize();
    result
}

/// Signs a message. Returns the signature followed by the message
/// and an updated secret key.
pub fn xmssmt_core_sign(params: &XmssParams, sk: &mut [u8], m: &[u8]) -> XmssResult<Vec<u8>> {
    xmssmt_core_sign_impl(params, sk, m, true)
}

/// `xmssmt_core_sign` with the subtree cache on (`use_cache`) or off (upstream `treehash`
/// on every layer of every signature, kept as the reference the cache is tested against).
pub(crate) fn xmssmt_core_sign_impl(
    params: &XmssParams,
    sk: &mut [u8],
    m: &[u8],
    use_cache: bool,
) -> XmssResult<Vec<u8>> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;
    let mlen = m.len();
    let sig_bytes = params.sig_bytes as usize;

    let sk_seed_start = idx_bytes;
    let sk_prf_start = idx_bytes + n;
    let pub_root_start = idx_bytes + 2 * n;
    let pub_seed_start = idx_bytes + 3 * n;

    let idx = bytes_to_ull(&sk[..idx_bytes]);

    // Check if key is exhausted before doing anything.
    let max_idx = if params.full_height >= 64 {
        u64::MAX
    } else {
        (1u64 << params.full_height) - 1
    };
    if idx > max_idx {
        return Err(Error::KeyExhausted);
    }

    // Copy secret values out before mutating sk.
    let mut sk_seed = sk[sk_seed_start..sk_seed_start + n].to_vec();
    let mut sk_prf = sk[sk_prf_start..sk_prf_start + n].to_vec();
    let pub_root = sk[pub_root_start..pub_root_start + n].to_vec();
    let pub_seed = sk[pub_seed_start..pub_seed_start + n].to_vec();

    let mut sm = vec![0u8; sig_bytes + mlen];

    let mut ots_addr = [0u32; 8];
    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);

    sm[sig_bytes..].copy_from_slice(m);

    // Write index into signature.
    sm[..idx_bytes].copy_from_slice(&sk[..idx_bytes]);

    // Advance the index in sk.
    if idx == max_idx {
        // Last valid index — mark as exhausted for next call.
        for b in sk[..idx_bytes].iter_mut() {
            *b = 0xFF;
        }
    } else {
        ull_to_bytes(&mut sk[..idx_bytes], idx + 1);
    }

    // Compute R (randomness for message hashing).
    let mut idx_bytes_32 = [0u8; 32];
    ull_to_bytes(&mut idx_bytes_32, idx);
    prf(
        params,
        &mut sm[idx_bytes..idx_bytes + n],
        &idx_bytes_32,
        &sk_prf,
    )?;

    let mut root = vec![0u8; n];
    let prefix_len = params.padding_len as usize + 3 * n;
    let prefix_start = sig_bytes - prefix_len;
    // Copy R out to avoid borrow conflict (sm is both read for R and mutated for prefix).
    let r_val = sm[idx_bytes..idx_bytes + n].to_vec();
    hash_message(
        params,
        &mut root,
        &r_val,
        &pub_root,
        idx,
        &mut sm[prefix_start..],
        mlen as u64,
    )?;

    let mut sm_offset = idx_bytes + n;

    for i in 0..params.d {
        let idx_leaf = (idx >> (params.tree_height * i)) & ((1u64 << params.tree_height) - 1);
        #[allow(clippy::cast_possible_truncation)] // masked to tree_height bits, always fits u32
        let idx_leaf = idx_leaf as u32;
        let tree_idx = idx >> (params.tree_height * (i + 1));

        set_layer_addr(&mut ots_addr, i);
        set_tree_addr(&mut ots_addr, tree_idx);
        set_ots_addr(&mut ots_addr, idx_leaf);

        wots_sign(
            params,
            &mut sm[sm_offset..],
            &root,
            &sk_seed,
            &pub_seed,
            &mut ots_addr,
        )?;
        sm_offset += params.wots_sig_bytes as usize;

        if use_cache {
            // The signature with the last leaf of this subtree is the last one that will
            // ever use it (the index only moves forward): drop its cache entry then.
            let span = params.tree_height * (i + 1);
            let lower = if span >= 64 { u64::MAX } else { (1u64 << span) - 1 };
            let release = idx & lower == lower;
            tree_cache::root_and_auth(
                params,
                &mut root,
                &mut sm[sm_offset..],
                &sk_seed,
                &pub_seed,
                idx_leaf,
                &ots_addr,
                release,
            )?;
        } else {
            treehash(
                params,
                &mut root,
                &mut sm[sm_offset..],
                &sk_seed,
                &pub_seed,
                idx_leaf,
                &ots_addr,
            )?;
        }
        sm_offset += params.tree_height as usize * n;
    }

    // Zeroize secret copies.
    sk_seed.zeroize();
    sk_prf.zeroize();

    // If this was the last valid index, zero the secret key material in sk.
    if idx == max_idx {
        #[allow(clippy::cast_possible_truncation)]
        let sk_bytes_len = params.sk_bytes as usize;
        for b in sk[idx_bytes..sk_bytes_len].iter_mut() {
            *b = 0;
        }
    }

    Ok(sm)
}

#[cfg(test)]
mod cache_tests {
    //! pqctoday-hsm: the subtree cache must reproduce upstream `treehash` signatures exactly.
    use super::*;
    use crate::params::XmssOid;
    use crate::utils::ull_to_bytes;

    fn params(oid: XmssOid) -> XmssParams {
        let mut p = XmssParams::default();
        oid.initialize(&mut p).unwrap();
        p
    }

    /// Signs `count` messages from index `start` twice — cache on and cache off (upstream
    /// treehash on every layer) — from the same key, and requires identical signatures
    /// and identical updated secret keys after every step.
    fn same_sequence(oid: XmssOid, start: u64, count: usize) {
        let p = params(oid);
        let seed: Vec<u8> = (0..p.get_seed_length()).map(|i| (i * 7 + 3) as u8).collect();
        let mut pk = vec![0u8; p.pk_bytes as usize];
        let mut sk = vec![0u8; p.sk_bytes as usize];
        xmssmt_core_seed_keypair(&p, &mut pk, &mut sk, &seed).unwrap();
        ull_to_bytes(&mut sk[..p.index_bytes as usize], start);
        let (mut sk_cached, mut sk_ref) = (sk.clone(), sk);
        for k in 0..count {
            let msg = [k as u8, 0x5a, 0xa5];
            let a = xmssmt_core_sign_impl(&p, &mut sk_cached, &msg, true).unwrap();
            let b = xmssmt_core_sign_impl(&p, &mut sk_ref, &msg, false).unwrap();
            assert!(a == b, "{oid:?}: signature {k} (index {}) differs", start + k as u64);
            assert!(sk_cached == sk_ref, "{oid:?}: updated key {k} differs");
        }
    }

    #[test]
    fn xmss_10_cached_signatures_match_upstream() {
        // From the key's first index, then across the height-3..9 boundaries around 512.
        same_sequence(XmssOid::XmssSha2_10_256, 0, 10);
        same_sequence(XmssOid::XmssSha2_10_256, 505, 10);
        // The last index of the tree: the entry is released and the key is exhausted.
        same_sequence(XmssOid::XmssSha2_10_256, 1022, 2);
    }

    #[test]
    fn xmssmt_cached_signatures_match_upstream_across_subtrees() {
        // d = 4 layers of height-5 subtrees: 29..40 crosses the layer-0 boundary at 32
        // (a new bottom subtree, and the old entry released), and 1020..1030 crosses the
        // layer-1 boundary at 1024.
        same_sequence(XmssOid::XmssMtSha2_20_4_256, 29, 11);
        same_sequence(XmssOid::XmssMtSha2_20_4_256, 1020, 10);
    }

    #[test]
    fn exhausted_subtrees_leave_the_cache() {
        let p = params(XmssOid::XmssMtSha2_20_4_256);
        let seed = vec![0x42u8; p.get_seed_length()];
        let mut pk = vec![0u8; p.pk_bytes as usize];
        let mut sk = vec![0u8; p.sk_bytes as usize];
        xmssmt_core_seed_keypair(&p, &mut pk, &mut sk, &seed).unwrap();
        let key = tree_cache::key_of(&p, &sk[p.index_bytes as usize..], &sk[p.index_bytes as usize + 3 * p.n as usize..], &{
            let mut a = [0u32; 8];
            set_layer_addr(&mut a, 0);
            a
        });
        ull_to_bytes(&mut sk[..p.index_bytes as usize], 30);
        let _ = xmssmt_core_sign(&p, &mut sk, b"a").unwrap(); // index 30: layer-0 tree 0 cached
        assert!(tree_cache::contains(&key));
        let _ = xmssmt_core_sign(&p, &mut sk, b"b").unwrap(); // index 31: its last leaf
        assert!(!tree_cache::contains(&key), "exhausted subtree still cached");
    }
}
