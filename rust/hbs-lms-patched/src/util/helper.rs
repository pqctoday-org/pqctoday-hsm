pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

pub fn read<'a>(src: &'a [u8], length: usize, index: &usize) -> &'a [u8] {
    &src[*index..*index + length]
}

/// Bounds-checked `read` — returns `None` instead of panicking when `src` is
/// too short. Wire parsers MUST use this: signature/key bytes are
/// attacker-controlled (e.g. ACVP sigver corrupt-by-design vectors), and a
/// panic aborts the whole wasm instance.
pub fn try_read<'a>(src: &'a [u8], length: usize, index: &usize) -> Option<&'a [u8]> {
    src.get(*index..*index + length)
}

/// Bounds-checked `read_and_advance`.
pub fn try_read_and_advance<'a>(
    src: &'a [u8],
    length: usize,
    index: &mut usize,
) -> Option<&'a [u8]> {
    let result = try_read(src, length, index)?;
    *index += length;
    Some(result)
}

pub fn read_and_advance<'a>(src: &'a [u8], length: usize, index: &mut usize) -> &'a [u8] {
    let result = read(src, length, index);
    *index += length;
    result
}

#[cfg(test)]
pub mod test_helper {
    use crate::{HashChain, Seed};
    use rand::{rngs::OsRng, RngCore};

    pub fn gen_random_seed<H: HashChain>() -> Seed<H> {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());
        seed
    }
}
