//! Allocation-free preflight for the exact, deliberately narrow PCZT-v2 profile.
//! Mirrors pczt 0.10.0-pre.1 v2 wire field order. Unknown formats fail closed.
//! Does not implement cryptography. Upstream performs semantic decoding afterward.

pub const MAX_BYTES: usize = 1_048_576;
pub const MAX_ACTIONS: usize = 64;

struct Cursor<'a> {
    bytes: &'a [u8],
    i: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.i.checked_add(n).ok_or("PCZT cursor overflow")?;
        let data = self.bytes.get(self.i..end).ok_or("Truncated PCZT")?;
        self.i = end;
        Ok(data)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn var(&mut self, bits: u32) -> Result<u64, String> {
        let mut n = 0_u64;
        for shift in (0..bits).step_by(7) {
            let b = self.byte()?;
            let low = b & 127;
            let remaining = bits - shift;
            if remaining < 7 && u32::from(low) >= (1 << remaining) {
                return Err("Oversized PCZT varint".into());
            }
            n |= u64::from(low) << shift;
            if b & 128 == 0 {
                if shift > 0 && low == 0 {
                    return Err("Noncanonical PCZT varint".into());
                }
                return Ok(n);
            }
        }
        Err("Oversized PCZT varint".into())
    }
    fn option(&mut self, f: impl FnOnce(&mut Self) -> Result<(), String>) -> Result<(), String> {
        match self.byte()? {
            0 => Ok(()),
            1 => f(self),
            _ => Err("Invalid PCZT option".into()),
        }
    }
    fn opt_bytes(&mut self, n: usize) -> Result<(), String> {
        self.option(|s| {
            s.take(n)?;
            Ok(())
        })
    }
    fn opt_var(&mut self, bits: u32) -> Result<(), String> {
        self.option(|s| {
            s.var(bits)?;
            Ok(())
        })
    }
    fn bytes_vec(&mut self, max: usize) -> Result<(), String> {
        let n = self.var(64)?;
        if n > max as u64 {
            return Err("PCZT vector exceeds profile bound".into());
        }
        self.take(n as usize)?;
        Ok(())
    }
    fn empty_map(&mut self) -> Result<(), String> {
        if self.var(64)? != 0 {
            return Err("Unqualified PCZT proprietary fields".into());
        }
        Ok(())
    }
    fn derivation(&mut self) -> Result<(), String> {
        self.option(|s| {
            s.take(32)?;
            let n = s.var(64)?;
            if n > 16 {
                return Err("ZIP32 derivation exceeds profile bound".into());
            }
            for _ in 0..n {
                s.var(32)?;
            }
            Ok(())
        })
    }
    fn action(&mut self) -> Result<(), String> {
        self.opt_bytes(32)?; // cv_net
        self.opt_bytes(32)?;
        self.opt_bytes(32)?; // nullifier, rk
        self.opt_bytes(64)?;
        self.opt_bytes(43)?;
        self.opt_var(64)?;
        self.opt_bytes(32)?;
        self.opt_bytes(32)?;
        self.opt_bytes(96)?;
        self.option(|s| {
            s.var(32)?;
            s.take(32 * 32)?;
            Ok(())
        })?;
        self.opt_bytes(32)?;
        self.derivation()?;
        if self.byte()? != 0 {
            return Err("Dummy spending keys must be removed by IO finalization".into());
        }
        self.empty_map()?;
        self.opt_bytes(32)?;
        self.take(32)?; // cmx, ephemeral key
        if self.var(32)? != 0 {
            return Err("Review requires actual encrypted note ciphertext".into());
        }
        self.bytes_vec(1024)?;
        self.bytes_vec(80)?;
        self.opt_bytes(43)?;
        self.opt_var(64)?;
        self.opt_bytes(32)?;
        self.opt_bytes(32)?;
        self.derivation()?;
        self.option(|s| s.bytes_vec(1024))?;
        self.empty_map()?;
        self.opt_bytes(32)?; // rcv
        Ok(())
    }
}

pub fn preflight(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_BYTES {
        return Err("PCZT exceeds 1 MiB profile bound".into());
    }
    let mut c = Cursor { bytes, i: 0 };
    if c.take(8)? != b"PCZT\x02\0\0\0" {
        return Err("PCZT v2 required".into());
    }
    c.var(32)?;
    c.var(32)?;
    c.var(32)?;
    c.opt_var(32)?;
    c.var(32)?;
    c.var(32)?;
    c.byte()?;
    c.empty_map()?;
    if c.byte()? != 0 {
        return Err("Transparent bundle must be canonically absent".into());
    }
    // IO-finalized PCZTs can carry empty Sapling binding-key context.
    c.option(|s| {
        if s.var(64)? != 0 || s.var(64)? != 0 || s.byte()? != 0 {
            return Err("Nonempty Sapling bundle is forbidden".into());
        }
        s.opt_bytes(32)?;
        s.opt_bytes(32)?;
        Ok(())
    })?;
    if c.byte()? != 0 {
        return Err("Orchard-pool bundle is forbidden".into());
    }
    if c.byte()? != 1 {
        return Err("Ironwood bundle is required".into());
    }
    let count = c.var(64)?;
    if count == 0 || count > MAX_ACTIONS as u64 {
        return Err("Ironwood action count outside 1..=64".into());
    }
    for _ in 0..count {
        c.action()?;
    }
    c.byte()?;
    c.var(64)?;
    if c.byte()? > 1 {
        return Err("Invalid value-sum sign flag".into());
    }
    c.opt_bytes(32)?;
    if c.var(32)? != 1 {
        return Err("Ironwood note plaintext V3 required".into());
    }
    c.option(|s| s.bytes_vec(262_144))?;
    c.opt_bytes(32)?;
    if c.i != bytes.len() {
        return Err("Trailing PCZT bytes are forbidden".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_noncanonical_and_unbounded_varints() {
        let mut a = super::Cursor {
            bytes: &[0x80, 0],
            i: 0,
        };
        assert!(a.var(32).is_err());
        let mut b = super::Cursor {
            bytes: &[0xff; 20],
            i: 0,
        };
        assert!(b.var(64).is_err());
        assert!(super::preflight(&vec![0; super::MAX_BYTES + 1]).is_err());
    }
}
