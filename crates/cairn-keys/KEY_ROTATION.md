# Key Rotation Procedure (age X25519)

## Current state
- `priv.pem` — age private key (permissions: 0600, in .gitignore as `*.pem`)
- `pub.pem` — age public key (safe to distribute)
- `priv.pem.bak` — backup of the previous private key (created on rotation)

## How to rotate the key

### 1. Generate a new key pair
```bash
age-keygen 2>&1 | tee new_key_output.txt
# Copy the public key from output
# Save the private key securely
```

### 2. Back up the old private key (ALWAYS do this first)
```bash
cp priv.pem priv.pem.bak
chmod 600 priv.pem.bak
```

### 3. Replace priv.pem with the new key
```bash
# Write the new private key to priv.pem
# Set correct permissions
chmod 600 priv.pem
```

### 4. Update pub.pem
```bash
# Extract public key from new key and save to pub.pem
```

### 5. Verify access works
```bash
# Test mount/backup with the new key pair
```

## If the private key is compromised
1. **Immediately** revoke trust in the old public key on all backup hosts.
2. Generate a new key pair (step 1 above).
3. **All existing encrypted data becomes unreadable** — you must re-encrypt from scratch:
   - Create a new archive with `init` using the new public key.
   - Re-backup all data.
   - The old archive is permanently inaccessible without the compromised private key.
4. Delete `priv.pem.bak` and any other copies of the compromised key **only after** confirming
   the new key works for a full backup/restore cycle.

## Important notes
- **Do NOT delete `priv.pem.bak` until you have verified the new key works.**
- The old private key is required to decrypt all existing data — if lost, that data is unrecoverable.
- Keep `priv.pem` on a trusted machine only; never on backup hosts.
- `pub.pem` is safe to distribute to any host that only writes backups.
