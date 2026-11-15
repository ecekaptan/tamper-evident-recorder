Detection over 50 random trials per attack. Log: 210 records, witness checkpoint every 25 records (8 receipts), seed 0.

| Attack | Attacker | Plain logs | Hash chain | + Signatures | + Witness checkpoints |
|---|---|---|---|---|---|
| Edit a field | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Edit and re-sign one record | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Delete a middle record | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Swap two adjacent records | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Insert a signed fake record | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Append a fake record (no operator key) | outsider | ✗ 0/50 | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 |
| Truncate the tail | operator | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 | ✓ 50/50 |
| Rewrite and re-sign the whole chain | operator | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 | ◐ 49/50 |
| Log a false event at write time | operator | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 |
