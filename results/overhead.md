2100 spans per run, 15 runs per configuration, wall time through the OTel SDK.

| Configuration | µs per span (median) | Added vs plain | Log bytes / record | Total bytes / record (incl. vault, receipts) |
|---|---|---|---|---|
| plain | 29.9 | +0.0 µs | 509 | 509 (1.00×) |
| hash | 64.7 | +34.8 µs | 787 | 787 (1.54×) |
| signed | 94.8 | +65.0 µs | 926 | 926 (1.82×) |
| committed | 104.8 | +75.0 µs | 958 | 1229 (2.41×) |
| witnessed | 111.0 | +81.1 µs | 958 | 1248 (2.45×) |
