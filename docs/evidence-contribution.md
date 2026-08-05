# Evidence contribution

Create bounded captures, sanitize them with `capture-sanitize`, validate them,
then produce an offline bundle:

```bash
qsidentify evidence-export capture-1.json capture-2.json \
  --output evidence-bundle.json --provenance-notes "physical validation"
qsidentify evidence-bundle-inspect evidence-bundle.json
qsidentify evidence-bundle-validate evidence-bundle.json
```

Bundles contain sanitized captures, a stability report, fingerprint, versions,
and contributor-supplied provenance notes. They exclude USB serial numbers,
usernames, hostnames, absolute source paths, unnormalized timestamps, channel
memory, calibration data, and unrelated device information. There is no upload
or network feature.

Labels such as marketed model, sticker, boot screen text, revision marking,
device group, and experiment ID are user-supplied observations. Clearly state
whether a fixture is raw, synthetic, or a sanitized derivative and how physical
ground truth was established.
