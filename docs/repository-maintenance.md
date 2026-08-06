# Repository Maintenance

This document records repository settings that require GitHub administration;
they are not changed by source edits.

## Suggested Topics

`quansheng`, `uv-k5`, `uv-k5-8`, `ham-radio`, `serial`, `firmware`, `radio`,
`python`, `reverse-engineering`, `hardware-identification`

## Settings Checklist

- Confirm the repository description and homepage point to the project.
- Keep Issues enabled; enable Discussions only if maintainers will monitor them.
- Enable private vulnerability reporting in the Security settings when available.
- Protect `main` and require the CI workflow before merging.
- Prefer squash merges and enable automatic branch deletion.
- Create releases only from reviewed tags and the changelog.
- Keep the package version, changelog, tag, and release notes consistent.
- Confirm the repository's default branch and workflow permissions are minimal.

At the time of this documentation update, the locally visible repository has a
`v1.0.0` tag, while the canonical package version is `1.3.0`. No GitHub release
was asserted or created by this change; maintainers should reconcile release
metadata deliberately.
