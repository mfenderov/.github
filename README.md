# .github

Shared reusable GitHub Actions workflows for `mfenderov` repos.

## Secret scanning (Gitleaks)

Add to any repo as `.github/workflows/gitleaks.yml`:

```yaml
name: gitleaks
on:
  pull_request:
  push:
  workflow_dispatch:
  schedule:
    - cron: "0 4 * * *"
jobs:
  scan:
    uses: mfenderov/.github/.github/workflows/gitleaks-reusable.yml@v1
    permissions:
      contents: read
      pull-requests: write
```
