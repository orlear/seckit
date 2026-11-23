---
name: pypi-release
description: Release a new seckit version to PyPI from this repository. Use when the user asks to publish, release, ship or tag a new version of seckit, bump the version, or check or fix the PyPI publish workflow.
---

# Publishing seckit to PyPI

Publishing is irreversible: PyPI never accepts the same version twice, even after deletion. Push a release tag only when the user asked for a release in this conversation.

## How it is set up

- Package `seckit` on PyPI (https://pypi.org/project/seckit/), module and command `seckit`. PyPI blocks the name `bluekit`, and `guardkit` belongs to someone else; never use either.
- The version lives only in `seckit/__init__.py` (`__version__`). `pyproject.toml` reads it dynamically, and the MCP `serverInfo` imports it.
- `.github/workflows/publish.yml` runs on a `v*` tag. Job `build` checks that the tag equals `v` + `__version__`, runs the unit tests, builds the sdist and wheel and runs `twine check --strict`. Job `publish` uploads with `pypa/gh-action-pypi-publish` through Trusted Publishing (OIDC, no token) and adds a Sigstore attestation.
- Trusted publisher on PyPI: owner `orlear`, repository `seckit`, workflow `publish.yml`, environment `pypi`. The GitHub environment `pypi` only accepts deployments from `v*` tags. If the repository, workflow file or environment is renamed, the publisher on PyPI must be updated first, or the upload fails with an OIDC error.
- All actions are pinned by commit SHA with the version in a comment, and the repository requires it. Dependabot proposes updates weekly; to update one by hand, resolve the SHA with `gh api repos/OWNER/REPO/commits/TAG --jq .sha` and update `test.yml` too.
- Repository rules: `main` changes only through a pull request with green `portable` and `engines` checks and signed commits; no force-push or deletion, and nobody bypasses this. Release tags `v*` cannot be moved or deleted once pushed. Commits and tags are signed with the SSH key configured in this repository's git config; signing needs the key loaded in ssh-agent (`ssh-add -l`).

## Release steps

1. Start from an up-to-date `main` with a clean tree: `git checkout main && git pull --ff-only`.
2. Choose the version with the user (semver: patch for fixes, minor for features or changed output, major for breaking CLI or JSON changes). Check it is not taken: `curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/seckit/X.Y.Z/json` must print 404.
3. Set `__version__` in `seckit/__init__.py`. Commit with the message `Release X.Y.Z` and a short list of user-visible changes since the last tag (`git log --oneline vPREV..HEAD`). Push it on a branch, open a pull request and merge it after CI is green (merge or squash; `main` takes no direct pushes).
4. Run the tests and check the exit code itself, not the exit code of a pipe:
   ```bash
   PYTHONPATH=. python3 -m unittest discover -s tests > "$SCRATCH/ut.log" 2>&1; echo "exit $?"; tail -3 "$SCRATCH/ut.log"
   ```
   Wait for CI on that commit to be green on all jobs: `gh run list --limit 3`, then `gh run view ID --json conclusion,jobs`.
5. Optionally build locally exactly as CI does, in a scratch venv with `build==1.6.1 twine==7.0.0`: `python -I -m build --outdir "$SCRATCH/dist" .` and `python -I -m twine check --strict "$SCRATCH/dist"/*`. Remove the `build/` and `*.egg-info` it leaves in the repository.
6. Update `main` to the merged commit (`git checkout main && git pull --ff-only`), then tag and push: `git tag -s vX.Y.Z -m "seckit X.Y.Z" && git push origin vX.Y.Z`. Check the tag points at the merged release commit first: it cannot be moved afterwards.
7. Watch the run: find it with `gh run list --workflow publish.yml --limit 1 --json databaseId`, then `gh run watch ID --exit-status`. Run it in the background and wait for the notification.

## Verify

- `curl -s https://pypi.org/pypi/seckit/json`: `info.version` is X.Y.Z, and `urls` lists the wheel and the sdist.
- Attestation: `curl -s https://pypi.org/integrity/seckit/X.Y.Z/seckit-X.Y.Z-py3-none-any.whl/provenance` returns 200 with publisher repository `orlear/seckit`, workflow `publish.yml`, environment `pypi`.
- Fresh install: create a scratch venv, `pip install --no-cache-dir seckit==X.Y.Z`, then `seckit --version`. The new version can take a minute to reach the CDN.
- Report to the user: the PyPI link, version, files, attestation and install result.

## When it fails

- Tag/version mismatch, tests or `twine check` fail in `build`: nothing was uploaded, but the tag cannot be deleted or moved. Fix on `main` through a pull request and release the next patch version, or ask the user whether they want to disable the `release tags` ruleset for a moment themselves; never change repository rules yourself.
- `publish` fails with an OIDC or "invalid-publisher" error: the trusted publisher on PyPI does not match the repository, workflow or environment. Only the user can fix it on pypi.org. Re-run the job with `gh run rerun ID --failed`.
- Upload was rejected because the file already exists: this version is on PyPI already, partly or fully. Never delete and re-upload; bump to the next patch version.
- A broken release is already on PyPI: release a fixed patch version. Yanking the bad one on pypi.org is the user's decision.
- The PyPI project page shows the README from the release. README changes appear there only with the next release.
