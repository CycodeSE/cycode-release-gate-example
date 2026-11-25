# Cycode release gate example for GitHub Actions

A go or no-go check for a release branch, built on the Cycode API. Nothing is scanned in the pipeline. The gate reads the results of the scans the Cycode platform already ran on the branch, compares them with thresholds the security team sets in Cycode, and returns GO only when no open violation is at or above a threshold.

**Last verified:** November 2026 against `api.cycode.com`, with `actions/checkout@v7` and `actions/upload-artifact@v7`.

## How the gate works

1. **Wait for the platform scans.** The gate waits until Cycode shows a completed SCA and IaC scan of the branch.
2. **Read the thresholds from Cycode.** It reads the PR status check severity set on a Cycode project, one per scanner: Secrets, SCA dependencies, SCA licenses, SAST and IaC. The pipeline holds no thresholds. A change in the Cycode console applies on the next run.
3. **Count open violations on the branch.** For each scanner it counts open violations at or above the threshold. Ignored and resolved violations are not counted. Secrets are matched to the branch by commit history. See [How Secrets are matched to a branch](#how-secrets-are-matched-to-a-branch).
4. **Answer.** GO when every count is zero. NO-GO when a count is above zero, or when the gate cannot evaluate: a scan is missing or failed, a threshold is not set, or the API returns an error.

## Repo layout

```
scripts/cycode_release_gate.py              The gate. Python standard library only
.github/workflows/cycode-release-gate.yml   Reusable workflow that runs the gate
.github/workflows/deploy.yml                Example pipeline: the deploy job runs only on GO
```

## Requirements

- **The repository is connected to Cycode** through the GitHub integration.
- **The platform scans your release branches.** Secrets scanning covers every branch. SCA, SAST and IaC scan the branches named in their branch scanning rules, so add a rule that matches your release branch names.
- **A Cycode project that includes the repository, with its own PR settings.** On each scanner's tab in the project's PR settings, select **Project Settings** and set the status check severity. 
- **A Cycode service account for the pipeline.** A read-only role is sufficient. 

## Setup

1. Copy `scripts/cycode_release_gate.py` and `.github/workflows/cycode-release-gate.yml` to the default branch of your repository.
2. Add two repository secrets: `CYCODE_CLIENT_ID` and `CYCODE_CLIENT_SECRET`.
3. Add a repository variable `CYCODE_PROJECT_ID`. It is the number at the end of the project's URL in the Cycode console.
4. Call the workflow from your deployment pipeline and make the deploy job depend on it. `deploy.yml` shows the pattern.

```yaml
jobs:
  gate:
    uses: ./.github/workflows/cycode-release-gate.yml
    with:
      branch: my-service-1.4.0
      projectId: ${{ vars.CYCODE_PROJECT_ID }}
    secrets:
      CYCODE_CLIENT_ID: ${{ secrets.CYCODE_CLIENT_ID }}
      CYCODE_CLIENT_SECRET: ${{ secrets.CYCODE_CLIENT_SECRET }}

  deploy:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - run: echo "Gate returned GO"
```

A NO-GO fails the `gate` job, so `deploy` is skipped. The run summary shows the threshold, the scan status and the open counts by severity for each scanner. The same result is uploaded as a JSON artifact.

## Workflow inputs

| Input | Default | Description |
|---|---|---|
| `branch` | required | Release branch to evaluate. |
| `projectId` | required | Cycode project whose PR settings hold the thresholds. |
| `scanners` | `secrets,sca,licenses,sast,iac` | Thresholds that can block. `sca` is SCA dependencies and `licenses` is SCA licenses. |
| `requireScans` | `sca,iac` | Scanners that must show a completed platform scan of the branch. |
| `triggerScans` | empty | Scanners to scan on demand before evaluating: `sast`, `sca`, `iac`. |
| `repositoryScope` | empty | Scanners counted across the whole repository instead of the branch, for example `secrets`. |
| `secretsBy` | `history` | `history` counts the open secrets whose commit is in the branch's history. `branch` counts only the secrets Cycode records against the branch. |
| `minAgeSeconds` | `1200` | The gate does not evaluate until this long after the branch was pushed. |
| `waitTimeoutSeconds` | `2700` | Total time the gate may wait before it returns NO-GO. |
| `repositoryId` | calling repository | GitHub repository node ID (`R_kgDO...`). |
| `runsOn` | `ubuntu-latest` | Runner label. |

The workflow has one output, `result`, which is `GO` or `NO-GO`.

## Running the script directly

Set `CYCODE_CLIENT_ID` and `CYCODE_CLIENT_SECRET` in the environment. Also set `GITHUB_TOKEN` or `GH_TOKEN` to a token that can read the repository, which the gate uses to match Secrets to the branch. Then:

```bash
python3 scripts/cycode_release_gate.py \
  --repo-id "$(gh api repos/OWNER/REPO --jq .node_id)" \
  --repo-name OWNER/REPO \
  --branch my-service-1.4.0 \
  --project-id 12345
```

| Exit code | Meaning |
|---|---|
| `0` | GO. Every gated scanner has zero open violations at or above its threshold. |
| `1` | NO-GO. Blocking violations were found. |
| `2` | NO-GO. The gate could not evaluate. |

Run it with `--help` for every option. Each option can also be set through a `GATE_*` environment variable.

## Timing

Cycode gives no signal that a scan's findings are fully published. A scan can show Completed before its findings appear as violations, and counts can change for several minutes while findings are ingested. The gate handles this by waiting:

- It does not evaluate until 20 minutes after the branch was pushed (`minAgeSeconds`).
- It then reads the counts until they have stayed unchanged for five minutes.
- It returns NO-GO if it cannot settle within 45 minutes (`waitTimeoutSeconds`).

In testing, findings were fully published 13 to 25 minutes after a push. Plan for 25 to 30 minutes between pushing a release branch and an answer.

## How Secrets are matched to a branch

Cycode records a secret against the commit that added it and the branch where that commit was first pushed. A release branch that shares history with an earlier branch holds the same secrets, but they stay recorded against the earlier branch. A count on the recorded branch alone would leave them out.

The gate therefore works from the repository's open secrets:

1. It lists the open secrets in the repository.
2. For each commit those secrets were added in, it asks GitHub whether the commit is in the release branch's history. That is one request per commit.
3. It counts the secrets whose commit is in the branch.

Things to know:

- **It needs a GitHub token with read access.** The workflow passes its own `github.token`. Without a token the gate returns NO-GO.
- **It follows history, not the current files.** A secret added by an earlier commit and removed by a later one still counts while Cycode shows it as open.
- **`secretsBy: branch`** counts only the secrets Cycode records against the branch. **`repositoryScope: secrets`** counts every open secret in the repository.
- **Outside GitHub** the same check is `git merge-base --is-ancestor <commit> <branch>` in a clone of the repository.

## Thresholds and exceptions

- **A threshold is a severity floor for one scanner.** The gate allows no open violations at that severity or above.
- **SCA has two thresholds.** Dependency findings and license findings are judged separately, as in the console.
- **Exceptions stay in Cycode.** Ignore the violation, or use an ignore workflow so that the exception also applies to later release branches. An ignored violation is not open, so the gate does not count it.

## Notes and limits

- **Scan records exist for SCA and IaC only.** The gate waits for those two. SAST and Secrets scans of a push leave no scan record, so for those scanners the gate cannot tell a branch that was not scanned from a clean one. Make sure your SAST branch rule matches your release branches.
- **A full SAST scan can be requested.** `triggerScans: sast` asks Cycode for a full SAST scan of the branch and waits for it. Allow extra time for the scan and for its findings to be published.
- **`triggerScans` does not accept `secrets`.** An on-demand Secrets scan covers the whole repository, not one branch.
- **CI/CD findings are not gated.** They describe the repository and the organization, not a release branch.
- **Check the gate against the console first.** Before you rely on it, compare its counts for one release branch with the Violations page filtered to the same repository and branch.
- **Self-hosted runners** need Actions Runner 2.327.1 or newer for the actions used here.

## API endpoints used

The Cycode endpoints are all in the Cycode API reference.

| Endpoint | Used for |
|---|---|
| `POST /api/v1/auth/api-token` | Authentication with the service account |
| `GET /v4/scans` | Scan status of the branch |
| `POST /v4/scans` | On-demand scan, only with `triggerScans` |
| `GET /v4/scans/pull-request-scoped-settings/Project/{projectId}` | Thresholds from the project's PR settings |
| `GET /v4/violations/count` | Open violation counts by severity |
| `GET /v4/violations` | Split of SCA findings into dependencies and licenses, and the repository's open secrets with their commits |

The gate also calls two GitHub REST endpoints with the workflow's token: `GET /repos/{owner}/{repo}/git/ref/heads/{branch}` and `GET /repos/{owner}/{repo}/compare/{commit}...{branch}`.

## Using it across repositories

This example keeps the script and the workflow in one repository. The workflow checks out the script from the repository it runs in, so calling it from another repository does not work as it is.

To share one copy across many repositories, repackage it as a composite action: an `action.yml` next to the script that runs it from `${{ github.action_path }}`. The other option is to change the checkout step so that it fetches the script from a central repository at a pinned tag.
