# Maintainer Annotations

**Maintainer Annotations** let maintainers add context to display alongside Scorecard check results. Annotations can provide users additional information when Scorecard has an incomplete assessment of a project's security practices.

## Annotating Your Project

To annotate your repository, create a `scorecard.yml` file in the root of your repository.
> You can also place your annotations in `.scorecard.yml` or `.github/scorecard.yml`.

The file structure is as follows:

```yml
annotations:
  - checks:
      - binary-artifacts
    reasons:
      - reason: test-data # the binary files are only used for testing
  - checks:
      - dangerous-workflow
    reasons:
      - reason: remediated # the workflow is dangerous but only run under maintainers verification and approval
```

You can annotate multiple checks at a time:

```yml
annotations:
  - checks:
      - binary-artifacts
      - pinned-dependencies
    reasons:
      - reason: test-data # the binary files and files with unpinned dependencies are only used for testing
```

And also provide multiple annotations for checks:

```yml
annotations:
  - checks:
      - binary-artifacts
    reasons:
      - reason: test-data # test.exe is only used for testing 
      - reason: remediated # dependency.exe is needed and it's used but the binary signature is verified
```

The available checks are the Scorecard checks in lower case e.g. Binary-Artifacts is `binary-artifacts`.

## Types of Annotations

The annotations are predefined as shown in the table below:

| Annotation | Description | Example |
|------------|-------------|---------|
| test-data | A check or probe has found a security issue in files or code snippets only used for test or example purposes. | The binary files are only used for testing. |
| remediated | To annotate when a check or probe has found a security issue to which a remediation was already applied. | A workflow is dangerous but only run under maintainers verification and approval, or a binary is needed but it is signed or has provenance. |
| not-applicable | To annotate when a check or probe is not applicable for the case. | The dependencies should not be pinned because the project is a library. |
| not-supported | To annotate when the maintainer fulfills a check or probe in a way that is not supported by Scorecard. | Clang-Tidy is used as SAST tool but not identified because its not supported. |
| not-detected | To annotate when the maintainer fulfills a check or probe in a way that is supported by Scorecard but not identified. | Dependabot is configured in the repository settings and not in a file. |

## Viewing Maintainer Annotations

To see the maintainers annotations for each check on Scorecard results, use the `--show-annotations` option.

# Token-Permissions Allowed Writes

The Token-Permissions check warns about job-level write permissions, unless the workflow uses a
packaging or release action that Scorecard recognizes. Maintainers can accept a job-level write
permission in the same `scorecard.yml` file, for jobs that use a specific action or reusable workflow,
or for a specific job:

```yml
token-permissions:
  allowed-writes:
    - permission: packages
      uses: actions/delete-package-versions
      reason: Deletes old container images from GHCR
    - permission: contents
      uses: octo-org/workflows/.github/workflows/release.yml
      reason: The remote reusable workflow creates GitHub releases
    - permission: contents
      workflow: .github/workflows/publish.yml
      job: publish-github
      reason: Creates the GitHub release with a shell script
```

- `permission` is one of `actions`, `checks`, `contents`, `deployments`, `packages`, `security-events` or `statuses`.
- Set either `uses`, or `workflow` and `job`:
  - `uses` is an action, a remote reusable workflow or a local reusable workflow, without a ref.
    A remote reference matches any ref. A local reusable workflow must match exactly.
    The rule applies to every job that uses it in a step, or that calls the reusable workflow.
  - `workflow` is the path of the workflow file in `.github/workflows/`, and `job` is the job ID.
    Use it when the job needs the permission for a `run` step, which Scorecard cannot identify.
- `reason` is required and is shown in the debug details of the check.

A rule applies only to jobs that declare the permission as `write`. Other jobs in the same workflow
file still get the warning. Top-level write permissions are never accepted.

A job that calls a local reusable workflow (`uses: ./.github/workflows/...`) does not need a rule.
GitHub requires the caller to grant the write permissions that the called jobs declare, so the check
accepts a caller's write when the called workflow declares the same write. The check reports the write
in the called workflow instead, where it is used. To accept it there, add a rule for the action that
the called job uses.
