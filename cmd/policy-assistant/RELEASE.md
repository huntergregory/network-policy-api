# Release Process

## Overview

The Policy Assistant release (releases with the `pola` suffix like `v0.0.1-pola`) has the following components:
- `pola` Command-Line Interface (CLI) tool for developing and troubleshooting policy 
- Corresponding Go bindings for Policy Assistant (`sigs.k8s.io/network-policy-api/policy-assistant` Go package)

## Versioning strategy

Versioning strategy is a work-in-progress.

For initial releases, please do not rely on raw text output for mission-critical workflows.

### Patch version (e.g. v0.0.1-pola -> v0.0.2-pola)

### Minor version (e.g. v0.0.4-pola -> v0.1.1-pola)

### Major version (e.g. v0.5.1-pola to v1.0.1-pola)

## Releasing a new version

### Writing a Changelog

ToDo: provide guidance for this sub-project.

### Release Steps

The following steps must be done by one of the [network-policy API maintainers][network-policy-api-team]:

- Create a new branch in your fork named something like `<githubuser>/release-x.x.x-pola`. Use the new branch
  in the upcoming steps.
- Use `git` to cherry-pick all relevant PRs into your branch (any changes to cmd/policy-assistant/ or the pola GH action under .github/)
- Update `pkg/generator/main.go` with the new semver tag and any updates to the API review URL.
- Create a pull request of the `<githubuser>/release-x.x.x-pola` branch into the `release-x.x-pola` branch upstream
  (which should already exist since this is a patch release). Add a hold on this PR waiting for at least
  one maintainer/codeowner to provide a `lgtm`.
- Verify the CI tests pass and merge the PR into `release-x.x-pola`.
- Create a tag using the `HEAD` of the `release-x.x-pola` branch. This can be done using the `git` CLI or
  Github's [release][release] page.
- Write a changelog for the new release in a local CHANGELOG.md in this cmd/policy-assistant/ directory.
- Use goreleaser to publish the release (see section below).

For a **MAJOR** or **MINOR** release:

- Cut a `release-major.minor-pola` branch that we can tag things in as needed.
- Check out the `release-major.minor-pola` release branch locally.
- Update `pkg/generator/main.go` with the new semver tag and any updates to the API review URL.
- Verify the CI tests pass before continuing.
- Create a tag using the `HEAD` of the `release-x.x-pola` branch. This can be done using the `git` CLI or
  Github's [release][release] page.
- Write a changelog for the new release in a local CHANGELOG.md in this cmd/policy-assistant/ directory.
- Use goreleaser to publish the release (see section below).

#### GoReleaser

See https://goreleaser.com/quick-start/

Follow steps to export your GH token and finally run `goreleaser release`.

[release]: https://github.com/kubernetes-sigs/network-policy-api/releases
[network-policy-api-team]: https://github.com/kubernetes/org/blob/main/config/kubernetes-sigs/sig-network/teams.yaml
