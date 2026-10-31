# Container releases

The `Release` workflow builds AMD64 on `ubuntu-24.04` and ARM64 on
`ubuntu-24.04-arm`. Each platform builds natively. CI builds and smoke-tests
both architectures, and the required `Container build` check passes only
when both succeed.

Platform images are pushed by digest. Once both builds succeed, the workflow
combines them into one image index and publishes the version, minor, major,
and `latest` tags. Platform caches have separate scopes so an AMD64 build
does not replace ARM64's cache.

## Publish a new release

1. Merge the version-preparation PR and wait for CI to pass.
2. Create and push the matching tag, such as `v1.5.9`. This starts the separate
   PyPI workflow, including its configured environment approval.
3. Publish the GitHub release for that tag. This starts the container workflow.

The container workflow checks that the tag identifies a published stable
release, matches the package version, and is the latest release before updating
the shared image tags. It resolves the tag once and builds both platforms from
that same commit.

## Recover a failed container release

For a transient package-mirror or network failure, rerun the failed container
workflow. Keep package checksum verification enabled.

If recovery needs a workflow fix, first merge that fix into `main`, then use
the updated workflow to rebuild the existing release:

```bash
gh workflow run release.yml --repo calebevans/mulder --ref main -f tag=v1.5.9
```

The dispatch uses the workflow from `main` and the application/Dockerfile from
the verified release tag. It does not move the tag or rerun PyPI publishing.
Rerunning an old workflow run would continue to use its old workflow definition.
Changes to the application's Dockerfile or source require a new release; this
recovery path applies workflow fixes to the existing release source.

Release notes remain on the GitHub release.
