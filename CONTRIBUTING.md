# Contributing

Thanks for wanting to contribute! Please follow these guidelines to make collaboration smooth.

- Required reviews: 1 approving review for PRs targeting `main`.
- CI: All PRs must pass CI (status check name: `go-ci`).
- Keep branches up-to-date: Rebase or merge main into your branch if required by the branch protection.
- Tests: Run `go test ./...` locally and ensure linting (`gofmt`, `golangci-lint`) passes.
- Commit messages: Use clear messages. Include `Signed-off-by: Your Name <email>` or use `git commit -s` if you follow DCO; maintainers may request sign-off for contribution acceptance.

Steps to submit a PR:
1. Fork the repo and create a branch from `main`.
2. Make changes, run tests and linters locally.
3. Push your branch and open a Pull Request describing the changes.
4. Address review comments; once approved and CI passes, the PR will be merged.

For security issues, see [SECURITY.md](SECURITY.md).
