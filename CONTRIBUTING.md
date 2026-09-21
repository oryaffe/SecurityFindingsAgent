# Contributing

Thank you for helping improve Security Findings Agent.

## Before proposing changes

Read the [architecture](docs/architecture.md), [security policy](SECURITY.md), and [current license notice](LICENSE). No open-source license has been selected yet; coordinate with the maintainer before submitting contributions intended for redistribution.

Keep changes focused on a concrete problem. Preserve the existing agent architecture, authentication behavior, authorization scope, database schema, and retrieval behavior unless a change is explicitly agreed.

## Bug reports

For non-sensitive bugs, open an issue with a short title, affected commit, OS/Python version, sanitized reproduction steps, expected/actual behavior, and relevant redacted logs. Use synthetic data. Security vulnerabilities must follow the private route in SECURITY.md.

## Development workflow

1. Follow the installation guide using your own local environment and demo database.
2. Create a focused branch.
3. Make the smallest change that addresses the problem.
4. Perform the relevant checks from the validation guide.
5. Update documentation if behavior or configuration changes.
6. Review the staged diff for secrets and generated data before committing.
7. Submit a pull request describing the problem, change, tests actually run, and limitations.

Do not add cloud resources, new frameworks, Docker, or broad refactoring as incidental changes. For deployment-related code changes, explain why the change is required, what existing behavior it may affect, and how regression will be checked.

No standard automated test command or CI workflow is established by this project. Do not claim tests pass without running the relevant project checks.
