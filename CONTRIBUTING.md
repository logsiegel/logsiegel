# Contributing to Logsiegel

Thanks for your interest in contributing.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
By signing off your commits you certify that you have the right to submit the
contribution under the project's license (Apache 2.0).

Sign off every commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <your@email>` line. Pull requests with
unsigned commits cannot be merged.

## Practical notes

- Run the test suite before opening a PR: `pytest`
- Keep changes small and focused; one topic per PR.
- The event format and receipt format are considered stable evidence formats —
  changes to them need an issue and discussion first.
