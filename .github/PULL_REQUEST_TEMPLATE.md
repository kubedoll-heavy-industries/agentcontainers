## Summary
<!-- What does this PR do? -->

## Test Plan
<!-- How did you verify this works? -->
- [ ] `go build ./... && go vet ./... && go test -race ./...`
- [ ] `cd enforcer && cargo check && cargo test`
- [ ] Docker/adversarial tests, if this touches runtime, dojo, network, or container behavior
- [ ] Docs-only or metadata-only change; full code test gate not applicable

## Checklist
- [ ] No secrets or credentials committed
- [ ] Tests added/updated for new functionality
- [ ] User-facing docs updated if behavior changed
- [ ] New contributor impact considered for setup, examples, or first-run behavior
