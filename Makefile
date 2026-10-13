.PHONY: verify typecheck verify-dependencies

verify:
	node tools/verify.mjs --case="$(CASE)" --mode="$(MODE)"

typecheck:
	npm run typecheck

verify-dependencies:
	node --test tests/contracts/dependency-direction.test.mjs
	node tools/check-dependency-direction.mjs
