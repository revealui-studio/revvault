# Durable Solutions — Root Causes Only

**Status:** convention for every session, product, and internal change. There is
no one-off or hotfix exception.

## The rule

1. **Fix the owning primitive.** Change the shared code, configuration,
   bootstrap, policy, or product behavior that causes the failure class. Add
   tests or a gate where they can keep that class from returning.
2. **Do not ship one-off solutions.** Session-local patches, machine or env
   overrides, ad hoc operational scripts, symptom suppression, and parallel
   paths are prohibited. Owner acceptance or a registry entry does not turn
   one into an acceptable fix.
3. **Record blockers as durable work.** If the root fix cannot be completed in
   this session, identify the owning path, failing behavior, durable target,
   validation needed, and tracked follow-up. Do not offer an interim procedure
   that leaves the failure class open. A ticket records work; it is not a fix.
4. **Inventory existing one-offs.** Search the affected code and operating
   instructions for prior exceptions. Record each location, behavior, owner,
   durable destination, and removal evidence. The hotfix registry is a debt
   inventory for existing entries; it never authorizes a new one-off.
5. **Extend before create.** Harden the existing primitive instead of adding
   another resolver, seed script, gate bypass, or product path.

## Boundaries

| Shape | Treatment |
|-------|-----------|
| Env or machine override | Replace with a fix in the loader, bootstrap, or supported configuration model. |
| Session-only recipe | Keep it out of product and operating instructions; implement the durable behavior. |
| Symptom patch | Repair the cause rather than catch-and-ignore or disable a gate. |
| Parallel path | Converge on the owning primitive and remove the duplicate path. |
| Existing registered hotfix | Inventory it, track its durable replacement, and remove it after verification. |

Temporary read-only diagnostics and synthetic test fixtures can help establish
the cause. They are not product fixes and must not become operational
dependencies. If an operation is needed repeatedly, implement it in the owning
maintained tool with tests and normal review.

## Relationship to other conventions

- Extend-before-create identifies the owning primitive to improve.
- Temp-scripts rules govern the lifecycle of diagnostic files; they do not
  permit one-off operational fixes.
- Disposition rules still govern publication, deployment, and other external
  actions after a durable fix is ready.

## Fleet identity

The only fleet identity is `revealfleet`. Configuration namespaces use
`REVEALFLEET`. Preserve these exact spellings in paths, profiles, generated
output, documentation, and session communication. Abbreviations and alternate
aliases are prohibited. Rename maintained references in their owning primitive
and regenerate consumers. Preserve original historical evidence for recovery;
do not turn historical names into active aliases or repeat them in new output.
