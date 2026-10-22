# Repository Instructions

## Project context

Build the Cloud Security Visualiser as a four-day MVP using Python, FastAPI,
NetworkX, React, TypeScript, and Cytoscape.js. Read `PRD.md` when present; this
repository currently uses `prd.md`. Public deployment is mandatory.

Prioritize, in order:

1. Correct security analysis.
2. Interactive infrastructure graph.
3. Scanning animation.
4. Animated attack-path visualisation.
5. Public deployment.

Do not introduce a database, WebSockets, authentication, microservices, or
additional features unless explicitly requested.

## Required coding skill

For every task involving writing, modifying, reviewing, debugging, or
refactoring code, first consult and follow
`.agents/skills/karpathy-guidelines/SKILL.md`.

Apply all four original principles: Think Before Coding, Simplicity First,
Surgical Changes, and Goal-Driven Execution. This reference supplements the
complete skill; it does not replace or shorten it.

## Simplicity

- Prefer the simplest correct solution.
- Avoid unnecessary abstractions, architecture layers, and dependencies.
- Do not add speculative functionality.
- Do not create helpers, classes, or interfaces without a clear need.
- Reuse existing functions and match the existing code style.
- Avoid premature optimization.

## Incremental implementation

- Implement only the task explicitly requested.
- Prefer changing one to three files per implementation task.
- Split large tasks into small, reviewable changes.
- Avoid unrelated refactoring or formatting.
- Preserve existing working functionality.
- Never proceed to the next task automatically.

## Correctness and verification

- Inspect existing code before modifying it.
- State significant assumptions instead of silently guessing.
- Define clear acceptance criteria for the requested change.
- Write or update focused tests where appropriate.
- Run relevant tests and report their exact results.
- Never claim success without verification.
- Do not silently modify unrelated failing code.

## Teaching requirement

After each task, explain:

1. Files changed and why.
2. Every function added or modified.
3. Its parameters and return values.
4. Its internal logic.
5. Where it is called.
6. How data flows through it.
7. Important algorithmic decisions.
8. How to verify the implementation.

Use small, concrete examples. Do not replace technical explanations with vague
summaries. After every implementation task, provide the exact commands needed
to install dependencies, run relevant tests, start the project, and exercise
the new functionality.

## Git safety

- Do not commit automatically.
- Do not reset or discard user changes.
- Do not alter unrelated files.
- Report exactly what changed.
- Wait for the user's instruction before proceeding.
