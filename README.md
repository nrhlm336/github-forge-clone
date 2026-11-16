# github-forge-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/nrhlm336/github-forge-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/nrhlm336/github-forge-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single TypeScript file (`app.ts`, Node standard library only): git smart HTTP (upload-pack protocol v2 and v0, receive-pack v0 with report-status and sideband), the REST v3 surface (repos, contents, branches, refs, labels, issues, comments, pull requests and merges), the GraphQL v4 subset that `gh` and github-mcp-server speak (including introspection, Relay global ids, cursor pagination and batching), and an MCP endpoint (streamable HTTP, revision 2026-07-28 plus the legacy initialize handshake). One in-memory content-addressed object store is shared by every surface, and all server-made commits use a deterministic logical clock, so the same request sequence always produces the same object ids.

## Run it

```sh
MAKEFUN_ENV_URL=http://localhost:8080 node main.ts
```

---

<sub>Entered on [make.fun](https://make.fun/?ref=tg8yhnf0&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
