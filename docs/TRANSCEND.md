# Transcend submission check

Hackathon: [Life After Code: The path to production at the speed of imagination](https://gitlab-transcend.devpost.com/) (GitLab Transcend, October 2026).

Binding source when pages disagree: [Official Rules](https://gitlab-transcend.devpost.com/rules) §11. Other pages used below: [hackathon home](https://gitlab-transcend.devpost.com/), [resources](https://gitlab-transcend.devpost.com/resources), [contributor onboarding](https://contributors.gitlab.com/transcend-hackathon).

This file describes the repository after the submission-prep changes. Nothing here has been submitted to Devpost or GitLab.

## Deadline

| Source | Submission deadline |
| --- | --- |
| [Official Rules §1](https://gitlab-transcend.devpost.com/rules) | 27 October 2026, 1:00 pm UTC |
| [Home page](https://gitlab-transcend.devpost.com/) | 27 October 2026, 9:00 am EDT, also written as 1:00 pm UTC |
| [Contributor page](https://contributors.gitlab.com/transcend-hackathon) | 27 October 2026, 14:00 UTC |

Use the rules page. 14:00 UTC is one hour later. Judging on the rules page ends 14 November 2026, 5:00 pm UTC. The contributor page says 11 November 2026. Winners are announced on or around 16 November 2026 on both pages.

Registration opened 29 September 2026, 10:00 UTC. The submission window opened 5 October 2026, 10:00 UTC ([rules §1](https://gitlab-transcend.devpost.com/rules)).

## Which path

The first public commit on this repository is `4a85b71`, authored 13 October 2026. That is inside the submission window.

[Path A](https://gitlab-transcend.devpost.com/) is new work created for the hackathon. Deployment is optional. [Path B](https://gitlab-transcend.devpost.com/rules) is an existing MIT project, imported to GitLab, with new automation and a public deployment, both done on or after 5 October 2026.

Enter Path A unless a judge treats the existing GitHub repository as a pre-hackathon project. Path B then also needs the original project URL (`https://github.com/Darren-dev141/agent-action-auditor`) and a live URL through the winners announcement.

Suggested autonomy: **Assisted**. The Duo flow in `.gitlab/duo/flows/audit-trace.yml` waits for approval before `node ci-gate.js` runs ([Assisted example](https://gitlab-transcend.devpost.com/rules)). The CI job `audit-gate` is deterministic and does not ask for approval; it is the gate, not a hands-off agent.

## Requirements

| Requirement | Source | Repo status | If not met, one-line fix |
| --- | --- | --- | --- |
| Post-code DevSecOps automation (review, test, security, compliance, deploy, monitor, or similar) | [Rules §4](https://gitlab-transcend.devpost.com/rules), [home](https://gitlab-transcend.devpost.com/) | Met for verify, secure, release, and govern. The engine flags uncorroborated irreversible calls, repeated calls, secret-shaped values, missing read-back, replayed destructive calls, and unsupported completion claims. `ci-gate.js` exits 10 on a HIGH finding. Not met for plan, create, package, configure, or monitor. | Add one real stage only if you have a working check for it; do not relabel the current gate. |
| Use GitLab Duo Agent Platform (agents, flows, or MCP clients) | [Home](https://gitlab-transcend.devpost.com/), [resources](https://gitlab-transcend.devpost.com/resources), [rules §6 stage one](https://gitlab-transcend.devpost.com/rules) | Partial. The repo contains a custom flow, an MCP client config, an Agent Skill, `AGENTS.md`, MR review instructions, and flow CI setup. None of them have been executed on GitLab. | In the provisioned project, paste `.gitlab/duo/flows/audit-trace.yml` into New flow, enable it, and run it once. |
| One of Assisted, Supervised, or Hands-off | [Rules §4](https://gitlab-transcend.devpost.com/rules) | Met as Assisted, on the flow file. The owner still chooses the prize category on the form. | Select Assisted on the Devpost form. |
| Project installs and runs as described | [Rules §4 Functionality](https://gitlab-transcend.devpost.com/rules) | Met locally. `npm ci` then `npm test` passes. See the README quickstart. | None for the local CLI. GitLab CI has not run yet. |
| English materials | [Rules §4](https://gitlab-transcend.devpost.com/rules) | Met. | None. |
| Text description of features and how GitLab automates the post-code lifecycle | [Rules §4](https://gitlab-transcend.devpost.com/rules), [home "What to Submit"](https://gitlab-transcend.devpost.com/) | Draft is in `docs/DEVPOST.md`. It is not on the form. | Paste `docs/DEVPOST.md` into the Devpost form. |
| Public GitLab repository with source, assets, and run instructions | [Rules §4](https://gitlab-transcend.devpost.com/rules) | Gap. This checkout is the GitHub remote. | Push the default branch to the hackathon GitLab project and set the project to public. |
| MIT `LICENSE` at the repo root, visible in the About section | [Rules §4](https://gitlab-transcend.devpost.com/rules), [resources](https://gitlab-transcend.devpost.com/resources) | The file is met (`LICENSE`, MIT, copyright Darren Foote, 2026). About visibility is a GitLab UI fact. | After the push, confirm the project About section shows MIT. |
| Third-party code is OSI-licensed | [Rules §4](https://gitlab-transcend.devpost.com/rules) | Met. `@modelcontextprotocol/server` and `client` are Apache-2.0. Playwright, used only in CI, is Apache-2.0. | None under the rules. The resources FAQ also says everything must be MIT; if a judge enforces that sentence, email shawni@devpost.com and point at rules §4. |
| Visible CI/CD pipeline history showing the automation running | [Rules §4](https://gitlab-transcend.devpost.com/rules), [home](https://gitlab-transcend.devpost.com/) | Partial. `.gitlab-ci.yml` runs `npm test` (including the two Playwright tests) and `audit-gate` (clean trace exits 0, violating trace must exit 10). No pipeline has run on GitLab. | Push to the hackathon project and confirm both jobs are green. |
| Demo video under 3 minutes, YouTube, public or unlisted, project actually running, no third-party trademarks or copyrighted music | [Rules §4](https://gitlab-transcend.devpost.com/rules), [resources](https://gitlab-transcend.devpost.com/resources) | Gap. Script is in `docs/DEVPOST.md`. | Record that script, upload it, and put the URL on the form. |
| Devpost registration and GitLab contributor onboarding | [Rules §4](https://gitlab-transcend.devpost.com/rules), [contributor page](https://contributors.gitlab.com/transcend-hackathon) | Gap. | Register on Devpost, submit the Devpost username on the contributor card, and wait for the subgroup. |
| Free access for judges through the end of judging | [Rules §4 Testing](https://gitlab-transcend.devpost.com/rules) | Met for the code once the GitLab project is public. No account is required to run the CLI. | Keep the GitLab project public through judging. |
| Google Cloud deployment for up to 0.2 bonus points | [Rules §6 stage three](https://gitlab-transcend.devpost.com/rules) | Gap, optional. Path A does not require any deployment. | Deploy, commit the deployment files, and add the live URL on the form. |
| Path B live URL until about 16 November 2026, plus the original MIT URL | [Rules §4](https://gitlab-transcend.devpost.com/rules) | Not applicable if you enter Path A. | If you enter Path B, deploy somewhere public and keep it up. |
| Most Environmentally Impactful prize (opt-in, SCI measurement) | [Rules §8](https://gitlab-transcend.devpost.com/rules), [resources](https://gitlab-transcend.devpost.com/resources) | Not claimed. There is no Software Carbon Intensity number. | Leave the prize unchecked. |
| Developer Certificate of Origin 1.1 on submission code | [Rules §4 IP](https://gitlab-transcend.devpost.com/rules) | Gap for future GitLab commits. | Use `git commit -s` on commits you push to the GitLab project. |
| Eligibility (age of majority; excluded locations listed in rules §3) | [Rules §3](https://gitlab-transcend.devpost.com/rules) | Owner-only. | Read rules §3 before registering. |

## What the repo meets today

- MIT license file at the root, and `package.json` `"license": "MIT"` with `"private": false`.
- A local quickstart: `npm ci`, `npm test`, `node audit.js`. Node.js 20.19 or newer.
- The same rule engine for the CLI, `ci-gate.js`, Claude Code hooks, the stdio MCP server, and the static browser page.
- Exit codes a pipeline can use: 0, 10, 11, and 2.
- GitLab CI config that runs the Node suite, the fixture validator, replay determinism, the security scan, and the two Playwright tests on `mcr.microsoft.com/playwright:v1.64.0-noble`.
- Duo Agent Platform files that do not need an account to exist in the tree:
  - `.gitlab/duo/flows/audit-trace.yml` (flow registry v1, `environment: ambient`)
  - `.gitlab/duo/mcp.json` (stdio MCP client for `mcp-server.js`)
  - `.gitlab/duo/agent-config.yml` (`npm ci` before a flow runs in CI)
  - `.gitlab/duo/mr-review-instructions.yaml` (Code Review Flow)
  - `skills/audit-agent-trace/SKILL.md` and `AGENTS.md`
- Draft form copy and a timed demo script in `docs/DEVPOST.md`.

Local `npm test` still skips the two browser tests when Playwright or Chrome is absent. The CI job installs Playwright 1.64.0 and points `AAA_CHROME` at that image's Chromium, so those two tests are not skipped there. They were run locally against Playwright Chromium 1.64.0 during this change: 2 passed, 0 skipped.

## Judging criteria, scored only after stage one

Stage one is pass/fail: the project fits the theme and uses GitLab Duo Agent Platform ([rules §6](https://gitlab-transcend.devpost.com/rules)). The five stage-two criteria are equally weighted ([home](https://gitlab-transcend.devpost.com/)):

| Criterion | Where this repo stands |
| --- | --- |
| Technological implementation | CI config and the gate are real. Duo use is files until the flow is enabled and run. |
| Design | CLI, CI gate, hooks, MCP, and browser are one workflow. The Duo approval step is not wired to a live GitLab project yet. |
| Potential impact | The audience is someone shipping an agent that can delete, send, or leak a secret-shaped value. The rules are a fixed list, documented in the README and `SPEC-v1.md`. |
| Innovation | Deterministic trace checks, not another chat review. Novelty is for the judges. |
| Presentation | No video yet. Script is in `docs/DEVPOST.md`. |

Google Cloud is a separate 0.2 after that score. Maximum final score on the rules page is 5.2.

## Gaps that need the owner

These need a Devpost account, a GitLab account, a recording, or a decision. They are not done here.

1. Register on [Devpost](https://gitlab-transcend.devpost.com/) and on the [contributor card](https://contributors.gitlab.com/transcend-hackathon). One-line fix: submit the Devpost username and wait for the subgroup.
2. Push this repository to that public GitLab project. One-line fix: push the default branch and confirm `test` and `audit-gate` are green.
3. Confirm MIT shows in the GitLab About section. One-line fix: open the project page after the push and check About.
4. Create and enable the custom flow, then run it once so pipeline history shows Duo, not only the Node jobs. One-line fix: paste `.gitlab/duo/flows/audit-trace.yml` into New flow and mention the flow's service account on an issue. Creating a flow needs Maintainer on current GitLab docs; the contributor page says the provisioned role is Developer, and the resources FAQ says Developer + AI. If New flow is missing, ask in `#transcend-hackathon`.
5. Merge `.gitlab/duo/agent-config.yml` to the default branch before expecting `npm ci` in a flow run. One-line fix: merge it; flow execution ignores other branches.
6. Restart the GitLab Duo CLI or IDE after the MCP file is on the default branch. One-line fix: reopen the project so Duo loads `.gitlab/duo/mcp.json`.
7. Check GitLab Credits before a Duo run (500 credits per month on the resources page). One-line fix: open the credits dashboard first.
8. Sign commits pushed to GitLab under DCO 1.1. One-line fix: `git commit -s`.
9. Record the video from `docs/DEVPOST.md` and upload it to YouTube as public or unlisted. One-line fix: keep it under three minutes and leave trademarks and music out.
10. Paste the description, GitLab URL, and YouTube URL into the Devpost form before 27 October 2026, 1:00 pm UTC. One-line fix: submit the form yourself; this prep does not submit it.
11. Choose Path A on the form, or switch to Path B and add a live deployment plus the original GitHub URL. One-line fix: pick Path A unless you are deploying.
12. Optional: Google Cloud bonus. One-line fix: add deployment files and a public URL, or skip the 0.2.
13. Optional prize: Most Environmentally Impactful. One-line fix: leave it unchecked.
14. After the deadline, do not edit the submitted repo, video, or form ([resources](https://gitlab-transcend.devpost.com/resources)). One-line fix: fork if you want to keep changing it.
15. Confirm you are allowed to enter under rules §3. One-line fix: read the excluded-locations list before you register.

## Sources

- [Life After Code hackathon home](https://gitlab-transcend.devpost.com/)
- [Official Rules](https://gitlab-transcend.devpost.com/rules)
- [Resources and FAQ](https://gitlab-transcend.devpost.com/resources)
- [Transcend Hackathon contributor page](https://contributors.gitlab.com/transcend-hackathon)
- [Custom flows](https://docs.gitlab.com/user/duo_agent_platform/flows/custom/)
- [Custom flow YAML schema](https://docs.gitlab.com/user/duo_agent_platform/flows/custom_flows_schema/)
- [Flow registry v1](https://docs.gitlab.com/user/duo_agent_platform/flows/claude-edit-v1-flow-registry/)
- [Flow execution and agent-config.yml](https://docs.gitlab.com/user/duo_agent_platform/flows/execution/)
- [GitLab MCP clients](https://docs.gitlab.com/user/gitlab_duo/model_context_protocol/mcp_clients/)
- [Agent Skills](https://docs.gitlab.com/user/duo_agent_platform/customize/agent_skills/)
- [MR review instructions](https://docs.gitlab.com/user/duo_agent_platform/customize/review_instructions/)
- [Playwright Docker images](https://playwright.dev/docs/docker)
- [DevSecOps lifecycle](https://about.gitlab.com/topics/devops/#the-dev-ops-lifecycle-and-how-dev-ops-works) (linked from rules §8)
