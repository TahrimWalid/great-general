# Notice: the generals and their licences

great-general's own files (SKILL.md, scripts, references, evals, assets) were written for this project. The generals it deploys are third-party works. This skill doesn't include their text: `generals.py` fetches them from their upstream repositories at pinned commits, and keeps each one's own LICENSE file with it.

| General(s) | Upstream | Licence | Pinned commit (as shipped) |
|---|---|---|---|
| anthropic-security-review | github.com/anthropics/claude-code-security-review | MIT, © 2025 Anthropic | 0c6a49f1fa56a1d472575da86a94dbc1edb78eda |
| cloudflare-security-audit | github.com/cloudflare/security-audit-skill | MIT, © Cloudflare | c1c8a8c1471069fb0e188eeaff69b8e8db6564a8 |
| tob-* (9 plugins) | github.com/trailofbits/skills | Creative Commons Attribution-ShareAlike 4.0 International. Made by Trail of Bits. | 149d7b21f4067765b82e67029730b42d228ef4b4 |
| claude-security | Anthropic product (Claude Enterprise) | Proprietary; not redistributed | n/a |

The method in `references/` that describes how to run and filter a security review is adapted, in new wording, from the MIT-licensed claude-code-security-review and security-audit-skill projects. No Trail of Bits text is adapted into great-general's own files.

If you redistribute a bundle of pinned generals, keep every general's LICENSE file and this notice with it. Trail of Bits material must stay under CC-BY-SA-4.0 with attribution. Don't modify it in place: pin, vet and approve a new upstream commit instead.
