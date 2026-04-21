# NGDC -- 2012 National Gallery DC Scenario

## Scenario

The [2012 National Gallery DC scenario](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/) is a multi-device forensic investigation spanning approximately 10 days. The published scenario contains three intertwined storylines centered around the National Gallery of Art in Washington, DC: an artwork-defacement plot (Alex, a Krasnovian planner, working through Carry), a stamp-theft conspiracy (Tracy, her brother Pat, and Carry/Coral), and unauthorized surveillance of Tracy via a kernel-level keylogger installed by her ex-husband Joe. Evidence is distributed across disk images, mobile devices, network captures, and email logs from multiple suspects.

**Source:** [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/) (free download, ~112 GB)

## Evidence Analyzed

| Evidence Type | Description |
|---------------|-------------|
| Disk images (E01) | Tracy's MacBook Air (HFS+) and external USB drive (exFAT), daily snapshots across ~10 days |
| Mobile images | Tracy's phone, Carry's phone (Samsung Nexus S) and tablet (ASUS Transformer TF101), multiple daily snapshots in E01, tar, and logical-ZIP formats |
| Network captures | NGDC interior and exterior traffic on July 6, 9, 10, 12 |
| Email logs | Keylogger (LogKext) output mailed via Postfix to joe.sum.twelve@gmail.com |

## Model Comparison

This scenario was run with two different models to compare investigative approaches. Sonnet run used Sonnet 4.6 (1M context, max effort) via Claude Code v2.1.114.

| Metric | Opus | Sonnet |
|--------|------|--------|
| Findings | 12 (7 crit, 3 high) | 19 (11 crit, 5 high) |
| Confirmed / Inference | 9 / 3 | 14 / 5 |
| Tool calls | 159 | 402 |
| Wall-clock time | ~28 min | ~1.4 hours |
| Steganography | Not detected | Detected jphide in 6 photos, extracted payload sizes |
| Gravelly Point dead drop | Not found | Identified via GPS + trail map in photo |
| Greece GPS data | Not found | Found on Tracy's iPhone |
| VirtualBox + "VMs" email | Not connected | Connected Perry's email to VBox download |
| Narrative style | Conservative, evidence-focused | Analytical, intelligence-assessment style |

**Opus** was faster and more conservative -- fewer findings, all tightly evidence-backed, minimal inference.

**Sonnet** was more thorough and analytical -- nearly 2x the tool calls, more willing to draw inferences (Gravelly Point as a dead drop, Greece GPS as foreign contact, m57.biz as possible foreign entity).

## Ground Truth Comparison

The scenario narrative is [published on Digital Corpora](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/). Community write-ups are available from [Medium](https://medium.com/@brsdncr/the-2012-national-gallery-dc-scenario-phase-ii-d6781b4aba4f) and [GitHub](https://github.com/jilek/iPhone_Forensics).

The published scenario describes three intertwined storylines: (1) an artwork-defacement plot (Alex, a Krasnovian planner, working through Carry), (2) a stamp-theft conspiracy (Tracy, her brother Pat, and Carry/Coral), and (3) unauthorized surveillance via Joe's keylogger. Both models largely reconstructed (2) and (3). Sonnet came closer to surfacing (1) by identifying intelligence tradecraft (steganography, dead drops, foreign GPS data) but did not explicitly name the defacement plot or Alex's role as orchestrator.

## Output Files

### Opus

- [HTML report](https://calebevans.github.io/mulder/examples/ngdc/opus/ngdc.report.html)
- [`opus/ngdc.report.md`](opus/ngdc.report.md) -- Markdown report
- [`opus/claude.log`](opus/claude.log) -- Claude Code session log

### Sonnet

- [HTML report](https://calebevans.github.io/mulder/examples/ngdc/sonnet/ngdc.report.html)
- [`sonnet/ngdc.report.md`](sonnet/ngdc.report.md) -- Markdown report
- [`sonnet/claude.log`](sonnet/claude.log) -- Claude Code session log
