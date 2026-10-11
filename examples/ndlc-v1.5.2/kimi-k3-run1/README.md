# NDLC on Kimi K3, run 1 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/us.moonshotai.kimi-k3` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 7 | 35% |
| PARTIAL | 11 | 55% |
| MISSED | 1 | 5% |
| FALSE POSITIVE | 5 | 25% |

**35% full match, 90% detection rate, 25% false positive rate.** One of three Kimi K3 runs on this image; see [run 2](../kimi-k3-run2/) (35% / 80% / 20%) and [run 3](../kimi-k3-run3/) (50% / 95% / 20%) for the spread.

## What the Model Concluded

- An insider, not an intrusion: the `informant` account (`iaman.informant@nist.gov`) researched "how to leak a secret", "anti-forensic tools", "DLP DRM", "windows event logs" and "security checkpoint cd-r", then moved the "Secret Project Data" tree from `\\10.11.11.128\secured_drive` (all eight directories, the V: mapping) onto two SanDisk Cruzer Fit sticks (serials 4C530012450531101593 and 4C530012550531106501) and a UDF CD-R "IAMAN CD" on 2015-03-24, with Google Drive set up as a possible fourth channel.
- Concealment: 17 Office documents renamed as .amr, .zip, .7z, .jpg, .avi, .svg, .png, .one, .gif and .txt on the FAT32 stick, every one typed by file signature; the same set burned to the disc across 9 sessions with folders shortened to de/pd/prog/prop/tr and three Windows sample photos added as decoys. The first run to extract and inspect the disc's files, identifying them as public NIST Govdocs corpus material standing in for classified data.
- Cleanup: Eraser 6.2.0.2962 and CCleaner 5.04 downloaded and run on 2015-03-25 with exact installer times; the system timezone (Eastern, UTC-4) stated for FAT-versus-UTC correlation; no malware, archivers, transfer tools, steganography or external logons found.
- Where it went wrong: three setup-day accounts read as backdoors; CCleaner credited with wiping browser history and both tools with deleting the stick's files a day after they were already gone; drive letters inverted (RM2 placed on D:, which is the burner, and a March 24 copy onto RM1, which was the source). None of the five documents is named, and the February 15 copy, iCloud's execution and the email correspondent are missing despite most being seen during the run.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 276 (53 disk, 223 other) |
| Total tool calls | 827 |
| Findings | 12 (1 critical, 5 high, 6 medium, 0 low, 0 info), 3 hypotheses ruled out |
| Confirmed / Inference | 10 / 2 |
| False positives | 5 |
| Runtime | 52 minutes |
| Model | bedrock/us.moonshotai.kimi-k3 (native reasoning) |
| Tokens | 200K output (LiteLLM does not report input tokens for this model) |
| Exit code | 0, all quality gates passed |
| Mulder | v1.5.2 |

## How It Was Run

Kimi K3 is absent from LiteLLM's model map, so its context window, output cap and reasoning support are supplied explicitly (see [Models LiteLLM does not know](../../../docs/usage-guide.md#models-litellm-does-not-know)):

```bash
docker run --privileged \
  -v /evidence:/evidence:ro -v cases:/home/mulder/.mulder/cases \
  -e AWS_REGION=us-west-2 \
  -e MULDER_MODEL_CONTEXT_WINDOW=262144 \
  -e MULDER_MODEL_MAX_OUTPUT_TOKENS=32768 \
  -e MULDER_MODEL_REASONING=1 \
  ghcr.io/calebevans/mulder:1.5.2 \
  mulder investigate /evidence ndlc --model bedrock/us.moonshotai.kimi-k3 --show-cli-stderr
```

Bedrock credentials came from the EC2 instance role.

## Evidence Dataset

| Field | Value |
|-------|-------|
| **Source** | [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) |
| **Answer Key** | [Published NIST ground truth (55 pages)](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) |
| **Accuracy Report** | [ACCURACY-REPORT.md](ACCURACY-REPORT.md) |

### Evidence Files

| File | Type | Size |
|------|------|------|
| cfreds_2015_data_leakage_pc.E01-.E04 | PC disk image (EnCase, 4 parts) | 7.3 GB |
| cfreds_2015_data_leakage_rm1.E01 | USB RM1 (exFAT, "Authorized USB") | 75 MB |
| cfreds_2015_data_leakage_rm2.E01 | USB RM2 (FAT32, "IAMAN $_@") | 243 MB |
| cfreds_2015_data_leakage_rm3_type3.E01 | CD-R RM3 (UDF) | 90 MB |

## Files in This Directory

| File | Description |
|------|-------------|
| `ndlc.report.md` | Full investigation report (Markdown) |
| `ndlc.report.html` | Investigation report (HTML with navigation) |
| `ndlc.audit.jsonl` | Structured tool execution audit log (863 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (4,062 lines) |
| `mulder.log` | MCP server tool execution log (1,220 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
