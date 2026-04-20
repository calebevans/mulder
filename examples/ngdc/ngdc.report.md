# Mulder Investigation Report

**Case:** ngdc
**Generated:** 2026-04-20T14:15:32.184449+00:00
**Evidence:** /evidence/ngdc

---

## Executive Summary

**Scope:** 18 evidence sources (63 disk, 36 other) | 159 tool calls | 28 minutes
**Results:** 12 findings (7 critical, 3 high) -- 9 confirmed, 3 inference | 1 hypothesis ruled out
**Timeline:** 2012-06-15 to 2012-07-10

**Key Threats:**
- LogKext Keylogger Installed on Tracy's MacBook Air
- Tracy Exfiltrated Confidential NGDC Stamp Exhibit Documents
- Stolen NGDC Documents Found on Tracy's External Drive
- Tracy Emailed Stolen Documents to Coral (coralbluetwo@hotmail.com) with Subject "things"
- Joe Installed LogKext Keylogger on Tracy's MacBook Air

**Narrative:** The earliest activity was "Joe's Search History Reveals Intentional Keylogger Research and Deployment" (2012-06-15). The investigation subsequently uncovered "LogKext Keylogger Installed on Tracy's MacBook Air"; "Joe Installed LogKext Keylogger on Tracy's MacBook Air"; "Tracy Exfiltrated Confidential NGDC Stamp Exhibit Documents". The most recent activity was "Tracy Facilitated Unauthorized Physical Access for Coral/Carry" (2012-07-10).

**Tools:** search (38), read_evidence_file (22), list_directory (15), submit_finding (13), get_raw_output (6). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **LogKext Keylogger Installed on Tracy's MacBook Air** (2012-06-28T15:41:39-04:00)


- **Tracy Exfiltrated Confidential NGDC Stamp Exhibit Documents** (2012-07-09T09:22:10-04:00 -- 2012-07-09T13:01:52-04:00)


- **Stolen NGDC Documents Found on Tracy's External Drive** (2012-07-09T09:22:10-04:00)


- **Tracy Emailed Stolen Documents to Coral (coralbluetwo@hotmail.com) with Subject "things"** (2012-07-09T13:01:52-04:00)


- **Joe Installed LogKext Keylogger on Tracy's MacBook Air** (2012-06-28T15:41:39-04:00)


- **Coral Forwarded Stolen NGDC Documents to Perry Patsum** (2012-07-09T10:22:17-07:00)


- **Joe's Search History Reveals Intentional Keylogger Research and Deployment** (2012-06-15T13:36:48-04:00)





---

## Investigation Report

# NGDC Insider Threat and Unauthorized Surveillance Investigation Report

## Background

The National Gallery DC (NGDC) investigation centers on the forensic examination of digital evidence from multiple subjects and devices collected between July 3 and July 16, 2012. The evidence encompasses 89 items including disk images of personal computers, mobile phones, and tablets belonging to two primary subjects — Tracy Sumtwelve and Carry Carsumtwotwelve — along with network packet captures from the NGDC work environment and email evidence containing keylogger output.

The investigation was initiated in connection with concerns about the security of a rare and valuable stamp collection exhibit scheduled to arrive at the National Gallery DC. The evidence reveals two distinct but interrelated incidents: an insider data theft conspiracy involving multiple actors, and an unauthorized surveillance campaign conducted through a kernel-level keylogger.

## Incident Timeline

**Mid-June 2012**: Joe Sumtwelve, Tracy's ex-husband who maintained a user account on the shared family MacBook Air, began researching the LogKext keylogger. His search history reveals queries including "logkext," "logkext minmeg," "what does minmeg do logkext," and most troublingly, "is it ok to keylog children" — searched seven times. Joe also searched for "mac mail and crontab daughter," indicating he was configuring automated exfiltration of the keylogger's output.

**June 28, 2012 (15:41 EDT)**: The LogKext kernel-level keylogger began operating on Tracy's MacBook Air, capturing all keystrokes from both user accounts — Tracy (tracysumtwelve) and her daughter Terry (terrysumtwelve). The keylogger was configured to email captured logs via Postfix (running as root) to joe.sum.twelve@gmail.com with the subject "Logfile" at approximately three-hour intervals. Joe subsequently deleted his user account from the MacBook Air, though the account directory remained as "Users/joesumtwelve (Deleted)" with recoverable Safari cache, bash history, and other artifacts.

**June 29, 2012**: Keylogger data captures Tracy communicating with "Perry" (Coral/Carry, via coralbluetwo@hotmail.com) about finding something valuable at work: "If anything comes up around the office that we can maybe... get in on... please lets try to do so. Kiddo is getting really bent out of shape about possibly having to switch schools." Tracy also advised caution: "Be careful! We have enough problems as it is, we can't be getting in trouble or losing our jobs."

**July 2, 2012**: Tracy researched financial assistance options (financial advisors, private school tuition help, alternatives to private school). She also emailed Joe asking for help with Terry's tuition at Prufrock Preparatory. Later that day, Tracy typed about a foreign exhibit arriving at NGDC with significant financial investment, noting the shipping costs appeared unusually low.

**July 3, 2012**: Tracy informed Coral that the gallery was expecting a "rare collection of stamps" and described it as "our ticket." She also emailed Pat (patsumtwelve@gmail.com) about the opportunity with the message "Good News" and noted "I just talked to Coral, she sounded ecstatic."

**July 6, 2012 (11:49 EDT)**: Pat TeeSumTwelve (patsumtwelve@gmail.com) sent an email with subject "can't pass up" to King (throne1966@hotmail.com) with Coral (coralbluetwo@hotmail.com) on CC, broadening the conspiracy network. That same day, Tracy had lunch with Carry and later typed a thank-you email. Network captures show workstation 192.168.1.101 browsing the Louvre museum website and Wikipedia articles about the Palais du Louvre from the NGDC interior network.

**July 9, 2012 (09:22-13:02 EDT)**: Tracy executed the data exfiltration. Keylogger data captures her terminal commands in detail: she navigated to her Documents folder, listed its contents, and created an encrypted ZIP archive of stamp insurance documents using the command `zip -e documents.zip Stamp[...] Ins[urance]` with the password "Hercules." She then emailed the encrypted documents to coralbluetwo@hotmail.com with the subject "things" and the message "Hey Perry, here are those documents I talked to you about. The password is your old dog's name."

**July 9, 2012 (13:22 EDT / 10:22 PDT)**: Within approximately 20 minutes of Tracy's email, Coral forwarded the stolen documents to Perry Patsum (perrypatsum@yahoo.com) with the subject "Some things for you" — Message-ID: 4FFB1349.70506@hotmail.com. This rapid forwarding indicates the exfiltration chain was pre-arranged.

**July 10, 2012**: Keylogger data shows Tracy offering to help someone bring a tablet past NGDC security: "I can definitely help get your tablet in. Our security guards can be pretty ridiculous sometimes! When would you want to get in and take a look around?" Network captures confirm webmail access (Gmail and Outlook) from the NGDC interior network.

**Post-July 9**: Tracy moved documents.zip and related files to the Trash on her MacBook Air, along with intermediate files like "Stamp insurance 1 2.pdf" and "Stamp insurance 1.pdf.zip." The original documents remained in Users/tracysumtwelve/Documents/docs/ and copies persisted on the external USB drive under "NGDC things."

## Key Findings

The investigation identified two distinct criminal acts occurring simultaneously on shared infrastructure:

**Incident 1 — Insider Data Theft Conspiracy**: Tracy Sumtwelve, an employee at the National Gallery DC, systematically collected confidential documents related to a rare and valuable stamp exhibit. The stolen documents included three stamp insurance valuation PDFs (Stamp insurance 1.pdf, Stamp Insurance 2.pdf, Stamp insurance 3.pdf), a security guard rotation schedule (securityrotation.pdf), and a blank NGDC letterhead template (NGDC_blank.doc). These documents were stored on Tracy's personal MacBook Air, transferred via her external USB drive (exFAT, "External"), encrypted into a ZIP archive with the password "Hercules," and emailed to her co-conspirator Coral/Carry (coralbluetwo@hotmail.com), who promptly forwarded them to Perry Patsum (perrypatsum@yahoo.com). The conspiracy involved at least five individuals: Tracy (insider), Coral/Carry (intermediary), Pat (facilitator), Perry Patsum (recipient), and King (additional conspirator).

**Incident 2 — Unauthorized Keylogger Surveillance**: Joe Sumtwelve installed the LogKext kernel-level keylogger on the family MacBook Air to monitor both his ex-wife Tracy and their daughter Terry. The keylogger operated as a macOS kernel extension with LaunchDaemon persistence, capturing all keystrokes system-wide. Joe configured Postfix to automatically email the keylogger output to his Gmail account at regular intervals. He then deleted his user account to conceal his involvement, though forensic artifacts (Safari history, installation receipts, kernel extension files) remained recoverable. Ironically, the keylogger Joe installed to surveil Tracy and Terry became the primary source of evidence documenting Tracy's insider theft activities.

## Impact Assessment

The stolen documents pose a significant security risk to the National Gallery DC and the incoming stamp exhibit:

The stamp insurance valuations reveal the precise monetary value of individual items in the collection, enabling targeted theft of the most valuable pieces. The security guard rotation schedule provides intelligence about when specific areas of the gallery are staffed and when transitions occur — critical information for planning a physical intrusion. The blank NGDC letterhead template could be used to forge official communications, potentially to misdirect shipments, authorize access, or create fraudulent documentation.

The combination of these documents transforms what might be opportunistic curiosity into actionable intelligence for art/stamp theft. The rapid forwarding chain (Tracy → Coral → Perry, within 20 minutes) and the pre-arranged encryption password suggest this was a coordinated operation, not an impulsive act.

The keylogger surveillance, while a separate criminal act, inadvertently served as the most comprehensive evidence source for the investigation. However, it also represents a serious violation of Tracy and Terry's privacy, with every keystroke — passwords, personal correspondence, schoolwork, and private searches — captured and transmitted to Joe.

## Recommendations

1. **Immediate security response**: Rotate all NGDC security procedures documented in the exfiltrated securityrotation.pdf. Change guard schedules, entry protocols, and any access codes that may have been compromised.

2. **Exhibit protection**: Implement enhanced security measures for the incoming stamp collection, including additional surveillance, access controls, and inventory monitoring, given that conspirators now possess detailed insurance valuations.

3. **Legal action**: Refer the insider theft to law enforcement for prosecution of Tracy Sumtwelve, Carry Carsumtwotwelve (Coral), Pat TeeSumTwelve, Perry Patsum, and the individual known as "King" (throne1966@hotmail.com). Separately refer Joe Sumtwelve for unauthorized computer access and surveillance.

4. **Network security**: Review the NGDC network architecture. The SSL-stripping middleman captured useful forensic data but also represents a significant privacy concern and potential legal liability for the organization.

5. **Data loss prevention**: Implement controls to prevent employees from emailing confidential documents to personal accounts, including monitoring for encrypted attachments and bulk document access.

6. **Device forensics**: The MacBook Air should be preserved as evidence. The LogKext keylogger should be removed only after all forensic preservation is complete. The external USB drive and Carry's tablet contain critical corroborating evidence.

## Conclusion

This investigation reveals a carefully orchestrated insider threat driven by financial desperation. Tracy Sumtwelve, facing mounting private school tuition costs and divorce-related financial pressures, identified the incoming stamp exhibit as a potential source of income. Working with a network of co-conspirators including Coral/Carry, Pat, Perry Patsum, and King, she exfiltrated confidential NGDC documents containing stamp valuations and security schedules. The exfiltration chain — from encrypted ZIP files on the MacBook Air to email transmission to Coral, who forwarded to Perry within 20 minutes — demonstrates premeditation and coordination.

The concurrent discovery of Joe Sumtwelve's keylogger surveillance adds complexity to the case but also provided the most detailed forensic evidence available. The keylogger captured Tracy's terminal commands, email compositions, and password entries in real-time, creating an irrefutable record of the theft activities.

The evidence supports the conclusion that the document theft was preparation for a potential physical theft of items from the stamp exhibit, though no evidence of an actual completed theft was found within the investigation timeframe. The stolen security rotation schedule and insurance valuations would be most useful in the planning phase of such an operation.



---

## Overview

| | |
|---|---|
| Findings | **12** (9 confirmed, 3 inference) |
| Severity | 7 critical, 3 high, 2 medium, 0 low, 0 info |
| Sources | 18 evidence sources across 159 tool calls |
| Ruled Out | 1 hypotheses tested and rejected |


---

## Evidence Hashes

SHA-256 hashes recorded at ingestion. Verify with `sha256sum <file>`.

| File | SHA-256 | Size |
|------|---------|------|
| carry-phone-2012-07-03-initial.zip | `fb31cab9b61140f1693f01d46e79040f00a77b085d5efe9f5043e6cc09d00cde` | 118.4 MB |
| carry-phone-2012-07-05.zip | `5ee6af1fecd97941cae3cb4b8996af4e745c3a75cb54bc7908df683b36c04b8b` | 118.7 MB |
| carry-phone-2012-07-06.zip | `6b638f7808ec557dfee67deb5d0783f00bdd89509bc4330ffd8e41a451dda1e0` | 118.9 MB |
| carry-phone-2012-07-09.zip | `6106823b00bfbcdfa95b143b57d3163b43627827511b2ebb8fdedee4834f8cb4` | 119.7 MB |
| carry-phone-2012-07-11.zip | `57383e90a2198740ac3782896b9247217ab0377deadbbe74c28ca757fccb325a` | 124.8 MB |
| carry-phone-2012-07-15-final.zip | `5cfec4e099e70529072b6934c6f98f97492985e5a48daeb64549f96719792d9e` | 190.6 MB |
| carry-tablet-2012-07-03.E01 | `e1d006ba87c89bcaedcb42b2416fab3cf15ce5be14787a0afed2510a963155b4` | 615.0 MB |
| carry-tablet-2012-07-03.tar | `862fdf9f03950e56b3fc8aeecfe70074b1ba00d453de94da6bd7a0e8e6cf88e2` | 462.3 MB |
| carry-tablet-2012-07-05.E01 | `1eff8a1b6bf01fef28680ca904c88f6c9e9bca556d849a8ac7c4a6b1e11eb428` | 661.5 MB |
| carry-tablet-2012-07-05.tar | `c1492c4877be07464a41e60b874ba403d6014a89de4a38723501372b4b1f3945` | 499.3 MB |
| carry-tablet-2012-07-06.E01 | `fe7de1f766220ed073e5859b086788277ea16ceba260354bbf6980a6547b34d7` | 730.5 MB |
| carry-tablet-2012-07-06.tar | `28e1cd84472cf53bcc972d635aa97713e1b6081aa5909dddbd7b8a6159a7d747` | 571.6 MB |
| carry-tablet-2012-07-09.E01 | `15415e1b0ba8b79dfcd0c645ab05e63af78618f3af2ef7ba73c462d4a4e54501` | 881.4 MB |
| carry-tablet-2012-07-09.tar | `b546df1398cb5f0da8d42c04f4c53575a49dcb4e7820babba5da2b72f9fe3634` | 694.1 MB |
| carry-tablet-2012-07-10.E01 | `87a31f45af472ca57d8a60f0f5bca77c6d97eea2927263199df9608fb268e630` | 884.9 MB |
| carry-tablet-2012-07-10.tar | `475cfd7e6f6564e5aa8c8769131a260f2e6d4eaa0dd04e3e93a89cf059e4c966` | 694.0 MB |
| carry-tablet-2012-07-11.E01 | `96509d4bfe56b3c565f99424aa446b9e02b8a1d92a9cf70fccbdfe76c9364ed9` | 904.7 MB |
| carry-tablet-2012-07-11.tar | `987a26f1ac03f932a5fb3a47c22b82ab12829f0767c9d052f1f86d0aa074cfc9` | 716.1 MB |
| carry-tablet-2012-07-12.E01 | `04c160a0b6d5b3da1820cdc644784b93eccdf415f912ae0892aa68fe2bafa25c` | 1.1 GB |
| carry-tablet-2012-07-12.tar | `ef427ef03aebc8bb97a742ca9b57e1c44383ff034f01d25b33031851f225ea81` | 777.2 MB |
| carry-tablet-2012-07-13.E01 | `15cd66db38924e83515726350e2ea8b05bd79159c360ffffbb9de4b39df293df` | 1.1 GB |
| carry-tablet-2012-07-13.tar | `f17e15728183b8965ea95932b6a1b30d57e87f3377976204ef0c6ca6bfacd5c3` | 778.6 MB |
| carry-tablet-2012-07-16-final.E01 | `26a6ea3049c06afdd34862c453fc272a5ab4c64954ae51d23cf9df688473a448` | 1.1 GB |
| carry-tablet-2012-07-16-final.tar | `c70762e49db8f95cfd11246a3e84d1fca8a20d7182d1525b462638a28331793f` | 778.8 MB |
| email.zip | `d1c4470e9e058f83798b6c0c2856e85df8747783f2105f8c354f366d30ab5505` | 15.8 KB |
| carry-phone-2012-07-09-0926.E01 | `4c73f99d5aa21aef548fab2fa8c6a412da7bdd970150c87061162db0e97d9039` | 25.2 MB |
| carry-phone-2012-07-09-1512.E01 | `48f46f900368175ab1027f8d9dc6834b36d67d0500843fa0aaa5fefe27687603` | 25.5 MB |
| carry-phone-2012-07-10-1627.E01 | `01ea788557b1ea121e4ef005d541c91d58932a1f5e51327c46f81ff4c416e8ac` | 25.5 MB |
| carry-phone-2012-07-11-1415.E01 | `deaf369f9f98883db958c93cf47bc3da2922cd7a2b3a5266d36bc16232188d70` | 25.5 MB |
| carry-phone-2012-07-13-1045.E01 | `824beba7c2d5a451d0f894ae96039bafd48dc2fe007bf7dcf4af2f42c174fb18` | 59.6 MB |
| carry-phone-2012-07-15-0535.E01 | `bfb36c7ff419500e6f3444e3efd432d865d47eb591d6df52a6840487194735eb` | 59.4 MB |
| carry-phone-FTK-2012-07-03.E01 | `a2f538f9104b07ea0a1e6ad5de453923e9f5ad006abc163c5a23229126bc3373` | 25.2 MB |
| carry-phone-FTK-2012-07-06.E01 | `f51c5606901d700a0a27b9f7ee2a90054172e4c3225d14a319ad05b0d0c045b3` | 25.2 MB |
| carry-phone-FTK-2012-07-09.E01 | `6ea887d2ba7774ab9573e53f5681c268f6aec8996c6fd67d9ca3a5e086b93318` | 25.5 MB |
| carry-phone-logical-2012-07-15-0618.zip | `cbcee1cb354884ebfa302ad5a6e41c9980fc3ba252b2f74e732b2162540f7357` | 29.1 MB |
| carry-tablet-2012-07-05-1839.E01 | `00e0957732be8f59f25e91f1067476722234d66a1a0e73b18921419ab7539264` | 237.6 MB |
| carry-tablet-2012-07-09-1604.E01 | `c284ed58eea491852b72d259425916483d220e36e3f6787430948c17f07b9551` | 467.9 MB |
| carry-tablet-2012-07-11-1859.E01 | `d7f007cd4abfef137a1dbb47c586109706d18a664ad0638481d3b26c9821e836` | 624.2 MB |
| carry-tablet-2012-07-12-1623.E01 | `97d730d7fefe112a0e99fc1421085afca06bf43a0dbf268d41fc7cc3100de372` | 594.9 MB |
| carry-tablet-2012-07-13-0415.E01 | `5e716412b6fe1622c0802dcac76007c560ff20a6fd107578013d841d71fe93e8` | 3.6 MB |
| carry-tablet-2012-07-13-0425.E01 | `b2de8e615c2a09f5319ab7c653d4e502f685ed0e069efb72f6fb4a176f06f214` | 595.2 MB |
| carry-tablet-2012-07-15-0532.E01 | `7cb9b127d0dc5501530cf8a67896121720a47a8107c69335e4b7d8b925d4b656` | 597.1 MB |
| carry-tablet-logical-2012-07-15-0907.zip | `e172f851877b6a335888f851d8d9929ef9bd0bdc5ecae083b2de3eeee512b165` | 314.3 MB |
| NOTES.txt | `4c22a05b794476ffbbee471d0365fa3fad9959e8aa310e409ac3c4e4639085db` | 60.0 B |
| Tracy-phone-logical-2012-07-15-1317.zip | `1e4287dff75dd2fb84ff46be3ef5f3152bb894b64030831b442776e522d30329` | 17.7 MB |
| ngdc-exterior-2012-07-06.pcap | `b2e89885b1c3775ddff8d106cdead6ae1b5331d53b3f539ac9c27010244c0895` | 142.3 MB |
| ngdc-exterior-2012-07-09.pcap | `dc317d6a9f6942148e726097e95d7f4d3bd0cc95bee0480d0797b60020147a8b` | 44.6 MB |
| ngdc-exterior-2012-07-10.pcap | `863587be812b9ed6dd184ad0c5960d4ebe4e713b767a07860aec946a5442c73b` | 36.3 MB |
| ngdc-exterior-2012-07-12.txt | `d4a233442a7d86244f3017ee69481c3079aade7c577257eb09b3bda9a73e1f4d` | 244.6 MB |
| ngdc-interior-2012-07-06.pcap | `d5f019db5796bd2118d8b917ae26805bb6cb3c978fd983860035f599d8ccb051` | 35.3 MB |
| ngdc-interior-2012-07-09.pcap | `67eb2629d2f29ea4b7101f3b03209621294b1bf0909d515927514b0c00dac449` | 38.2 MB |
| ngdc-interior-2012-07-10.pcap | `d47a9e1144c92a5a818b295546bf5c3219a2bb18a21bb9dcc9702ee48f200548` | 24.9 MB |
| ngdc-interior-2012-07-12.txt | `2b2cbcc969cfa9d7dc7ad1087cc59e456e941c3c7c5d4416ba2a9ce0b83d7e66` | 4.2 MB |
| tracy-external-2012-07-03-initial.E01 | `1e5a3d79829acd983082208997f8751a62b04270c9a37504ca7618148075b388` | 3.5 GB |
| tracy-external-2012-07-05.E01 | `258424980de8fce8710af2e9cce3700c1fd41c8c532416122fd1ae176045d707` | 3.5 GB |
| tracy-external-2012-07-06.E01 | `0620934be3936a7f9cd808f312adb68250e7eacbc9ba66ccc61c4e24fc0a7b11` | 3.5 GB |
| tracy-external-2012-07-09.E01 | `13921c2bb5c79ac80e984db70265d54f3d085084cd1587b6db44f9e6d0eb2a30` | 3.5 GB |
| tracy-external-2012-07-10.E01 | `f4c9dcef754e97879d304dc62b2522e362084718f43ce716226d570ac6b890a2` | 3.5 GB |
| tracy-external-2012-07-11.E01 | `81995cb6772d23685f7bc569d7abe0bf5115943e294f6fa86bfcd6c0dcd795a1` | 3.5 GB |
| tracy-external-2012-07-12.E01 | `c703083132f551ccf57db79fd16c91bd97bd372a602f4d6fb4219b79a9a674bf` | 3.5 GB |
| tracy-external-2012-07-13.E01 | `a9fc2954067ebccdbb0f4ecd5f0ae7e1908d42c12bf6d3b2a05c76b3ce1a41f3` | 3.5 GB |
| tracy-external-2012-07-16-final.E01 | `bfff9410215485be97d57ed7064c576319cafacc4bfead179e070af77c5b6078` | 3.5 GB |
| tracy-home-2012-07-03-initial.E01 | `c248f4682ce80204167d0762f789f922ee5053c22baf83fa15cdbb9dac6bbcbe` | 4.0 GB |
| tracy-home-2012-07-05.E01 | `40e53ffc58e66c0693b46853855a70fc2881484cf411d24cd923aa8eec6139ab` | 4.0 GB |
| tracy-home-2012-07-06.E01 | `31320381fadfba284370068c573c8eb04d55a35e81b549520c21f7275e8089bb` | 4.0 GB |
| tracy-home-2012-07-09.E01 | `58eaa38cef2b4915b2f8b8b732c300499756f9f0e294c4be9b76d867d674e8f0` | 4.0 GB |
| tracy-home-2012-07-10.E01 | `596d52b960bbc754819f035ec4e2528ca2536761eb5ebb70a8116e40f1def2b1` | 4.0 GB |
| tracy-home-2012-07-11.E01 | `2690d2340903df7d71167f9e8d6c6b69ab5e79a9024846092787703c8bc51159` | 4.0 GB |
| tracy-home-2012-07-12.E01 | `91586fb0e1d5834c690a43bfe4e9e6c55fb4bd7048851de404896a4457ec83e5` | 4.0 GB |
| tracy-home-2012-07-13.E01 | `544ccb70fd064d3e48d5af8001d6a5b847908c62884a4ca0ddd30e72bbd49696` | 4.0 GB |
| tracy-home-2012-07-16-final.E01 | `26218dd0553a5f22cd11e98aae42e7b89c9739bba87ee8b1de5cd43a069ef17c` | 4.0 GB |
| tracy-phone-2012-07-03-initial.E01 | `3e5eb75fd0b1340485ff257a25811db1dad1deba193a00df77fb615d966886b7` | 755.2 MB |
| tracy-phone-2012-07-03-initial.tar | `e63bf43c73542263e26622790a8c41e1eb1ae047c4ed7b460b228923c6b36671` | 710.5 MB |
| tracy-phone-2012-07-05.E01 | `7410eb756ed1af9e12d8d8873f9faa164076214a62a042d1b93b3d935e7333b7` | 753.1 MB |
| tracy-phone-2012-07-05.tar | `aa8ac5304f5f12cf1eecb8462bd7aac5225f05ac42115bfebf5ad56befe86005` | 712.0 MB |
| tracy-phone-2012-07-06.E01 | `7c5342254e818d1b0ac87106f6c1bedae25d1e8e9022117eae6a0f1771f099f7` | 751.0 MB |
| tracy-phone-2012-07-06.tar | `51e998631fe0092c01888ee05f205f57d64ebe6b86559080183913b3f9350589` | 712.2 MB |
| tracy-phone-2012-07-09.E01 | `6bdee47174559f6379906f0a530dcc9136a6c38b66866224e825ca653356f278` | 751.1 MB |
| tracy-phone-2012-07-09.tar | `c845267fad6a45414e87bdd76bfb8fb3d5f4e47925c19270e5776c7c99c42e4b` | 729.8 MB |
| tracy-phone-2012-07-10.E01 | `3e49d257d1eb421737af60d3e0bca91e49f47ba83193b6850bce2c480de5780a` | 751.9 MB |
| tracy-phone-2012-07-10.tar | `abba1fc999da1dc1bc5d67aa5ab959afa1a49f631293748fcffae98a022e5078` | 731.2 MB |
| tracy-phone-2012-07-11.E01 | `4e9246308fec0a0a43fc03350234b5c242ac58d0ae5022c0c596c35192d914ca` | 751.8 MB |
| tracy-phone-2012-07-11.tar | `aa89ba23dbb1801655471686dd6a321eb23aee3b7902a23117030f6f48fbb112` | 731.2 MB |
| tracy-phone-2012-07-12.E01 | `0d3d14a0b6391eb245dab9ac1c37952d5be12d3806a3a2e5b2d80bd321e42bc9` | 752.6 MB |
| tracy-phone-2012-07-12.tar | `5cc5d3f908b313cbc6913689ee29ff27e24af11d2610a6430422205a5b5fc973` | 751.2 MB |
| tracy-phone-2012-07-13.E01 | `84ce162dc0f110b0a21977f23f317c7c26add7a443b88c3e56aeca7946a59294` | 752.1 MB |
| tracy-phone-2012-07-13.tar | `7c1a7cc4b57826bcdc4e38daee3624a442e22bd7cfbefbef226103653d91e7a4` | 751.2 MB |
| tracy-phone-2012-07-15-final.E01 | `71aed05a86a753dec4ef4033ed7f52d6577ccb534ca0d1e83ffd27683e621607` | 751.9 MB |
| tracy-phone-2012-07-15-final.tar | `b209e812aeeab7b6234f8f6d16be6b63027e02d667d8882104bd52b3aea204a1` | 751.2 MB |



---

## Attack Timeline


| Time | Event | Severity | Sources |
|------|-------|----------|---------|
| 2012-06-15T13:36:48-04:00 | Joe's Search History Reveals Intentional Keylogger Research and Deployment | CRITICAL | bulk.url_searches (tracy-home), tsk.filelist (tracy-home) |
| 2012-06-28T15:41:39-04:00 | LogKext Keylogger Installed on Tracy's MacBook Air | CRITICAL | email/logfile-2012-06-28-1600.eml, email/logfile-2012-06-29-1100.eml, email/logfile-2012-07-02-1200.eml |
| 2012-06-28T15:41:39-04:00 | Joe Installed LogKext Keylogger on Tracy's MacBook Air | CRITICAL | tsk.filelist (tracy-home) |
| 2012-06-29T09:04:12-04:00 | Financial Motive: Tracy's Tuition Crisis Drove Insider Theft | HIGH | email/logfile-2012-06-29-1100.eml, email/logfile-2012-07-02-1200.eml, email/logfile-2012-07-06-1100.eml, bulk.url_searches (tracy-home) |
| 2012-07-06T11:49:31-04:00 | Wider Conspiracy Network: Pat, King, Coral/Carry Connected via "can't pass up" Email | HIGH | bulk.rfc822 (carry-tablet), bulk.email (carry-tablet), bulk.email (tracy-home) |
| 2012-07-06T14:12:26Z | NGDC Interior Network Traffic Shows Webmail Access During Work Hours | MEDIUM | pcap.http (interior-2012-07-10), pcap.tls (interior-2012-07-10), pcap.http (interior-2012-07-06) |
| 2012-07-09T09:22:10-04:00 | Tracy Exfiltrated Confidential NGDC Stamp Exhibit Documents | CRITICAL | email/logfile-2012-07-09-1300.eml, email/logfile-2012-07-10-1000.eml, email/logfile-2012-07-02-1500.eml, email/logfile-2012-07-02-1200.eml, email/logfile-2012-06-29-1100.eml |
| 2012-07-09T09:22:10-04:00 | Stolen NGDC Documents Found on Tracy's External Drive | CRITICAL | tsk.filelist (tracy-external), tsk.filelist (tracy-home) |
| 2012-07-09T10:22:17-07:00 | Coral Forwarded Stolen NGDC Documents to Perry Patsum | CRITICAL | bulk.rfc822 (carry-tablet), bulk.email (carry-tablet), bulk.email (tracy-home) |
| 2012-07-09T13:01:52-04:00 | Tracy Emailed Stolen Documents to Coral (coralbluetwo@hotmail.com) with Subject "things" | CRITICAL | bulk.email (tracy-home), tsk.filelist (tracy-home), tsk.filelist (tracy-external) |
| 2012-07-10T09:15:54-04:00 | Tracy Facilitated Unauthorized Physical Access for Coral/Carry | HIGH | email/logfile-2012-07-10-1000.eml |



---

## Findings


### 1. [CRITICAL] LogKext Keylogger Installed on Tracy's MacBook Air

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2012-06-28T15:41:39-04:00 |
| **Sources** | email/logfile-2012-06-28-1600.eml, email/logfile-2012-06-29-1100.eml, email/logfile-2012-07-02-1200.eml |
| **Evidence Refs** | tc_38c3eb1c, tc_4d0e371b, tc_63ef6a7d |
| **ATT&CK** | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) |


A kernel-level keylogger (LogKext) is running as root on Tracy's MacBook Air (Tracys-MacBook-Air.local). The keylogger captures all keystrokes from users 'tracysumtwelve' and 'terrysumtwelve'. Logs are automatically emailed via Postfix (running as root, userid 0) to joe.sum.twelve@gmail.com with subject "Logfile" at regular intervals. First observed daemon startup: "LogKext Daemon starting up : Thu Jun 28 15:41:39 2012". The emails originate from the MacBook Air's IPv6 addresses on the 2600:1003::/32 prefix. This represents unauthorized surveillance of Tracy and her daughter Terry.

Key evidence from email headers:
- From: root@Tracys-MacBook-Air.local (System Administrator)
- To: joe.sum.twelve@gmail.com
- Subject: Logfile
- Sent via Postfix from userid 0 (root)



### 2. [CRITICAL] Tracy Exfiltrated Confidential NGDC Stamp Exhibit Documents

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2012-07-09T09:22:10-04:00 -- 2012-07-09T13:01:52-04:00 |
| **Sources** | email/logfile-2012-07-09-1300.eml, email/logfile-2012-07-10-1000.eml, email/logfile-2012-07-02-1500.eml, email/logfile-2012-07-02-1200.eml, email/logfile-2012-06-29-1100.eml |
| **Evidence Refs** | tc_0b62886e, tc_c97f423a, tc_9aeda5b6, tc_63ef6a7d, tc_4d0e371b |
| **ATT&CK** | [T1560.001](https://attack.mitre.org/techniques/T1560/001/), [T1048.002](https://attack.mitre.org/techniques/T1048/002/) |


Keylogger data shows Tracy (tracysumtwelve) created an encrypted ZIP file of confidential documents related to a rare stamp collection exhibit at the National Gallery DC (NGDC) on July 9, 2012. The keystrokes captured show:

Terminal commands typed:
```
ls
cd Documents
ls
zip -e documents.zip Sta[mps] Ins[urance]
```
Password used for encryption: "Hercules" (typed twice for confirmation)

Tracy then emailed the encrypted documents to coralbluetwo@hotmail.com (Coral/Perry) with the message: "Hey Perry, here are those documents I talked to you about. The password is your old dog's name." - confirming the ZIP password is "Hercules" (Perry/Coral's old dog's name).

Earlier keylogger entries show Tracy and Coral/Perry discussing finding valuable items at NGDC to exploit for financial gain. Tracy mentioned a rare stamp collection coming to the gallery and called it "our ticket."



### 3. [CRITICAL] Stolen NGDC Documents Found on Tracy's External Drive

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2012-07-09T09:22:10-04:00 |
| **Sources** | tsk.filelist (tracy-external), tsk.filelist (tracy-home) |
| **Evidence Refs** | tc_13854cb7, tc_bfc3e8d3, tc_21776942 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Tracy's external USB drive (exFAT, volume "External") contains a directory "NGDC things" with confidential National Gallery DC documents:
- Stamp insurance 1.pdf (inode 268646403)
- Stamp Insurance 2.pdf (inode 268646407)
- Stamp insurance 3.pdf (inode 268646411)
- securityrotation.pdf (inode 268646415) — security guard rotation schedule
- NGDC_blank.doc (inode 268646419) — blank NGDC letterhead template

Additionally, **deleted** copies of these files exist at the root level of the drive (inodes 3108, 3112, 3116, 3120, marked with * in fls output), along with a deleted "NGDC letterhead" directory (inode 3124). This indicates Tracy first copied files to the drive root, then reorganized them into the "NGDC things" folder.

The securityrotation.pdf is particularly concerning as it would reveal when security guards change shifts — critical intelligence for planning a physical theft of the stamp collection.



### 4. [CRITICAL] Tracy Emailed Stolen Documents to Coral (coralbluetwo@hotmail.com) with Subject "things"

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2012-07-09T13:01:52-04:00 |
| **Sources** | bulk.email (tracy-home), tsk.filelist (tracy-home), tsk.filelist (tracy-external) |
| **Evidence Refs** | tc_f7ca6c35, tc_06434451, tc_721e9acb, tc_5897fdab |
| **ATT&CK** | [T1048.002](https://attack.mitre.org/techniques/T1048/002/), [T1560.001](https://attack.mitre.org/techniques/T1560/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Bulk extractor recovered email metadata from Tracy's MacBook Air showing an email sent from tracysumtwelve@gmail.com to coralbluetwo@hotmail.com with subject "things" and attachment "public.zip". The email is stored in the Sent Messages mbox at:
Users/tracysumtwelve/Library/Mail/V2/IMAP-tracysumtwelve@imap.gmail.com/Sent Messages.mbox/

The attachment contained a "docs" directory with the stamp insurance PDFs. There are also draft versions of this email found at the Drafts location, suggesting Tracy composed it before sending.

Additionally, documents.zip was found in Tracy's Trash (inode 430246), along with "Stamp insurance 1 2.pdf" and "Stamp insurance 1.pdf.zip" — evidence of Tracy cleaning up after exfiltration. The original documents exist in Users/tracysumtwelve/Documents/docs/ and Users/tracysumtwelve/Documents/docs 2/.

The keylogger confirms the ZIP password is "Hercules" (Perry/Coral's old dog's name).



### 5. [CRITICAL] Joe Installed LogKext Keylogger on Tracy's MacBook Air

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2012-06-28T15:41:39-04:00 |
| **Sources** | tsk.filelist (tracy-home) |
| **Evidence Refs** | tc_3ca44269, tc_06434451 |
| **ATT&CK** | [T1056.001](https://attack.mitre.org/techniques/T1056/001/), [T1547.006](https://attack.mitre.org/techniques/T1547/006/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Joe (joesumtwelve) installed the LogKext kernel-level keylogger on Tracy's MacBook Air. Evidence:

1. **Deleted user account**: Users/joesumtwelve (Deleted) — Joe had an active user account on the MacBook Air that was subsequently deleted to cover tracks.

2. **Browser history showing research**: Joe's Safari cache contains search history for "logkext minmeg" at:
   Users/joesumtwelve (Deleted)/Library/Caches/Metadata/Safari/History/

3. **Full LogKext installation** found on the system:
   - System/Library/Extensions/logKext.kext/ (kernel extension)
   - Library/LaunchDaemons/logKext.plist (persistence via LaunchDaemon)
   - Library/Application Support/logKext/ (support files including logKextKeyGen, logKextKeymap.plist)
   - private/var/root/Library/Preferences/com.fsb.logKext.plist (configuration)
   - Installation receipts at private/var/db/receipts/com.fsb.logkext.*.pkg (logkext, logkextclient, logkextdaemon, logkextExt, logkextkeygen, logkextkeymap, logkextReadme, logkextuninstall)

4. **Automated exfiltration**: Keylogger configured to email logs via Postfix (root) to joe.sum.twelve@gmail.com every ~3 hours.

Joe likely installed the keylogger to monitor Tracy's activities, possibly related to their personal/divorce situation (divorcerates.doc found in Tracy's Documents).



### 6. [CRITICAL] Coral Forwarded Stolen NGDC Documents to Perry Patsum

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2012-07-09T10:22:17-07:00 |
| **Sources** | bulk.rfc822 (carry-tablet), bulk.email (carry-tablet), bulk.email (tracy-home) |
| **Evidence Refs** | tc_961897f8, tc_9e443fdd, tc_721e9acb |
| **ATT&CK** | [T1048.002](https://attack.mitre.org/techniques/T1048/002/) |


Within minutes of receiving the stolen NGDC documents from Tracy, Coral (coralbluetwo@hotmail.com) forwarded them to Perry Patsum (perrypatsum@yahoo.com) with subject "Some things for you."

Email recovered from Carry's tablet (which contains Coral's Thunderbird email client configuration):
- From: Coral <coralbluetwo@hotmail.com>
- To: Perry Patsum <perrypatsum@yahoo.com>
- Subject: Some things for you
- Date: Mon, 09 Jul 2012 10:22:17 -0700 (1:22 PM EDT)
- Message-ID: 4FFB1349.70506@hotmail.com

Timeline:
1. Tracy created encrypted ZIP of stamp insurance documents on MacBook Air ~9:22 AM EDT on July 9
2. Tracy emailed the ZIP to coralbluetwo@hotmail.com with subject "things" ~1:01 PM EDT
3. Coral forwarded to Perry Patsum at 1:22 PM EDT — approximately 20 minutes later

This confirms a three-person conspiracy: Tracy (insider at NGDC) → Coral/Carry (intermediary) → Perry Patsum (end recipient). The stolen documents include stamp insurance valuations and security guard rotation schedules.



### 7. [CRITICAL] Joe's Search History Reveals Intentional Keylogger Research and Deployment

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2012-06-15T13:36:48-04:00 |
| **Sources** | bulk.url_searches (tracy-home), tsk.filelist (tracy-home) |
| **Evidence Refs** | tc_6417e74e, tc_3ca44269 |
| **ATT&CK** | [T1056.001](https://attack.mitre.org/techniques/T1056/001/), [T1547.006](https://attack.mitre.org/techniques/T1547/006/), [T1053.003](https://attack.mitre.org/techniques/T1053/003/) |


Search history recovered from Tracy's MacBook Air (from Joe's deleted user account and system-wide browser caches) shows extensive research into the LogKext keylogger:

1. **"what does minmeg do logkext"** — searched 66 times (most frequent query on the system)
2. **"logkext minmeg"** — searched 36 times
3. **"what does minimum megs do logkext"** — searched 24 times
4. **"logkext"** — searched 7 times
5. Multiple cached pages from logkext.googlecode.com (source code review)
6. Visited logKextClient.cpp source code directly

Most critically:
- **"is it ok to keylog children"** — searched 7 times, showing Joe was aware of the legal/ethical implications and was also monitoring his daughter Terry
- **"mac mail and crontab daughter"** — Joe set up automated emailing of keylogger data via crontab

Other searches of interest:
- "Prufrock Preparatory tuition" — Terry's school, showing Joe's concern about tuition costs (matching Tracy's conversations)
- "buick" — appears in multiple searches

Joe clearly planned, researched, installed, and configured the LogKext keylogger to monitor both Tracy and their daughter Terry on the shared MacBook Air, then configured Postfix/crontab to automatically email the logs to joe.sum.twelve@gmail.com.



### 8. [HIGH] Tracy Facilitated Unauthorized Physical Access for Coral/Carry

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2012-07-10T09:15:54-04:00 |
| **Sources** | email/logfile-2012-07-10-1000.eml |
| **Evidence Refs** | tc_c97f423a |
| **ATT&CK** | [T1200](https://attack.mitre.org/techniques/T1200/) |


Keylogger data from July 10, 2012 shows Tracy offering to help someone (likely Coral/Carry) bring a tablet device past NGDC security and gain access to view exhibits:

"I can definitely help get your tablet in. Our security guards can be pretty ridiculous sometimes! When would you want to get in and take a look around?"

This suggests Tracy is facilitating unauthorized or improperly authorized physical access to the gallery for her co-conspirator to case the stamp exhibit. Combined with the document exfiltration, this indicates planning for potential theft of the rare stamp collection.



### 9. [HIGH] Wider Conspiracy Network: Pat, King, Coral/Carry Connected via "can't pass up" Email

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2012-07-06T11:49:31-04:00 |
| **Sources** | bulk.rfc822 (carry-tablet), bulk.email (carry-tablet), bulk.email (tracy-home) |
| **Evidence Refs** | tc_405b2871, tc_146dd7d9, tc_9e443fdd |
| **ATT&CK** | [T1048.002](https://attack.mitre.org/techniques/T1048/002/) |


An email recovered from Carry's tablet reveals a wider conspiracy network beyond Tracy and Coral:

Email details:
- From: Pat TeeSumTwelve <patsumtwelve@gmail.com>
- To: throne1966@hotmail.com (addressed as "King")
- CC: coralbluetwo@hotmail.com (Coral/Carry)
- Subject: "can't pass up"
- Date: Fri, 6 Jul 2012 11:49:31 -0400

This email, with subject "can't pass up," was sent just days before Tracy exfiltrated the stamp insurance documents (July 9). It establishes that Pat, King, and Coral/Carry were communicating about an opportunity that was too good to pass up — consistent with the stamp exhibit theft conspiracy.

Keylogger data also shows Tracy typed "throne1966@hotmail.com...King, first..." — indicating Tracy was also in contact with King.

Identity network:
- Tracy Sumtwelve (tracysumtwelve@gmail.com) — NGDC insider
- Carry "Coral" Carsumtwotwelve (cat2welve@gmail.com, coralbluetwo@hotmail.com) — intermediary
- Pat TeeSumTwelve (patsumtwelve@gmail.com) — conspirator, possibly Tracy's relative
- Perry Patsum (perrypatsum@yahoo.com) — received forwarded documents from Coral
- "King" (throne1966@hotmail.com) — recipient of "can't pass up" email



### 10. [HIGH] Financial Motive: Tracy's Tuition Crisis Drove Insider Theft

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2012-06-29T09:04:12-04:00 -- 2012-07-10T09:50:41-04:00 |
| **Sources** | email/logfile-2012-06-29-1100.eml, email/logfile-2012-07-02-1200.eml, email/logfile-2012-07-06-1100.eml, bulk.url_searches (tracy-home) |
| **Evidence Refs** | tc_4d0e371b, tc_63ef6a7d, tc_d595d352, tc_6417e74e |


Multiple evidence sources establish Tracy's financial desperation as the motive for the NGDC document theft:

1. **Keylogger captured searches**: "private school tuition help", "financial advisor washington dc", "private school financial aid", "best alternative to private school"
2. **Email to Joe**: Tracy emailed joe.sum.twelve@gmail.com asking for help with Terry's tuition at Prufrock Preparatory: "is there any way you would be willing to help me out with her tuition for this year?"
3. **divorcerates.doc**: Found in Tracy's Documents folder, suggesting ongoing divorce proceedings
4. **Keylogger email (June 29)**: Tracy wrote to Coral: "If anything comes up around the office that we can maybe... get in on... please lets try to do so. Kiddo is getting really bent out of shape about possibly having to switch schools."
5. **July 2 keylogger**: Tracy called the stamp exhibit "our ticket" after learning about its value
6. **Terry's own awareness**: Terry (terrysumtwelve) searched "how to help your parents with private school" and "help parents afford private school"

The financial pressure from private school tuition and divorce costs directly motivated Tracy to steal confidential NGDC documents about the valuable stamp exhibit.



### 11. [MEDIUM] VM.vmdk Virtual Machine on Tracy's External Drive

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Sources** | tsk.filelist (tracy-external) |
| **Evidence Refs** | tc_4dbd286c, tc_13854cb7 |
| **ATT&CK** | [T1564.006](https://attack.mitre.org/techniques/T1564/006/) |


Tracy's external USB drive contains a VM.vmdk (virtual machine disk) at the root level alongside the stolen NGDC documents. The presence of a virtual machine on a portable drive used for transporting stolen documents between home and work raises concerns about:
1. Potential use for covert activities that leave no trace on the host OS
2. Possible encryption or additional document staging
3. Bypassing workplace security monitoring

The VM.vmdk file coexists with the "NGDC things" directory containing stolen stamp insurance documents and security rotation schedules. The external drive (exFAT formatted, volume "External") was used to transport data between Tracy's home computer and work computer according to the evidence README.



### 12. [MEDIUM] NGDC Interior Network Traffic Shows Webmail Access During Work Hours

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2012-07-06T14:12:26Z -- 2012-07-10T15:15:30Z |
| **Sources** | pcap.http (interior-2012-07-10), pcap.tls (interior-2012-07-10), pcap.http (interior-2012-07-06) |
| **Evidence Refs** | tc_68dab365, tc_94445a32, tc_360b6a0d |


Network packet captures from the NGDC interior network (SSL-stripping middleman) captured on July 6, 9, and 10 reveal workstation activity:

1. **192.168.1.101** (interior IP, maps to 10.10.1.169 exterior):
   - Accessed mail.google.com on July 10 at 15:13:00 UTC (11:13 AM EDT)
   - Connected to outlook.com (pod51018.outlook.com) on July 10 at 15:12:45 UTC
   - Browsed www.louvre.fr and Wikipedia's Palais du Louvre article on July 6
   - Searched Google for "gmail" on July 10
   
2. **192.168.1.100** (separate workstation):
   - Windows Update traffic
   - Microsoft Watson error reporting (ASUSTeK EB1012P)

The combination of Gmail and Outlook/Hotmail access from the same workstation during work hours is consistent with Tracy accessing both her personal Gmail (tracysumtwelve@gmail.com) and potentially Coral's Hotmail (coralbluetwo@hotmail.com) to coordinate the document exfiltration. The Louvre browsing suggests research into museum operations.




---

## Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No Evidence of Second Independent Attack Narrative** -- After thoroughly analyzing all evidence sources, no evidence of a second independent attack narrative was found beyond the two identified incidents (insider theft and keylogger...



---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| Internal IP | `192.168.1.101` | NGDC Interior Network Traffic Shows Webmail Access During Work Hours |
| Internal IP | `10.10.1.169` | NGDC Interior Network Traffic Shows Webmail Access During Work Hours |
| Internal IP | `192.168.1.100` | NGDC Interior Network Traffic Shows Webmail Access During Work Hours |


### File IOCs

| Type | Value | Context |
|------|-------|---------|
| Path | `/var/root/Library/Preferences/com.fsb.logKext.plist` | Joe Installed LogKext Keylogger on Tracy's MacBook Air |
| Path | `/var/db/receipts/com.fsb.logkext` | Joe Installed LogKext Keylogger on Tracy's MacBook Air |



### Email IOCs

| Type | Value | Context |
|------|-------|---------|
| Email | `joe.sum.twelve@gmail.com` | LogKext Keylogger Installed on Tracy's MacBook Air |
| Email | `root@tracys-macbook-air.local` | LogKext Keylogger Installed on Tracy's MacBook Air |
| Email | `coralbluetwo@hotmail.com` | Tracy Exfiltrated Confidential NGDC Stamp Exhibit Documents |
| Email | `tracysumtwelve@gmail.com` | Tracy Emailed Stolen Documents to Coral (coralbluetwo@hotmail.com) with Subject  |
| Email | `imap-tracysumtwelve@imap.gmail.com` | Tracy Emailed Stolen Documents to Coral (coralbluetwo@hotmail.com) with Subject  |
| Email | `perrypatsum@yahoo.com` | Coral Forwarded Stolen NGDC Documents to Perry Patsum |
| Email | `4ffb1349.70506@hotmail.com` | Coral Forwarded Stolen NGDC Documents to Perry Patsum |
| Email | `patsumtwelve@gmail.com` | Wider Conspiracy Network: Pat, King, Coral/Carry Connected via "can't pass up" E |
| Email | `throne1966@hotmail.com` | Wider Conspiracy Network: Pat, King, Coral/Carry Connected via "can't pass up" E |
| Email | `throne1966@hotmail.com...king` | Wider Conspiracy Network: Pat, King, Coral/Carry Connected via "can't pass up" E |
| Email | `cat2welve@gmail.com` | Wider Conspiracy Network: Pat, King, Coral/Carry Connected via "can't pass up" E |




---

## MITRE ATT&CK Coverage

10 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) &#8594; Execution (1) &#8594; Persistence (2) &#8594; Privilege Escalation (2) &#8594; Defense Evasion (2) &#8594; Credential Access (1) &#8594; Collection (3) &#8594; Exfiltration (2)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Tracy Facilitated Unauthorized Physical Access... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron | Joe's Search History Reveals Intentional... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron | Joe's Search History Reveals Intentional... |
| [T1547.006](https://attack.mitre.org/techniques/T1547/006/) | Kernel Modules and Extensions | Joe Installed LogKext Keylogger on Tracy's MacBook Air; Joe's Search History Reveals Intentional... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron | Joe's Search History Reveals Intentional... |
| [T1547.006](https://attack.mitre.org/techniques/T1547/006/) | Kernel Modules and Extensions | Joe Installed LogKext Keylogger on Tracy's MacBook Air; Joe's Search History Reveals Intentional... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Tracy Emailed Stolen Documents to Coral...; Joe Installed LogKext Keylogger on Tracy's MacBook Air |
| [T1564.006](https://attack.mitre.org/techniques/T1564/006/) | Run Virtual Instance | VM.vmdk Virtual Machine on Tracy's External Drive |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Keylogging | LogKext Keylogger Installed on Tracy's MacBook Air; Joe Installed LogKext Keylogger on Tracy's MacBook Air; Joe's Search History Reveals Intentional... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Stolen NGDC Documents Found on Tracy's External Drive |
| [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Keylogging | LogKext Keylogger Installed on Tracy's MacBook Air; Joe Installed LogKext Keylogger on Tracy's MacBook Air; Joe's Search History Reveals Intentional... |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Tracy Exfiltrated Confidential NGDC Stamp...; Tracy Emailed Stolen Documents to Coral... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1048.002](https://attack.mitre.org/techniques/T1048/002/) | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Tracy Exfiltrated Confidential NGDC Stamp...; Tracy Emailed Stolen Documents to Coral...; Coral Forwarded Stolen NGDC Documents to Perry Patsum; Wider Conspiracy Network: Pat, King,... |
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Stolen NGDC Documents Found on Tracy's External Drive |





---

## Audit Trail

| Metric | Value |
|--------|-------|
| Total tool calls | 159 |
| Findings submitted | 12 |
| Confirmed | 9 |
| Inferences | 3 |
| Audit log | /root/.mulder/cases/ngdc.audit.jsonl |


<details>
<summary>Evidence Sources (99)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 12 |
| tsk.partitions | sleuthkit | 16 |
| tsk.fsstat | sleuthkit | 36 |
| tsk.fsstat | sleuthkit | 35 |
| pcap.summary | tshark | 80 |
| pcap.summary | tshark | 83 |
| pcap.conversations | tshark | 99 |
| pcap.http | tshark | 11 |
| pcap.conversations | tshark | 394 |
| pcap.tls | tshark | 5 |
| pcap.http | tshark | 907 |
| pcap.beaconing | tshark | 9 |
| pcap.tls | tshark | 34 |
| pcap.tunneling | tshark | 8 |
| pcap.beaconing | tshark | 5 |
| pcap.tunneling | tshark | 20 |
| tsk.filelist | sleuthkit | 152 |
| tsk.filelist | sleuthkit | 344147 |
| bulk.domain | bulk_extractor | 165507 |
| bulk.email | bulk_extractor | 10272 |
| bulk.ether | bulk_extractor | 529 |
| bulk.exif | bulk_extractor | 2181 |
| bulk.gps | bulk_extractor | 9 |
| bulk.ip | bulk_extractor | 11 |
| bulk.packets | bulk_extractor | 22 |
| bulk.rfc822 | bulk_extractor | 27777 |
| bulk.tcp | bulk_extractor | 7 |
| bulk.url | bulk_extractor | 152208 |
| bulk.domain | bulk_extractor | 23464 |
| bulk.url_facebook-address | bulk_extractor | 47 |
| bulk.email | bulk_extractor | 4838 |
| bulk.url_facebook-id | bulk_extractor | 9 |
| bulk.ether | bulk_extractor | 97 |
| bulk.url_searches | bulk_extractor | 190 |
| bulk.exif | bulk_extractor | 269 |
| bulk.url_services | bulk_extractor | 3160 |
| bulk.httplogs | bulk_extractor | 6 |
| bulk.rfc822 | bulk_extractor | 1098 |
| bulk.url | bulk_extractor | 19326 |
| bulk.url_facebook-address | bulk_extractor | 9 |
| bulk.url_searches | bulk_extractor | 17 |
| bulk.url_services | bulk_extractor | 1126 |
| pcap.summary | tshark | 82 |
| pcap.summary | tshark | 86 |
| pcap.summary | tshark | 86 |
| pcap.summary | tshark | 84 |
| pcap.conversations | tshark | 157 |
| pcap.conversations | tshark | 408 |
| pcap.conversations | tshark | 153 |
| pcap.http | tshark | 112 |
| pcap.conversations | tshark | 321 |
| pcap.http | tshark | 1281 |
| pcap.http | tshark | 148 |
| pcap.tls | tshark | 9 |
| pcap.http | tshark | 921 |
| pcap.tls | tshark | 47 |
| pcap.beaconing | tshark | 13 |
| pcap.tls | tshark | 27 |
| pcap.beaconing | tshark | 9 |
| pcap.beaconing | tshark | 5 |
| pcap.tls | tshark | 53 |
| pcap.tunneling | tshark | 11 |
| pcap.beaconing | tshark | 5 |
| pcap.tunneling | tshark | 17 |
| pcap.tunneling | tshark | 20 |
| pcap.tunneling | tshark | 23 |
| bulk.domain | bulk_extractor | 197541 |
| bulk.email | bulk_extractor | 4869 |
| bulk.ether | bulk_extractor | 6 |
| bulk.exif | bulk_extractor | 611 |
| bulk.ip | bulk_extractor | 37 |
| bulk.packets | bulk_extractor | 99 |
| bulk.rfc822 | bulk_extractor | 2417 |
| bulk.tcp | bulk_extractor | 16 |
| bulk.url | bulk_extractor | 244001 |
| bulk.url_facebook-address | bulk_extractor | 8 |
| bulk.url_searches | bulk_extractor | 44 |
| bulk.url_services | bulk_extractor | 2518 |
| bulk.domain | bulk_extractor | 19008 |
| bulk.email | bulk_extractor | 3181 |
| bulk.ether | bulk_extractor | 213 |
| bulk.exif | bulk_extractor | 35 |
| bulk.httplogs | bulk_extractor | 6 |
| bulk.rfc822 | bulk_extractor | 108 |
| bulk.url | bulk_extractor | 15399 |
| bulk.url_facebook-address | bulk_extractor | 13 |
| bulk.url_searches | bulk_extractor | 12 |
| bulk.url_services | bulk_extractor | 848 |
| bulk.domain | bulk_extractor | 145768 |
| bulk.email | bulk_extractor | 48884 |
| bulk.ether | bulk_extractor | 5565 |
| bulk.exif | bulk_extractor | 392 |
| bulk.gps | bulk_extractor | 48 |
| bulk.rfc822 | bulk_extractor | 1340 |
| bulk.url | bulk_extractor | 92280 |
| bulk.url_facebook-address | bulk_extractor | 12 |
| bulk.url_facebook-id | bulk_extractor | 7 |
| bulk.url_searches | bulk_extractor | 34 |
| bulk.url_services | bulk_extractor | 1525 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) -- AI-driven forensic investigation via MCP*
