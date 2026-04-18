# Phone Forensics Roadmap for Mulder

## Problem

Mulder currently has limited phone forensic capabilities. In the NGDC case,
Carry's phone (raw .bin dump) and Tracy's phone (E01 images) contained
evidence the agent couldn't fully access. The `org.alexmbrown.sly` encrypted
app on Carry's tablet was flagged but not cracked. Phone evidence
(SMS, contacts, call logs, app data) is often the key to answering Q4
(lateral movement), Q5 (data theft), and Q8 (motive/attribution).

## Current Capabilities

| Capability | Status | Gap |
|-----------|--------|-----|
| Extract phone ZIPs/TARs | Working | `extract_archive` handles this |
| Classify phone databases | Working | Classifier detects contacts2.db, mmssms.db, etc. |
| Query SQLite from disk image | Working | `query_sqlite_from_image` needs an inode |
| Parse browser history | Working | `parse_browser_history` for Chrome/Firefox/Safari |
| Steganography detection | Partial | `stegdetect` now in Dockerfile, HEIC conversion added |
| SQLite carving from raw images | Missing | Can't find databases in raw .bin dumps |
| Android artifact parsing | Missing | No dedicated SMS/contacts/call log parser |
| iOS backup parsing | Missing | No plist-based backup manifest parser |
| App data decryption | Missing | No way to handle encrypted app databases |
| WhatsApp/Signal/Telegram parsing | Missing | No chat app parsers |

## Proposed New MCP Tools

### Tool 1: `carve_sqlite_from_raw` -- SQLite Database Carver

Finds and extracts SQLite databases from raw binary images (phone dumps,
.bin files) where the filesystem can't be read by TSK.

**How it works:**
1. Scan the raw image for SQLite magic bytes (`SQLite format 3\000`)
2. For each hit, read the database header to get page size and page count
3. Extract the complete database to a temp file
4. Return the list of carved databases with sizes and table names

**Underlying tools (choose one):**
- [FQLite](https://www.staff.hs-mittweida.de/~pawlaszc/fqlite/) -- Java,
  100% recovery rate in forensic testing, handles deleted records
- [DC3 sqlite-dissect](https://github.com/dod-cyber-crime-center/sqlite-dissect)
  -- Python, DoD-maintained, carving + recovery + freelist parsing
- [xsqlite](https://github.com/NetherlandsForensicInstitute/xsqlite) --
  Python, Netherlands Forensic Institute, deleted record recovery
- Custom: simple Python script using SQLite magic byte scanning + page
  extraction (fastest to implement, least capable)

**MCP function signature:**
```python
@mcp.tool()
def carve_sqlite_from_raw(
    image_path: str,
    max_databases: int = 50,
) -> dict:
    """Carve SQLite databases from a raw binary image.

    Scans for SQLite magic bytes and extracts complete databases to
    temp files. Returns database paths, sizes, and table listings.
    Use query_sqlite_from_image on the carved databases for analysis.
    """
```

**Implementation approach:**
```python
SQLITE_MAGIC = b"SQLite format 3\000"

def _carve_sqlite_databases(image_path, tmpdir, max_dbs=50):
    with open(image_path, "rb") as f:
        data = f.read()

    databases = []
    offset = 0
    while len(databases) < max_dbs:
        pos = data.find(SQLITE_MAGIC, offset)
        if pos == -1:
            break
        # Read SQLite header (first 100 bytes)
        header = data[pos:pos+100]
        page_size = int.from_bytes(header[16:18], "big")
        if page_size == 1:
            page_size = 65536
        db_size_pages = int.from_bytes(header[28:32], "big")
        db_size = page_size * db_size_pages

        if db_size > 0 and db_size < 500_000_000:  # sanity check
            db_data = data[pos:pos+db_size]
            db_path = Path(tmpdir) / f"carved_{pos:010x}.sqlite"
            db_path.write_bytes(db_data)
            # Get table names
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                tables = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()]
                conn.close()
                databases.append({
                    "offset": pos,
                    "size": db_size,
                    "path": str(db_path),
                    "tables": tables,
                })
            except sqlite3.Error:
                pass

        offset = pos + max(page_size, 1)

    return databases
```

### Tool 2: `parse_android_artifacts` -- Android Evidence Parser

Comprehensive Android artifact parser that handles both logical extractions
(from ZIP/TAR backups) and carved databases from raw images.

**Artifacts to parse:**

| Artifact | Database Path | Key Tables/Queries |
|----------|--------------|-------------------|
| SMS/MMS | `mmssms.db` | `SELECT address, body, date, type FROM sms ORDER BY date DESC` |
| Contacts | `contacts2.db` | `SELECT display_name, data1 FROM contacts JOIN data ON contacts._id=data.raw_contact_id WHERE mimetype_id IN (5,6)` |
| Call Log | `contacts2.db` or `calllog.db` | `SELECT number, name, duration, date, type FROM calls ORDER BY date DESC` |
| Browser | `browser2.db` | `SELECT url, title, date FROM bookmarks WHERE bookmark=0 ORDER BY date DESC` |
| WiFi | `wpa_supplicant.conf` or `WifiConfigStore.xml` | SSID, BSSID, password |
| Accounts | `accounts.db` | `SELECT name, type FROM accounts` |
| Downloads | `downloads.db` | `SELECT uri, _data, title, lastmod FROM downloads` |
| Calendar | `calendar.db` | `SELECT title, dtstart, dtend, description FROM Events` |
| WhatsApp | `msgstore.db` | `SELECT key_remote_jid, data, timestamp FROM messages ORDER BY timestamp DESC` |
| Telegram | `cache4.db` | Messages table varies by version |
| Signal | `signal.db` | `SELECT body, date_sent, address FROM sms` |
| Skype | `main.db` | `SELECT author, body_xml, timestamp FROM Messages` |
| Gmail | `mailstore.*.db` | `SELECT fromAddress, subject, snippet, dateReceivedMs FROM messages` |

**MCP function signature:**
```python
@mcp.tool()
def parse_android_artifacts(
    evidence_path: str,
    artifact_types: list[str] | None = None,
) -> dict:
    """Parse Android artifacts from a logical extraction or carved databases.

    evidence_path can be a directory containing extracted phone backup
    files, or a path to a raw .bin image (will carve SQLite DBs first).

    artifact_types filters which artifacts to parse (e.g. ["sms", "contacts",
    "calls", "whatsapp"]). Parses all if omitted.
    """
```

### Tool 3: `parse_ios_artifacts` -- iOS Evidence Parser

Parses iOS backup formats (iTunes/Finder backups, logical extractions).

**Artifacts to parse:**

| Artifact | Database/File | Key Tables/Queries |
|----------|-------------|-------------------|
| SMS/iMessage | `sms.db` (3d0d7e5fb2ce288813306e4d4636395e047a3d28) | `SELECT text, datetime(date+978307200,'unixepoch'), handle.id FROM message JOIN handle ON message.handle_id=handle.ROWID` |
| Call History | `call_history.db` (2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca) | `SELECT address, duration, date, flags FROM call` |
| Contacts | `AddressBook.sqlitedb` (31bb7ba8914766d4ba40d6dfb6113c8b614be442) | `SELECT c0First, c1Last, c16Phone FROM ABPersonFullTextSearch_content` |
| Safari History | `History.db` (e74113c185fd8297e140571b60c618c6b47da205) | `SELECT url, title, visit_time FROM history_items JOIN history_visits` |
| Photos | `Photos.sqlite` | EXIF data, GPS coordinates, timestamps |
| Notes | `NoteStore.sqlite` | `SELECT ZTITLE, ZBODY FROM ZSFNOTE` |
| Health | `healthdb_secure.sqlite` | Step counts, heart rate, location data |
| WiFi | `com.apple.wifi.known-networks.plist` | SSID, BSSID, last connected |
| Locations | `consolidated.db` | GPS coordinates with timestamps |
| KnowledgeC | `knowledgeC.db` | App usage, device activity, screen time |
| Voicemail | `voicemail.db` | `SELECT sender, date, duration FROM voicemail` |

**iOS backup manifest:**
iTunes/Finder backups use `Manifest.db` which maps SHA1 hashes to
original file paths. The parser should:
1. Open `Manifest.db`
2. Query `SELECT fileID, relativePath, domain FROM Files`
3. Map hash-named files back to their original paths
4. Parse each artifact database using the queries above

### Tool 4: `decrypt_app_data` -- Application Data Decryptor

Attempts to decrypt/parse data from known application formats.

**Approach for unknown apps (like org.alexmbrown.sly):**
1. Extract the app's data directory from the image
2. Check for SQLite databases (even encrypted ones have headers)
3. Try common encryption patterns:
   - SQLCipher (most common Android DB encryption) -- try empty password,
     then common passwords from keylogger output
   - SharedPreferences XML files (often contain keys/tokens in plaintext)
   - Room database with passphrase
4. Extract any plaintext strings from binary data files
5. Check `shared_prefs/*.xml` for API keys, tokens, account names

**For known apps:**
- WhatsApp: `key` file + `msgstore.db.crypt14` → decrypt with known algorithm
- Signal: SQLCipher with passphrase from `shared_prefs`
- Telegram: custom encryption, parse `cache4.db` directly

**MCP function signature:**
```python
@mcp.tool()
def decrypt_app_data(
    app_data_path: str,
    known_passwords: list[str] | None = None,
) -> dict:
    """Attempt to decrypt and parse application data.

    Tries SQLCipher decryption with provided passwords, parses
    SharedPreferences XML, and extracts plaintext from binary files.
    known_passwords should include any passwords found during the
    investigation (from keylogger, browser history, etc.).
    """
```

## Dockerfile Additions

```dockerfile
# Phone forensics tools
RUN pip install --no-cache \
    iLeapp \          # iOS artifact parser (1000+ stars)
    aleapp \          # Android artifact parser (companion to iLEAPP)
    mvt \             # Mobile Verification Toolkit (Amnesty International)
    pysqlcipher3      # SQLCipher support for encrypted databases

# FQLite for SQLite carving (Java)
RUN apt-get install -y default-jre-headless \
    && wget -q https://github.com/pawlaszczyk/fqlite/releases/download/v4.0/fqlite-4.0.jar \
        -O /opt/fqlite.jar
```

**Note on dependencies:**
- `iLeapp` and `aleapp` are the gold standard for mobile forensics
- `mvt` (Mobile Verification Toolkit) by Amnesty International detects
  Pegasus and other spyware -- adds credibility to the tool
- `pysqlcipher3` enables SQLCipher decryption for encrypted app databases
- FQLite is Java but has the best SQLite carving capability

## Priority Order for Implementation

| Priority | Tool | Impact | Effort |
|----------|------|--------|--------|
| 1 | `carve_sqlite_from_raw` | Unlocks ALL phone evidence from raw dumps | Medium (Python, no deps) |
| 2 | `parse_android_artifacts` | Structured Android evidence extraction | Medium (wraps aleapp or custom) |
| 3 | `parse_ios_artifacts` | Structured iOS evidence extraction | Medium (wraps iLeapp or custom) |
| 4 | `decrypt_app_data` | Cracks encrypted app databases | Hard (SQLCipher, app-specific) |

## What This Would Have Found in NGDC

With these tools, the NGDC investigation would have:

1. **Carved SQLite databases from Carry's phone .bin dump** → found SMS
   messages between Carry and Alex discussing the defacement plot
2. **Parsed Android contacts** → identified Alex's phone number and email
   (alexjfam11@gmail.com already found, but with context)
3. **Parsed Android browser history** from carved databases → found
   Carry's research into Krasnovia, art defacement, flash mob planning
4. **Decrypted org.alexmbrown.sly** → possibly revealed encrypted
   communications between Carry and Alex about the Krasnovian plot
5. **Parsed iOS backup from Tracy's phone** → found SMS/iMessage threads
   with Pat (brother) about the stamp theft plan
