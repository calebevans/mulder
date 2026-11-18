"""Microsoft 365 and Entra ID audit logs: every export shape reaches the index, the log
tables, the summary and the rules, and mailbox files reach parse_pst.

The records are hand-written after Microsoft's schema documentation and real records
(field names, value forms and the places a value hides in), with documentation
addresses, an invented tenant and generated identifiers.
"""

from __future__ import annotations

import csv
import inspect
import io
import json
import os
import sqlite3
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from mulder import logtable, m365
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.extractors.classifier import EvidenceClassifier
from mulder.orchestrator import prompts
from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.types import PhaseResult
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.extract_helpers import _WINDOW_CHAR_BUDGET
from mulder.server.tool_access import Role, get_tools_for_role
from mulder.server.tools import cloudlogs, review
from mulder.server.tools.cloudlogs import (
    _MULDER_RULES,
    _flatten,
    _read_events,
    run_cloud_audit_logs,
)

_TENANT = "3ebe6a93-c972-4720-8a1d-4e8c66419917"
_ATTACKER_IP = "203.0.113.9"
_SESSION = "793195b2-2fc4-4264-905f-77f8c41932da"
_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0"
_SYSTEM = "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)"


def _exchange_admin(
    operation: str, when: str, parameters: dict[str, str], **more: Any
) -> dict[str, Any]:
    """An ExchangeAdmin record (RecordType 1), as the Management Activity API writes it."""
    return {
        "CreationTime": when,
        "Id": f"id-{operation}-{when}",
        "Operation": operation,
        "OrganizationId": _TENANT,
        "RecordType": 1,
        "ResultStatus": "True",
        "UserKey": "1003200075E8231E",
        "UserType": 2,
        "Version": 1,
        "Workload": "Exchange",
        "ClientIP": f"{_ATTACKER_IP}:9808",
        "ObjectId": "alice",
        "UserId": "alice@contoso.example",
        "AppId": "00000002-0000-0ff1-ce00-000000000000",
        "ClientAppId": "",
        "ExternalAccess": False,
        "OrganizationName": "contoso.example",
        "Parameters": [{"Name": name, "Value": value} for name, value in parameters.items()],
        "SessionId": _SESSION,
        **more,
    }


def _provisioning(operation: str, when: str, parameters: dict[str, str]) -> dict[str, Any]:
    """The same cmdlet run by Exchange Online itself: no client address and no session."""
    record = _exchange_admin(operation, when, parameters, UserId=_SYSTEM, UserKey=_SYSTEM)
    del record["ClientIP"], record["SessionId"]
    return record


def _directory(operation: str, when: str, modified: dict[str, str], **more: Any) -> dict[str, Any]:
    """An AzureActiveDirectory record (RecordType 8): the operation ends in a period."""
    return {
        "CreationTime": when,
        "Id": f"id-{operation}-{when}",
        "Operation": operation,
        "OrganizationId": _TENANT,
        "RecordType": 8,
        "ResultStatus": "Success",
        "UserKey": "100320001D2AB3BA@contoso.example",
        "UserType": 0,
        "Version": 1,
        "Workload": "AzureActiveDirectory",
        "ObjectId": "be8658b1-f384-4439-9b82-7d20c8ee272c",
        "UserId": "alice@contoso.example",
        "AzureActiveDirectoryEventType": 1,
        "ExtendedProperties": [
            {"Name": "additionalDetails", "Value": json.dumps({"User-Agent": _CHROME})},
            {"Name": "extendedAuditEventCategory", "Value": "ServicePrincipal"},
        ],
        "ModifiedProperties": [
            {"Name": name, "NewValue": value, "OldValue": ""} for name, value in modified.items()
        ],
        "Actor": [{"ID": "alice@contoso.example", "Type": 5}],
        "ActorContextId": _TENANT,
        "Target": [{"ID": "ServicePrincipal_62d940e3", "Type": 2}],
        **more,
    }


def _logon(operation: str, when: str, ip: str, session: str, **more: Any) -> dict[str, Any]:
    """An AzureActiveDirectoryStsLogon record (RecordType 15)."""
    return {
        "CreationTime": when,
        "Id": f"id-{operation}-{when}",
        "Operation": operation,
        "OrganizationId": _TENANT,
        "RecordType": 15,
        "ResultStatus": "Success" if operation == "UserLoggedIn" else "Failed",
        "UserKey": "8ca9b00c-290a-40d3-9f18-8d6b7725b374",
        "UserType": 0,
        "Version": 1,
        "Workload": "AzureActiveDirectory",
        "ClientIP": ip,
        "ObjectId": "00000002-0000-0ff1-ce00-000000000000",
        "UserId": "alice@contoso.example",
        "ExtendedProperties": [
            {"Name": "ResultStatusDetail", "Value": "Success"},
            {"Name": "UserAgent", "Value": _CHROME},
            {"Name": "RequestType", "Value": "Login:login"},
        ],
        "ModifiedProperties": [],
        "ActorIpAddress": ip,
        "ApplicationId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "DeviceProperties": [
            {"Name": "OS", "Value": "Windows 10"},
            {"Name": "SessionId", "Value": session},
        ],
        "ErrorNumber": "0",
        **more,
    }


def _mail_access(when: str, how: str, ip: str, session: str, **more: Any) -> dict[str, Any]:
    """A MailItemsAccessed record: OperationProperties says Sync or Bind."""
    return {
        "CreationTime": when,
        "Id": f"id-mia-{when}",
        "Operation": "MailItemsAccessed",
        "OrganizationId": _TENANT,
        "RecordType": 50,
        "ResultStatus": "Succeeded",
        "UserKey": "10032001266C162C",
        "UserType": 0,
        "Version": 1,
        "Workload": "Exchange",
        "UserId": "alice@contoso.example",
        "AppId": "00000002-0000-0ff1-ce00-000000000000",
        "ClientAppId": "11c0913d-9fe8-460b-9a28-88c4b4df919a",
        "ClientIPAddress": ip,
        "ClientInfoString": "Client=OWA;Action=ViaProxy",
        "ExternalAccess": False,
        "LogonType": 0,
        "MailboxOwnerUPN": "alice@contoso.example",
        "OperationProperties": [
            {"Name": "MailAccessType", "Value": how},
            {"Name": "IsThrottled", "Value": "False"},
        ],
        "AppAccessContext": {"AADSessionId": session, "ClientAppId": "11c0913d"},
        **more,
    }


_INBOX_RULE = _exchange_admin(
    "New-InboxRule",
    "2026-10-05T12:29:35",
    {
        "Name": ".",
        "SubjectContainsWords": "invoice;payment",
        "MoveToFolder": "RSS Feeds",
        "MarkAsRead": "True",
        "StopProcessingRules": "True",
    },
    ObjectId="EURPR04A009.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/alice\\.",
)
_FORWARDING = _exchange_admin(
    "Set-Mailbox",
    "2026-10-05T12:30:51",
    {
        "Identity": "alice",
        "ForwardingSmtpAddress": "smtp:alice.contoso@mail.example",
        "DeliverToMailboxAndForward": "True",
    },
    ClientIP="[2001:db8::1a:9b]:54809",
)
_PERMISSION = _exchange_admin(
    "Add-MailboxPermission",
    "2026-10-05T12:32:53",
    {"Identity": "cfo@contoso.example", "AccessRights": "FullAccess", "User": "alice"},
)
_SEND_AS = _exchange_admin(
    "Add-RecipientPermission",
    "2026-10-05T12:33:10",
    {"Identity": "cfo@contoso.example", "AccessRights": "SendAs", "Trustee": "alice"},
)
_TRANSPORT_RULE = _exchange_admin(
    "New-TransportRule",
    "2026-10-05T12:35:47",
    {"Name": ".", "BlindCopyTo": "itcornpany@mail.example", "SubjectOrBodyContainsWords": "IBAN"},
)
_AUDIT_BYPASS = _exchange_admin(
    "Set-MailboxAuditBypassAssociation",
    "2026-10-05T12:36:00",
    {"AuditBypassEnabled": "True", "Identity": "alice@contoso.example"},
)
_AUDIT_OFF = _exchange_admin(
    "Set-AdminAuditLogConfig",
    "2026-10-05T12:36:30",
    {"UnifiedAuditLogIngestionEnabled": "False"},
)
_MAILBOX_AUDIT_OFF = _exchange_admin(
    "Set-Mailbox", "2026-10-05T12:37:00", {"Identity": "alice", "AuditEnabled": "False"}
)
_CONSENT = _directory(
    "Consent to application.",
    "2026-10-05T12:40:14",
    {
        "ConsentContext.IsAdminConsent": "False",
        "ConsentAction.Permissions": "[] => [[Scope: Mail.Read offline_access]]; ",
    },
)
_APP_SECRET = _directory(
    "Update application – Certificates and secrets management ",
    "2026-10-05T12:44:41",
    {"KeyDescription": '[\r\n  "[KeyIdentifier=bf0bc63d,KeyType=Password,KeyUsage=Verify]"\r\n]'},
    ObjectId="Application_1da54bcb-978f-4d88-99b9-985e63760e88",
)
_SP_SECRET = _directory(
    "Add service principal credentials.",
    "2026-10-05T12:45:00",
    {"KeyDescription": "[KeyIdentifier=11aa,KeyType=AsymmetricX509Cert,KeyUsage=Verify]"},
)
_MFA_REGISTERED = _directory(
    "User registered security info",
    "2026-10-05T12:20:00",
    {},
    ResultReason="User registered Authenticator App with Notification and Code",
)
_UPDATE_INBOX_RULES = {
    "CreationTime": "2026-10-05T12:50:00",
    "Id": "id-updateinboxrules",
    "Operation": "UpdateInboxRules",
    "OrganizationId": _TENANT,
    "RecordType": 2,
    "ResultStatus": "Succeeded",
    "UserId": "alice@contoso.example",
    "Workload": "Exchange",
    "ClientIPAddress": _ATTACKER_IP,
    "ClientInfoString": "Client=MSExchangeRPC",
    "MailboxOwnerUPN": "alice@contoso.example",
    "OperationProperties": [
        {"Name": "RuleOperation", "Value": "AddMailboxRule"},
        {"Name": "RuleName", "Value": "x"},
        {
            "Name": "RuleActions",
            "Value": '[{"ActionType":"Forward","Recipients":["a@mail.example"]}]',
        },
    ],
    "SessionId": _SESSION,
}
#: One realistic event per shipped rule, by the rule's file name.
_RULE_EVENTS: dict[str, list[dict[str, Any]]] = {
    "m365_inbox_rule_changed": [_INBOX_RULE, _UPDATE_INBOX_RULES],
    "m365_mailbox_forwarding_set": [_FORWARDING],
    "m365_mailbox_permission_granted": [_PERMISSION, _SEND_AS],
    "m365_application_consent_granted": [_CONSENT],
    "m365_application_credentials_added": [_APP_SECRET, _SP_SECRET],
    "m365_authentication_method_registered": [_MFA_REGISTERED],
    "m365_audit_logging_disabled": [_AUDIT_BYPASS, _AUDIT_OFF, _MAILBOX_AUDIT_OFF],
    "m365_transport_rule_changed": [_TRANSPORT_RULE],
}
#: Events that look like the above and are not: no rule may match them.
_LOOK_ALIKES = [
    # Exchange provisioning a mailbox, as its own service account.
    _provisioning("Add-MailboxPermission", "2026-10-01T00:00:00", {"User": "x"}),
    _provisioning(
        "Set-AdminAuditLogConfig",
        "2026-10-01T00:00:01",
        {"UnifiedAuditLogIngestionEnabled": "False"},
    ),
    _exchange_admin("Set-Mailbox", "2026-10-01T00:00:02", {"RecoverableItemsQuota": "30 GB"}),
    _exchange_admin("Set-MailboxAuditBypassAssociation", "2026-10-01T00:00:03", {})
    | {"Parameters": [{"Name": "AuditBypassEnabled", "Value": "$false"}]},
    _exchange_admin("Remove-InboxRule", "2026-10-01T00:00:04", {"Identity": "x"}),
    _directory("Remove service principal credentials.", "2026-10-01T00:00:05", {}),
    _directory("Update user.", "2026-10-01T00:00:06", {"StrongAuthenticationRequirement": "[]"}),
    _logon("UserLoggedIn", "2026-10-01T00:00:07", "198.51.100.7", "s-0"),
]

_GRAPH_SIGNIN = {  # Microsoft Graph v1.0 signIn: no user agent, no session id
    "id": "66ea54eb-6301-4ee5-be62-ff5a759b0100",
    "createdDateTime": "2026-10-05T12:13:13.1234567Z",
    "userDisplayName": "Alice Example",
    "userPrincipalName": "alice@contoso.example",
    "userId": "8ca9b00c-290a-40d3-9f18-8d6b7725b374",
    "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
    "appDisplayName": "Graph Explorer",
    "ipAddress": _ATTACKER_IP,
    "clientAppUsed": "Browser",
    "correlationId": "d79f5bee-5860-4832-928f-3133e22ae912",
    "conditionalAccessStatus": "notApplied",
    "isInteractive": True,
    "riskLevelDuringSignIn": "none",
    "resourceDisplayName": "Microsoft Graph",
    "status": {"errorCode": 0, "failureReason": None, "additionalDetails": None},
    "deviceDetail": {"operatingSystem": "Windows 10", "browser": "Chrome 114.0.0"},
    "location": {"city": "Amsterdam", "state": "Noord-Holland", "countryOrRegion": "NL"},
}
_GRAPH_SIGNIN_BETA = _GRAPH_SIGNIN | {
    "id": "beta-1",
    "userAgent": _CHROME,
    "sessionId": _SESSION,
    "uniqueTokenIdentifier": "6mRn2pDO6UqtK1mLoyUdAA",
    "authenticationRequirement": "singleFactorAuthentication",
    "autonomousSystemNumber": 64496,
    "status": {"errorCode": 50126, "failureReason": "Invalid username or password."},
}
_LA_SIGNIN = {  # Log Analytics SigninLogs: PascalCase, dynamic columns as JSON strings
    "TimeGenerated": "2026-10-05T12:15:00.123Z",
    "Id": "la-1",
    "UserPrincipalName": "bob@contoso.example",
    "IPAddress": "2001:db8::7",
    "AppId": "00000002-0000-0ff1-ce00-000000000000",
    "AppDisplayName": "Office 365 Exchange Online",
    "ResourceDisplayName": "Office 365 Exchange Online",
    "ResultType": "50126",
    "ResultDescription": "Invalid username or password.",
    "UserAgent": "python-requests/2.28.2",
    "SessionId": "la-session",
    "UniqueTokenIdentifier": "tok-1",
    "AuthenticationRequirement": "multiFactorAuthentication",
    "ConditionalAccessStatus": "failure",
    "IsInteractive": False,
    "ClientAppUsed": "Other clients",
    "LocationDetails": json.dumps({"city": "Bucharest", "countryOrRegion": "RO"}),
    "DeviceDetail": json.dumps({"operatingSystem": "Linux"}),
}
_GRAPH_AUDIT = {  # Microsoft Graph directoryAudit
    "id": "Directory_a1b2c3",
    "category": "ApplicationManagement",
    "correlationId": "83069a8d-357f-457e-93ca-5cdf8a1a2c46",
    "result": "success",
    "resultReason": "",
    "activityDisplayName": "Consent to application",
    "activityDateTime": "2026-10-05T12:40:14.5Z",
    "loggedByService": "Core Directory",
    "operationType": "Assign",
    "initiatedBy": {
        "user": {
            "id": "8ca9b00c",
            "userPrincipalName": "alice@contoso.example",
            "ipAddress": _ATTACKER_IP,
        },
        "app": None,
    },
    "targetResources": [
        {
            "id": "62d940e3-fd5b-47c3-8fe7-131abb360587",
            "displayName": "PerfectData Software",
            "type": "ServicePrincipal",
            "modifiedProperties": [
                {
                    "displayName": "ConsentAction.Permissions",
                    "oldValue": None,
                    "newValue": '"[] => [[Scope: Mail.Read offline_access]]"',
                }
            ],
        }
    ],
    "additionalDetails": [{"key": "User-Agent", "value": _CHROME}],
}
_LA_AUDIT = {  # Log Analytics AuditLogs
    "TimeGenerated": "2026-10-05T12:45:00Z",
    "Id": "la-audit-1",
    "OperationName": "Add service principal credentials",
    "Category": "ApplicationManagement",
    "Result": "success",
    "LoggedByService": "Core Directory",
    "CorrelationId": "corr-9",
    "InitiatedBy": json.dumps(
        {"app": {"displayName": "Deploy Pipeline", "servicePrincipalId": "sp-1"}}
    ),
    "TargetResources": json.dumps(
        [
            {
                "id": "sp-2",
                "displayName": "Backup App",
                "type": "ServicePrincipal",
                "modifiedProperties": [
                    {"displayName": "KeyDescription", "newValue": "[KeyType=Password]"}
                ],
            }
        ]
    ),
}


def _recognise(event: dict[str, Any]) -> m365.Record:
    record = m365.recognise(event)
    assert record is not None, event
    return record


def _csv(header: list[str], rows: list[list[str]], preamble: str = "") -> str:
    out = io.StringIO()
    csv.writer(out, quoting=csv.QUOTE_ALL).writerows([header, *rows])
    return preamble + out.getvalue()


def _purview_csv(events: list[dict[str, Any]]) -> str:
    """The Purview portal's export."""
    header = ["RecordId", "CreationDate", "RecordType", "Operation", "UserId", "AuditData"]
    rows = [
        [
            e["Id"],
            "2026-10-05T12:29:35.0000000Z",
            str(e["RecordType"]),
            e["Operation"],
            e["UserId"],
        ]
        + [json.dumps(e, separators=(",", ":"))]
        for e in events
    ]
    return _csv(header, rows)


def _powershell_csv(events: list[dict[str, Any]]) -> str:
    """Search-UnifiedAuditLog | Export-Csv on Windows PowerShell, without -NoTypeInformation."""
    header = ["PSComputerName", "RunspaceId", "RecordType", "CreationDate", "UserIds"]
    header += ["Operations", "AuditData", "ResultIndex", "ResultCount", "Identity", "IsValid"]
    rows = [
        [
            "outlook.office365.com",
            "2850e838",
            "ExchangeAdmin",
            "10/5/2026 12:29:35 PM",
            e["UserId"],
        ]
        + [e["Operation"], json.dumps(e), str(n), str(len(events)), e["Id"], "True"]
        for n, e in enumerate(events, 1)
    ]
    kind = "#TYPE Deserialized.Microsoft.Exchange.Data.ApplicationLogic.UnifiedAuditLogEvent\r\n"
    return _csv(header, rows, preamble=kind)


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    """A real case database behind the server context, so indexing is not mocked."""
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


def _run(path: Path, **kwargs: Any) -> dict[str, Any]:
    """The tool without Zircolite, which the unit tests do not have."""
    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        result: dict[str, Any] = run_cloud_audit_logs.__wrapped__(str(path), **kwargs)  # type: ignore[attr-defined]
    return result


def _text(db: CaseDB, source: str) -> str:
    return "".join(w.raw_text for w in db.get_windows_by_source(source))


def _rows(db: CaseDB, table: str, **kwargs: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = logtable.rows(db, table, limit=500, **kwargs)["rows"]
    return found


# --- classification -------------------------------------------------------------------


def test_exports_are_cloud_audit_logs_and_outlook_files_are_mailboxes(tmp_path: Path) -> None:
    root = tmp_path / "contoso-m365"
    (root / "mail").mkdir(parents=True)
    (root / "ual-purview.csv").write_text(_purview_csv([_INBOX_RULE]))
    (root / "ual-powershell.csv").write_bytes(_powershell_csv([_INBOX_RULE]).encode("utf-16"))
    (root / "ual.jsonl").write_text(json.dumps(_INBOX_RULE))
    wrapped = {
        "RecordType": "ExchangeAdmin",
        "Operations": "x",
        "AuditData": json.dumps(_FORWARDING),
    }
    (root / "ual-wrapped.json").write_bytes(json.dumps([wrapped], indent=4).encode("utf-16"))
    (root / "signins.json").write_text(json.dumps([_GRAPH_SIGNIN], indent=2))
    (root / "signins-la.json").write_text(json.dumps([_LA_SIGNIN]))
    (root / "audit.json").write_text(json.dumps([_GRAPH_AUDIT]))
    (root / "mail" / "alice.pst").write_bytes(b"!BDN")
    (root / "mail" / "BOB.OST").write_bytes(b"!BDN")
    # Not audit logs: an ordinary CSV, one that only mentions the column, ordinary JSON.
    (root / "inventory.csv").write_text("host,owner\nws-01,alice\n")
    (root / "notes.csv").write_text('"note"\n"see the AuditData column"\n')
    (root / "settings.json").write_text('{"appId": "x", "theme": "dark"}')

    found = {
        str(c.path.relative_to(root.resolve())): c.artifact_type
        for c in EvidenceClassifier().classify(root)
    }

    assert found == {
        "audit.json": "cloud_audit_log",
        "mail/BOB.OST": "mailbox",
        "mail/alice.pst": "mailbox",
        "signins-la.json": "cloud_audit_log",
        "signins.json": "cloud_audit_log",
        "ual-powershell.csv": "cloud_audit_log",
        "ual-purview.csv": "cloud_audit_log",
        "ual-wrapped.json": "cloud_audit_log",
        "ual.jsonl": "cloud_audit_log",
    }


def test_the_classifier_does_not_open_a_fifo_named_like_an_export(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "ual.csv")  # opening it would block forever

    assert EvidenceClassifier().classify(tmp_path) == []


# --- shapes ---------------------------------------------------------------------------


def test_every_unified_audit_log_export_yields_the_same_record(tmp_path: Path) -> None:
    """The Purview CSV, Search-UnifiedAuditLog through Export-Csv and through
    ConvertTo-Json, the Management Activity API and the Graph audit query."""
    graph = {
        "id": _INBOX_RULE["Id"],
        "createdDateTime": "2026-10-05T12:29:35Z",
        "auditLogRecordType": "exchangeAdmin",
        "operation": "New-InboxRule",
        "organizationId": _TENANT,
        "userType": "admin",
        "userId": "1003200075E8231E",
        "service": "Exchange",
        "objectId": "alice",
        "userPrincipalName": "alice@contoso.example",
        "clientIp": f"{_ATTACKER_IP}:9808",
        "auditData": {"@odata.type": "#microsoft.graph.security.defaultAuditData"} | _INBOX_RULE,
    }
    wrapper = {"RecordType": "ExchangeAdmin", "CreationDate": "/Date(1791203375000)/"}
    wrapper |= {"UserIds": "alice@contoso.example", "Operations": "New-InboxRule"}
    files = {
        "purview.csv": _purview_csv([_INBOX_RULE]).encode(),
        "powershell.csv": _powershell_csv([_INBOX_RULE]).encode("utf-16"),
        "bom.csv": b"\xef\xbb\xbf" + _purview_csv([_INBOX_RULE]).encode(),
        "api.jsonl": json.dumps(_INBOX_RULE).encode(),
        "convertto-json.json": json.dumps(
            [wrapper | {"AuditData": _INBOX_RULE}], indent=4
        ).encode(),
        "convertto-json-string.json": json.dumps(
            [wrapper | {"AuditData": json.dumps(_INBOX_RULE)}]
        ).encode("utf-16"),
        "graph.json": json.dumps({"@odata.context": "https://graph", "value": [graph]}).encode(),
    }
    for name, data in files.items():
        file = tmp_path / name
        file.write_bytes(data)
        read = m365.read_csv if name.endswith(".csv") else _read_events
        events, damaged, not_objects = read(file)
        assert (len(events), damaged, not_objects) == (1, 0, 0), name
        record = _recognise(events[0])
        assert record.kind == "m365", name
        assert record.fields == {
            "event_time": "2026-10-05T12:29:35Z",
            "actor": "alice@contoso.example",
            "src_ip": _ATTACKER_IP,
            "action": "New-InboxRule",
            "target": _INBOX_RULE["ObjectId"],
            "status": "True",
            "user_agent": "",
            "session_id": _SESSION,
            "extra": {
                "event_id": _INBOX_RULE["Id"],
                "workload": "Exchange",
                "app_id": "00000002-0000-0ff1-ce00-000000000000",
            },
        }, name
        # What is indexed is the record itself, without the wrapper.
        assert record["Parameters"] == _INBOX_RULE["Parameters"], name


def test_a_graph_audit_record_without_the_inner_fields_takes_the_outer_ones() -> None:
    record = _recognise(
        {
            "id": "g-1",
            "createdDateTime": "2026-10-05T12:29:35Z",
            "auditLogRecordType": "exchangeAdmin",
            "operation": "Set-Mailbox",
            "service": "Exchange",
            "userPrincipalName": "alice@contoso.example",
            "clientIp": "198.51.100.7",
            "auditData": {"Parameters": [{"Name": "ForwardingAddress", "Value": "x"}]},
        }
    )

    assert (record.kind, record.fields["action"], record.fields["src_ip"]) == (
        "m365",
        "Set-Mailbox",
        "198.51.100.7",
    )
    assert record.fields["extra"]["workload"] == "Exchange"


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        # The source address: three field names, with a port, in brackets, IPv4-mapped.
        ({"ClientIP": "203.0.113.9:52385"}, {"src_ip": "203.0.113.9"}),
        ({"ClientIP": "[2001:DB8::1A:9B]:54809"}, {"src_ip": "2001:db8::1a:9b"}),
        ({"ClientIPAddress": "2001:db8::13"}, {"src_ip": "2001:db8::13"}),
        ({"ClientIPAddress": "::ffff:203.0.113.9"}, {"src_ip": "203.0.113.9"}),
        ({"ActorIpAddress": "198.51.100.7"}, {"src_ip": "198.51.100.7"}),
        ({"ClientIP": "<null>"}, {"src_ip": "<null>"}),
        # The user agent: SharePoint, Entra sign-ins, Entra directory changes, mailboxes.
        ({"UserAgent": "OneDriveSync/23"}, {"user_agent": "OneDriveSync/23"}),
        (
            {"ExtendedProperties": [{"Name": "UserAgent", "Value": "python-requests/2.28.2"}]},
            {"user_agent": "python-requests/2.28.2"},
        ),
        (
            {
                "ExtendedProperties": [
                    {"Name": "additionalDetails", "Value": '{"User-Agent":"azurehound/v2.0.4"}'}
                ]
            },
            {"user_agent": "azurehound/v2.0.4"},
        ),
        (
            {"ClientInfoString": "Client=OWA;Action=ViaProxy"},
            {"user_agent": "Client=OWA;Action=ViaProxy"},
        ),
        # The session: its own field, the app access context, the device properties.
        ({"SessionId": "s-1"}, {"session_id": "s-1"}),
        ({"AppAccessContext": {"AADSessionId": "s-2"}}, {"session_id": "s-2"}),
        ({"DeviceProperties": [{"Name": "SessionId", "Value": "s-3"}]}, {"session_id": "s-3"}),
        # The error: real records say ErrorNumber, the schema ErrorCode; 0 is no error.
        ({"ErrorNumber": "50126"}, {"extra": {"error": "50126"}}),
        ({"ErrorCode": 50053}, {"extra": {"error": "50053"}}),
        ({"ErrorNumber": "0"}, {"extra": {}}),
        # A mailbox record has no ObjectId: the mailbox is its target.
        ({"MailboxOwnerUPN": "cfo@contoso.example"}, {"target": "cfo@contoso.example"}),
    ],
)
def test_a_field_is_found_wherever_the_workload_puts_it(
    event: dict[str, Any], expected: dict[str, Any]
) -> None:
    fields = _recognise({"CreationTime": "2026-10-05T12:00:00", "Operation": "X"} | event).fields

    for name, value in expected.items():
        if name == "extra":
            assert {k: v for k, v in fields["extra"].items() if k == "error"} == value
        else:
            assert fields[name] == value


def test_name_value_arrays_fold_into_objects_and_keep_repeated_names() -> None:
    assert m365.fold(_FORWARDING["Parameters"]) == {
        "Identity": "alice",
        "ForwardingSmtpAddress": "smtp:alice.contoso@mail.example",
        "DeliverToMailboxAndForward": "True",
    }
    modified = [{"Name": "KeyDescription", "NewValue": "new", "OldValue": "old"}]
    assert m365.fold(modified) == {"KeyDescription": "new"}
    assert m365.fold([{"key": "User-Agent", "value": "x"}]) == {"User-Agent": "x"}
    assert m365.fold([{"Name": "To", "Value": "a"}, {"Name": "To", "Value": "b"}]) == {
        "To": ["a", "b"]
    }
    # Whatever else an array holds is not a pair.
    assert m365.fold([None, "x", {"Value": "no name"}, {"Name": 7, "Value": 1}]) == {}
    assert m365.fold("Name=Value") == {}


def test_sign_ins_are_read_in_graph_and_log_analytics_spelling() -> None:
    v1, beta, la = (_recognise(e) for e in (_GRAPH_SIGNIN, _GRAPH_SIGNIN_BETA, _LA_SIGNIN))

    assert {r.kind for r in (v1, beta, la)} == {"entra_signin"}
    assert v1.fields == {
        "event_time": "2026-10-05T12:13:13Z",
        "actor": "alice@contoso.example",
        "src_ip": _ATTACKER_IP,
        "action": "Graph Explorer",
        "target": "Microsoft Graph",
        "status": "Success",
        # Graph v1.0 has neither, and neither is invented.
        "user_agent": "",
        "session_id": "",
        "extra": {
            "event_id": _GRAPH_SIGNIN["id"],
            "app_id": _GRAPH_SIGNIN["appId"],
            "client_app": "Browser",
            "interactive": "true",
            "conditional_access": "notApplied",
            "risk": "none",
            "country": "NL",
        },
    }
    assert (beta.fields["status"], beta.fields["user_agent"], beta.fields["session_id"]) == (
        "50126",
        _CHROME,
        _SESSION,
    )
    assert beta.fields["extra"] | {"event_id": ""} == v1.fields["extra"] | {
        "event_id": "",
        "auth_requirement": "singleFactorAuthentication",
        "asn": "64496",
        "token_id": "6mRn2pDO6UqtK1mLoyUdAA",
    }
    assert la.fields == {
        "event_time": "2026-10-05T12:15:00Z",
        "actor": "bob@contoso.example",
        "src_ip": "2001:db8::7",
        "action": "Office 365 Exchange Online",
        "target": "Office 365 Exchange Online",
        "status": "50126",
        "user_agent": "python-requests/2.28.2",
        "session_id": "la-session",
        "extra": {
            "event_id": "la-1",
            "app_id": "00000002-0000-0ff1-ce00-000000000000",
            "client_app": "Other clients",
            "interactive": "false",
            "auth_requirement": "multiFactorAuthentication",
            "conditional_access": "failure",
            "country": "RO",  # from LocationDetails, a JSON string in this export
            "token_id": "tok-1",
        },
    }


def test_directory_audits_are_read_in_graph_and_log_analytics_spelling() -> None:
    graph, la = _recognise(_GRAPH_AUDIT), _recognise(_LA_AUDIT)

    assert (graph.kind, la.kind) == ("entra_audit", "entra_audit")
    assert graph.fields == {
        "event_time": "2026-10-05T12:40:14Z",
        "actor": "alice@contoso.example",
        "src_ip": _ATTACKER_IP,
        "action": "Consent to application",
        "target": "PerfectData Software",
        "status": "success",
        "user_agent": _CHROME,
        "session_id": "",
        "extra": {
            "event_id": "Directory_a1b2c3",
            "category": "ApplicationManagement",
            "service": "Core Directory",
            "target_type": "ServicePrincipal",
            "correlation_id": "83069a8d-357f-457e-93ca-5cdf8a1a2c46",
        },
    }
    # An application acted, and the nested columns arrived as JSON strings.
    assert (la.fields["actor"], la.fields["action"], la.fields["target"], la.fields["src_ip"]) == (
        "Deploy Pipeline",
        "Add service principal credentials",
        "Backup App",
        "",
    )


def test_a_diagnostic_settings_stream_and_a_graph_page_are_unwrapped(tmp_path: Path) -> None:
    stream = {
        "records": [
            {
                "time": "2026-10-05T12:13:13Z",
                "category": "SignInLogs",
                "properties": _GRAPH_SIGNIN,
            },
            {"time": "2026-10-05T12:40:14Z", "category": "AuditLogs", "properties": _GRAPH_AUDIT},
            {"time": "2026-10-05T12:00:00Z", "category": "Administrative", "properties": {"x": 1}},
        ]
    }
    page = {
        "@odata.context": "https://graph.microsoft.com/beta/$metadata",
        "value": [_GRAPH_SIGNIN],
    }
    (tmp_path / "stream.json").write_text(json.dumps(stream))
    (tmp_path / "page.json").write_text(json.dumps(page))
    # "value" alone is no Graph page: a settings file stays one object.
    (tmp_path / "plain.json").write_text(json.dumps({"value": [1, 2]}))

    events, _, _ = _read_events(tmp_path / "stream.json")
    kinds = [getattr(m365.recognise(e), "kind", "generic") for e in events]

    assert kinds == ["entra_signin", "entra_audit", "generic"]
    assert _read_events(tmp_path / "page.json") == ([_GRAPH_SIGNIN], 0, 0)
    assert _read_events(tmp_path / "plain.json") == ([{"value": [1, 2]}], 0, 0)


def test_other_json_is_not_taken_for_a_microsoft_log() -> None:
    others: list[dict[str, Any]] = [
        {"Operation": "x"},  # no time
        {"appId": "x", "ipAddress": "1.2.3.4"},  # nothing that says sign-in
        {"initiatedBy": {}},
        {"AuditData": "not json", "Operations": "x"},
        {"properties": {"x": 1}, "category": "Administrative"},
    ]
    for event in others:
        assert m365.recognise(event) is None, event


def test_hostile_values_cannot_raise_break_a_line_or_reach_a_reader_as_control_text() -> None:
    forged = "ok\u2028FORGED\tLINE\x1b[31m\u202eevil\x00" + "A" * 5000
    hostile: list[dict[str, Any]] = [
        # Every field the wrong type.
        {
            "Operation": ["x"],
            "CreationTime": {"a": 1},
            "UserId": 7,
            "ClientIP": [1],
            "ExtendedProperties": "x",
            "DeviceProperties": [1, None, {"Name": [], "Value": {}}],
            "AppAccessContext": "x",
            "OperationProperties": {"Name": "x"},
            "Parameters": [[]],
            "Folders": "x",
            "Item": 3,
        },
        # Text that tries to start a second line or carry escape sequences.
        _exchange_admin("New-InboxRule", "2026-10-05T12:00:00", {"Name": forged})
        | {"UserId": forged, "ObjectId": forged, "ClientIP": forged, "SessionId": forged},
        {"appId": None, "ipAddress": forged, "resultType": forged, "status": "x", "location": 5},
        {"initiatedBy": forged, "targetResources": [forged], "additionalDetails": {"key": 1}},
    ]

    records = [_recognise(event) for event in hostile]

    for record in records:
        values = [v for k, v in record.fields.items() if k != "extra"]
        for value in [*values, *record.fields["extra"].values()]:
            assert isinstance(value, str) and len(value) <= 500
            assert value == "" or value.isprintable()
        assert len(cloudlogs._event_line(record.kind, record).splitlines()) == 1
    lines, _ = m365.summarise("m365", forged, records[:2])
    assert all(line.replace("\t", "").isprintable() for line in lines)
    assert not any(line.startswith("FORGED") for line in lines)
    # A time that is not one is no time: it cannot become a first or last seen.
    assert records[0].fields["event_time"] == ""


# --- through the tool -------------------------------------------------------------------

_SECOND_IP = "198.51.100.7"
_BEC = [
    # The user, from her usual address; then the same session from another one.
    _logon("UserLoggedIn", "2026-10-05T08:00:00", _SECOND_IP, _SESSION),
    _logon(
        "UserLoginFailed", "2026-10-05T12:10:00", _ATTACKER_IP, "s-failed", ErrorNumber="50126"
    ),
    _logon("UserLoggedIn", "2026-10-05T12:13:13", _ATTACKER_IP, _SESSION),
    _MFA_REGISTERED,
    _INBOX_RULE,
    _FORWARDING,
    _PERMISSION,
    _CONSENT,
    _mail_access(
        "2026-10-05T12:55:00",
        "Bind",
        _ATTACKER_IP,
        _SESSION,
        Folders=[
            {
                "Path": "\\Inbox",
                "FolderItems": [{"InternetMessageId": "<1@x>"}, {"InternetMessageId": "<2@x>"}],
            }
        ],
        OperationCount=2,
    ),
    _mail_access(
        "2026-10-05T13:05:00",
        "Sync",
        _ATTACKER_IP,
        _SESSION,
        ClientInfoString="Client=MSExchangeRPC",
        Item={"Id": "LgAAAA", "ParentFolder": {"Name": "Finance", "Path": "Not Available"}},
    ),
    # Exchange's own work: on the loopback address inside her session, and provisioning.
    _exchange_admin("Set-Mailbox", "2026-10-05T12:31:00", {"Identity": "alice"}, ClientIP="::1"),
    _provisioning("Add-MailboxPermission", "2026-10-01T03:00:00", {"User": "x"}),
]


@pytest.fixture
def bec(tmp_path: Path) -> Path:
    """One tenant's exports: the unified audit log as CSV, sign-ins and directory audits."""
    root = tmp_path / "contoso-m365"
    root.mkdir()
    (root / "ual.csv").write_text(_purview_csv(_BEC))
    (root / "signins.json").write_text(json.dumps([_GRAPH_SIGNIN, _GRAPH_SIGNIN_BETA, _LA_SIGNIN]))
    (root / "directory-audit.json").write_text(json.dumps([_GRAPH_AUDIT, _LA_AUDIT]))
    (root / "inventory.csv").write_text("host,owner\nws-01,alice\n")
    return root


def test_each_log_is_indexed_loaded_and_summarised(case: CaseDB, bec: Path) -> None:
    result = _run(bec)["results"]

    # inventory.csv is not an audit log: not read, and not reported as a problem.
    assert result["files_read"] == 3 and "files_with_problems" not in result
    types = result["log_types"]
    assert {name: entry["events"] for name, entry in types.items()} == {
        "entra_audit": 2,
        "entra_signin": 3,
        "m365": len(_BEC),
    }
    for name, entry in types.items():
        assert entry["source"] == entry["log_table"] == f"cloudlog.{name}"
        assert entry["summary_source"] == f"cloudlog.{name}.summary"
    assert types["m365"]["summary"] == {
        "users": 1,
        "sessions_from_several_ips": 1,
        "persistence_operations": 5,
        "mailboxes_accessed": 1,
    }
    assert types["entra_signin"]["summary"] == {"users": 2, "sessions_from_several_ips": 0}
    # A user is listed for the addresses, agents and sessions it has: the pipeline has none.
    assert types["entra_audit"]["summary"] == {"users": 1, "persistence_operations": 2}
    # Rules exist for the unified audit log; here there is no Zircolite to run them.
    assert types["m365"]["sigma"].startswith("skipped: ")
    assert "no Sigma rules" not in types["m365"]["sigma"]
    # No rules ship for the Entra logs, and the result says so rather than "0 detections".
    assert types["entra_signin"]["sigma"].startswith("skipped: no Sigma rules")
    assert "export_warnings" not in types["m365"]

    # One event per line, in time order: time, actor, action, source IP, target, event.
    lines = _text(case, "cloudlog.m365").splitlines()
    assert len(lines) == len(_BEC)
    assert lines[5].startswith(
        "2026-10-05T12:29:35Z\talice@contoso.example\tNew-InboxRule\t203.0.113.9\t"
    )
    assert json.loads(lines[5].split("\t")[5]) == _INBOX_RULE
    assert _text(case, "cloudlog.entra_signin").startswith(
        "2026-10-05T12:13:13Z\talice@contoso.example\tGraph Explorer\t203.0.113.9\t"
        "Microsoft Graph\t"
    )
    window = case.get_windows_by_source("cloudlog.m365")[0]
    assert str(window.event_time).startswith("2026-10-01T03:00:00")

    # The same events as rows, pointing at their line in the text.
    listed = {t["table"]: t for t in logtable.tables(case)}
    assert sorted(listed) == ["cloudlog.entra_audit", "cloudlog.entra_signin", "cloudlog.m365"]
    assert set(listed["cloudlog.m365"]["fields"]) == {
        "actor", "src_ip", "action", "target", "status", "user_agent", "session_id",
        "event_id", "workload", "app_id", "error", "mailbox", "access_type",
    }  # fmt: skip
    rule = _rows(
        case, "cloudlog.m365", filters=[{"field": "action", "op": "eq", "value": "New-InboxRule"}]
    )
    assert rule == [
        {
            "time": "2026-10-05T12:29:35Z",
            "actor": "alice@contoso.example",
            "src_ip": _ATTACKER_IP,
            "action": "New-InboxRule",
            "target": _INBOX_RULE["ObjectId"],
            "status": "True",
            "session_id": _SESSION,
            "event_id": _INBOX_RULE["Id"],
            "workload": "Exchange",
            "app_id": "00000002-0000-0ff1-ce00-000000000000",
            "source": "cloudlog.m365",
            "line": 6,
        }
    ]
    # The pivot the guidance asks for: who else used the intruder's address.
    shared = logtable.top(
        case,
        "cloudlog.entra_signin",
        ["actor"],
        filters=[{"field": "src_ip", "op": "eq", "value": _ATTACKER_IP}],
    )
    assert [(r["actor"], r["count"]) for r in shared["rows"]] == [("alice@contoso.example", 2)]


def test_the_summary_says_who_came_from_where_what_they_left_and_what_they_read(
    case: CaseDB, bec: Path
) -> None:
    _run(bec)

    lines = _text(case, "cloudlog.m365.summary").splitlines()
    assert lines[0] == (
        f"# Microsoft 365 unified audit log summary of {bec}: {len(_BEC)} events, "
        "2026-10-01T03:00:00Z to 2026-10-05T13:05:00Z"
    )
    assert "not by a model" in lines[1]
    # Per user: each source IP, user agent and session, first seen, events, last seen.
    assert (
        f"2026-10-05T12:10:00Z\tuser\talice@contoso.example\tsrc_ip\t{_ATTACKER_IP}"
        "\tevents=6\tlast=2026-10-05T13:05:00Z"
    ) in lines
    assert (
        f"2026-10-05T08:00:00Z\tuser\talice@contoso.example\tsrc_ip\t{_SECOND_IP}"
        "\tevents=1\tlast=2026-10-05T08:00:00Z"
    ) in lines
    assert (
        "2026-10-05T12:10:00Z\tuser\talice@contoso.example\tsession_id\ts-failed"
        "\tevents=1\tlast=2026-10-05T12:10:00Z"
    ) in lines
    assert any("\tuser_agent\tClient=MSExchangeRPC\tevents=1\t" in line for line in lines)
    # The session that moved: every address it was seen from, in order of first use, and
    # not the loopback one Exchange recorded for its own work.
    (session,) = [line for line in lines if "\tsession\t" in line]
    assert session == (
        f"2026-10-05T08:00:00Z\tsession\t{_SESSION}\tusers=alice@contoso.example\tips=3: "
        f"{_SECOND_IP} (events=1, 2026-10-05T08:00:00Z to 2026-10-05T08:00:00Z); "
        f"{_ATTACKER_IP} (events=5, 2026-10-05T12:13:13Z to 2026-10-05T13:05:00Z); "
        "2001:db8::1a:9b (events=1, 2026-10-05T12:30:51Z to 2026-10-05T12:30:51Z)"
    )
    # What was left behind, with the parameters folded; Exchange's own grant is counted.
    kept = [line.split("\t") for line in lines if "\tpersistence\t" in line]
    assert [(row[0], row[2], row[4]) for row in kept] == [
        ("2026-10-05T12:20:00Z", "authentication method", "User registered security info"),
        ("2026-10-05T12:29:35Z", "inbox rule", "New-InboxRule"),
        ("2026-10-05T12:30:51Z", "mailbox forwarding", "Set-Mailbox"),
        ("2026-10-05T12:32:53Z", "mailbox permission", "Add-MailboxPermission"),
        ("2026-10-05T12:40:14Z", "application consent", "Consent to application."),
    ]
    assert kept[2][3:] == [
        "alice@contoso.example",
        "Set-Mailbox",
        "2001:db8::1a:9b",
        _SESSION,
        "alice",
        json.dumps(m365.fold(_FORWARDING["Parameters"])),
    ]
    assert json.loads(kept[4][8])["ConsentAction.Permissions"].startswith(
        "[] => [[Scope: Mail.Read"
    )
    assert (
        "# operations that leave access behind or hide it: 5 (application consent 1, "
        "authentication method 1, inbox rule 1, mailbox forwarding 1, mailbox permission 1)"
        "; 1 more by Exchange's own"
    ) in "".join(lines)
    # What was read: a bind names its messages, a sync the folder that was copied.
    mailbox = {line.split("\t")[3]: line.split("\t") for line in lines if "\tmailbox\t" in line}
    assert mailbox["Bind"] == [
        "2026-10-05T12:55:00Z",
        "mailbox",
        "alice@contoso.example",
        "Bind",
        "events=1",
        "last=2026-10-05T12:55:00Z",
        "items=2",
        "throttled=0",
        "folders=\\Inbox (1)",
        "by=alice@contoso.example (1)",
        f"ips={_ATTACKER_IP} (1)",
        f"sessions={_SESSION} (1)",
    ]
    assert mailbox["Sync"][6:9] == ["items=0", "throttled=0", "folders=Finance (1)"]

    # The sign-in summary has no persistence or mailbox section to be empty in.
    signins = _text(case, "cloudlog.entra_signin.summary")
    assert "persistence" not in signins and "MailItemsAccessed" not in signins
    assert "\tuser\tbob@contoso.example\tsrc_ip\t2001:db8::7\tevents=1\t" in signins
    audit = _text(case, "cloudlog.entra_audit.summary").splitlines()
    assert [line.split("\t")[2:5] for line in audit if "\tpersistence\t" in line] == [
        ["application consent", "alice@contoso.example", "Consent to application"],
        ["application credentials", "Deploy Pipeline", "Add service principal credentials"],
    ]
    assert json.loads(audit[-1].split("\t")[8]) == {"KeyDescription": "[KeyType=Password]"}
    # Graph serialises a new value as JSON inside the string; it is shown as the value.
    assert json.loads(audit[-2].split("\t")[8]) == {
        "ConsentAction.Permissions": "[] => [[Scope: Mail.Read offline_access]]"
    }


def test_a_graph_v1_sign_in_export_says_it_cannot_link_sessions(
    case: CaseDB, tmp_path: Path
) -> None:
    file = tmp_path / "signins.json"
    file.write_text(json.dumps([_GRAPH_SIGNIN]))

    _run(file)

    summary = _text(case, "cloudlog.entra_signin.summary")
    assert "No record in this export has a user_agent or a session_id" in summary
    assert "not a finding that they differ or agree" in summary
    fields = {t["table"]: t["fields"] for t in logtable.tables(case)}["cloudlog.entra_signin"]
    assert "user_agent" not in fields and "session_id" not in fields


@pytest.mark.parametrize(
    ("count", "unreadable", "flagged"),
    # 100 is what Search-UnifiedAuditLog returns when no ResultSize is given, and a row
    # that cannot be read is still a row of the export.
    [(5000, 0, True), (4999, 0, False), (4999, 1, True), (100, 0, True), (99, 0, False)],
)
def test_an_export_of_exactly_the_size_at_which_exports_stop_is_flagged(
    case: CaseDB, tmp_path: Path, count: int, unreadable: int, flagged: bool
) -> None:
    file = tmp_path / "ual.csv"
    record = json.dumps({"CreationTime": "2026-10-05T12:00:00", "Operation": "FileAccessed"})
    rows = [["", "", "", record]] * count + [["", "", "", ""]] * unreadable
    file.write_text(_csv(["CreationDate", "UserIds", "Operations", "AuditData"], rows))

    entry = _run(file)["results"]["log_types"]["m365"]

    summary = _text(case, "cloudlog.m365.summary")
    assert entry["events"] == count
    if flagged:
        (warning,) = entry["export_warnings"]
        assert warning.startswith(f"{file}: exactly {count + unreadable} unified audit records")
        assert "probably incomplete" in warning
        assert f"WARNING\t{warning}" in summary.splitlines()
    else:
        assert "export_warnings" not in entry and "WARNING" not in summary


def test_csv_rows_without_an_event_are_counted_and_the_rest_is_kept(
    case: CaseDB, tmp_path: Path
) -> None:
    file = tmp_path / "ual.csv"
    header = ["CreationDate", "UserIds", "Operations", "AuditData"]
    rows = [
        ["", "", "", json.dumps(_INBOX_RULE)],
        ["", "", "", ""],  # real exports have such rows
        ["", "", "", '{"CreationTime": "2026-10-05T12:00:00", "Operation": "cut off'],
        ["short row"],
        ["", "", "", json.dumps(_FORWARDING)],
    ]
    file.write_text(_csv(header, rows) + "\r\n")
    # An export in which no row can be read, beside another log.
    (tmp_path / "broken.csv").write_text(_csv(header, [["", "", "", "{"], ["", "", "", "x"]]))
    (tmp_path / "signins.json").write_text(json.dumps([_GRAPH_SIGNIN]))

    result = _run(tmp_path)["results"]

    assert result["files_with_problems"] == {
        str(file): "rows without a readable AuditData event: 3; events read: 2",
        str(tmp_path / "broken.csv"): "rows without a readable AuditData event: 2; events read: 0",
    }
    # What a unified audit log CSV lost is that log's, not the sign-in log's.
    tables = {t["table"]: (t["rows"], t["rows_not_parsed"]) for t in logtable.tables(case)}
    assert tables == {"cloudlog.m365": (2, 5), "cloudlog.entra_signin": (1, 0)}


def test_a_csv_field_that_never_ends_costs_what_follows_it_and_says_so(tmp_path: Path) -> None:
    file = tmp_path / "ual.csv"
    good = _purview_csv([_INBOX_RULE])
    file.write_text(good + '"x","x","x","x","x","{' + "A" * (33 * 1024 * 1024))

    events, damaged, stopped = m365.read_csv(file)

    assert ([e["Operation"] for e in events], damaged, stopped) == (["New-InboxRule"], 1, 3)
    # A CSV that is not an audit export holds no events, and that is no damage.
    file.write_text("host,owner\nws-01,alice\n")
    assert m365.read_csv(file) == ([], 0, 0)


def test_a_csv_that_cannot_be_read_to_its_end_says_where_reading_stopped(
    case: CaseDB, tmp_path: Path
) -> None:
    """Four rows follow the one the csv module cannot get past: "one unreadable row"
    alone would be a wrong account of what was lost."""
    file = tmp_path / "ual.csv"
    rows = [["", "", "", json.dumps(_INBOX_RULE | {"Id": str(n)})] for n in range(6)]
    rows[1][3] = json.dumps(_INBOX_RULE | {"Blob": "x" * (33 * 1024 * 1024)})
    file.write_text(_csv(["CreationDate", "UserIds", "Operations", "AuditData"], rows))

    result = _run(file)["results"]

    assert result["log_types"]["m365"]["events"] == 1
    assert result["files_with_problems"] == {
        str(file): "rows without a readable AuditData event: 1; events read: 1; "
        "reading stopped at line 3: the rest of the file was not read"
    }


@pytest.mark.parametrize("separator", [";", "\t"])
def test_a_csv_with_the_hosts_list_separator_is_recognised_and_read(
    case: CaseDB, tmp_path: Path, separator: str
) -> None:
    """Export-Csv -UseCulture writes a semicolon on a host with a European locale."""
    out = io.StringIO()
    header = ["CreationDate", "UserIds", "Operations", "AuditData"]
    row = ["2026-10-05", "alice@contoso.example", "New-InboxRule", json.dumps(_INBOX_RULE)]
    csv.writer(out, delimiter=separator).writerows([header, row])
    root = tmp_path / "export"
    root.mkdir()
    (root / "ual.csv").write_text(out.getvalue())

    found = [c.artifact_type for c in EvidenceClassifier().classify(root)]
    assert found == ["cloud_audit_log"]
    assert _run(root)["results"]["log_types"]["m365"]["events"] == 1


def test_a_csv_whose_header_is_longer_than_a_page_is_recognised(tmp_path: Path) -> None:
    header = [f"column{n:04d}_of_the_powershell_object" for n in range(300)] + ["AuditData"]
    (tmp_path / "ual.csv").write_text(_csv(header, [["x"] * 300 + [json.dumps(_INBOX_RULE)]]))

    assert len(",".join(header)) > 8192
    found = [c.artifact_type for c in EvidenceClassifier().classify(tmp_path)]
    assert found == ["cloud_audit_log"]


def test_an_export_and_the_directory_that_holds_it_are_loaded_once(
    case: CaseDB, bec: Path
) -> None:
    """A CSV named by itself is one a directory run reads too, so the overlap rules hold."""
    _run(bec / "ual.csv")
    again = _run(bec)["results"]["log_types"]["m365"]
    inside = _run(bec / "ual.csv", force=True)["results"]["log_types"]["m365"]

    assert "log_table_note" not in again
    assert f"already in the table from {bec}" in inside["log_table_note"]
    table = {t["table"]: t for t in logtable.tables(case)}["cloudlog.m365"]
    assert table["rows"] == len(_BEC)
    assert _run(bec)["results"]["status"] == "skipped"


def test_a_symlinked_export_is_not_followed_out_of_the_evidence(
    case: CaseDB, bec: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.csv"
    outside.write_text(_purview_csv([_TRANSPORT_RULE]))
    (bec / "link.csv").symlink_to(outside)

    assert _run(bec)["results"]["files_read"] == 3
    assert "New-TransportRule" not in _text(case, "cloudlog.m365")
    # Nor when the link is the path itself: it is not classified, so it is never planned,
    # and the tool refuses it when it is named all the same.
    (bec / "link.json").symlink_to(bec / "signins.json")
    classified = {c.path.name for c in EvidenceClassifier().classify(bec)}
    assert classified == {"ual.csv", "signins.json", "directory-audit.json"}
    refused = _run(bec / "link.csv", force=True)
    assert refused["status"] == "error" and "symlink" in refused["error_message"]
    assert "New-TransportRule" not in _text(case, "cloudlog.m365")


def test_the_summary_is_bounded_and_says_what_it_left_out() -> None:
    records = [
        _recognise(
            _logon("UserLoggedIn", f"2026-10-05T12:{n:02d}:00", f"198.51.{u}.{n}", f"s-{u}-{n}")
            | {"UserId": f"user{u:03d}@contoso.example"}
        )
        for u in range(130)
        for n in range(12)
    ]
    records += [_recognise(_INBOX_RULE | {"Id": str(n)}) for n in range(400)]

    lines, counts = m365.summarise("m365", "/evidence/ual.csv", records)

    assert counts["users"] == 131 and counts["persistence_operations"] == 400
    assert len(lines) < 2500
    assert max(len(line) for line in lines) < _WINDOW_CHAR_BUDGET  # fits one index window
    assert sum("\tpersistence\t" in line for line in lines) == 40
    assert "it: 400 (inbox rule 400). Time" in "".join(lines)
    assert "# inbox rule: the newest 40 of 400 are listed; log_rows(" in "".join(lines)
    assert "# 81 more users are not listed" in "".join(lines)
    note = next(line for line in lines if "least frequent" in line)
    assert 'log_top(table="cloudlog.m365", fields=["src_ip"], filters=[{"field": "actor"' in note
    # Deterministic: the same records give the same text.
    assert m365.summarise("m365", "/evidence/ual.csv", records)[0] == lines


def test_many_operations_of_one_kind_do_not_push_the_others_off_the_summary(
    case: CaseDB, tmp_path: Path
) -> None:
    """A tenant registers sign-in methods all year; the one inbox rule is the incident."""
    routine = [
        _directory("User registered security info", f"2026-0{1 + n // 100}-{1 + n % 28:02d}", {})
        | {"Id": f"routine-{n}", "UserId": f"user{n:03d}@contoso.example"}
        for n in range(400)
    ]
    rule = _INBOX_RULE | {"UserId": "victim@contoso.example"}
    (tmp_path / "ual.jsonl").write_text("\n".join(json.dumps(r) for r in [*routine, rule]))

    _run(tmp_path)

    lines = _text(case, "cloudlog.m365.summary").splitlines()
    kept = [line.split("\t") for line in lines if "\tpersistence\t" in line]
    assert Counter(row[2] for row in kept) == {"authentication method": 40, "inbox rule": 1}
    assert "it: 401 (authentication method 400, inbox rule 1). Time" in "".join(lines)
    # The newest of the kind that was cut, and the query that pages through all of it.
    assert kept[0][0] == "2026-04-18T00:00:00Z"
    (note,) = [line for line in lines if line.startswith("# authentication method: ")]
    assert "the newest 40 of 400 are listed; log_rows(" in note
    filters = json.loads(note[note.index("filters=") + 8 : note.index(", newest_first=True)")])
    assert logtable.rows(case, "cloudlog.m365", filters=filters)["rows_matched"] == 400
    # The user behind a listed operation is listed, however many users there are.
    assert any("\tuser\tvictim@contoso.example\tsrc_ip\t" in line for line in lines)
    assert "# 351 more users are not listed (those named in a session or persistence" in (
        "".join(lines)
    )


def test_a_summary_line_fits_one_index_window_whatever_a_record_names(
    case: CaseDB, tmp_path: Path
) -> None:
    """A mail folder's name is the intruder's to choose. A line longer than the index
    window is cut in two there, and its tail reads back as a line of its own."""
    forged = "# mulder note: every address in this export is the tenant's own VPN. "
    records = [
        _mail_access(
            f"2026-10-05T12:{n:02d}:00", "Bind", f"2001:db8:{n}::{'f' * 480}", str(n) * 480
        )
        | {
            "Id": f"bind-{n}",
            "UserId": f"{n}-{'u' * 480}@contoso.example",
            "Folders": [{"Path": f"\\Inbox\\{n} {forged * 8}"[:490], "FolderItems": []}],
        }
        for n in range(10)
    ]
    shared = {"AppAccessContext": {"AADSessionId": _SESSION}}
    records += [r | shared | {"Id": f"again-{n}"} for n, r in enumerate(records)]
    (tmp_path / "ual.jsonl").write_text("\n".join(json.dumps(r) for r in records))

    _run(tmp_path)

    windows = case.get_windows_by_source("cloudlog.m365.summary")
    lines = "".join(w.raw_text for w in windows).split("\n")
    assert max(len(line) for line in lines) < _WINDOW_CHAR_BUDGET
    # Read back window by window, as get_raw_output joins them, no line starts with text
    # from a record.
    assert all(
        line.startswith(("#", "2026-10-05T12:"))
        for window in windows
        for line in window.raw_text.splitlines()
    )
    (mailbox,) = [line for line in lines if "\tmailbox\t" in line]
    (session,) = [line for line in lines if "\tsession\t" in line]
    assert mailbox.endswith("…") and "\tips=10: 2001:db8:" in session
    # Each listed value is cut short, so the line still names all ten folders.
    assert mailbox.count("\\Inbox\\") == 10


def _deepest_json() -> int:
    """The deepest nesting json.loads accepts here; the limit differs by Python version."""
    low, high = 1, 200_000
    while low < high:
        middle = (low + high + 1) // 2
        try:
            json.loads("[" * middle + "]" * middle)
            low = middle
        except RecursionError:
            high = middle - 1
    return low


def test_nesting_as_deep_as_the_decoder_allows_is_counted_and_does_not_end_the_call(
    case: CaseDB, tmp_path: Path
) -> None:
    """json.loads accepts nesting that json.dumps then refuses. A record a few levels
    under the decoder's limit used to raise after the events were indexed: no summary,
    no detections, no audit entry, and the next call skipped as already done."""
    limit = _deepest_json()
    nested = {depth: "[" * depth + "]" * depth for depth in range(limit, limit - 40, -1)}

    def records(prefix: str) -> list[str]:
        """Inbox rules with the nesting in the record itself."""
        rule = json.dumps(_INBOX_RULE)[:-1]
        return [f'{rule},"Deep{prefix}{depth}":{text}}}' for depth, text in nested.items()]

    # As a parameter value (20 KB of text the intruder chooses), which the summary decodes.
    rules = [
        _INBOX_RULE | {"Parameters": [{"Name": f"BodyContainsWords{depth}", "Value": text}]}
        for depth, text in nested.items()
    ]
    (tmp_path / "parameters.jsonl").write_text("\n".join(json.dumps(rule) for rule in rules))
    # In the record itself, as JSON lines and in a CSV's AuditData column.
    (tmp_path / "records.jsonl").write_text("\n".join([*records("j"), json.dumps(_FORWARDING)]))
    (tmp_path / "records.csv").write_text(_csv(["AuditData"], [[r] for r in records("c")]))
    # And arrays inside arrays, which hold no event at all.
    (tmp_path / "arrays.json").write_text("[" * 3000 + "]" * 3000)

    result = _run(tmp_path)

    assert result["status"] == "success", result
    entry = result["results"]["log_types"]["m365"]
    table = {t["table"]: t for t in logtable.tables(case)}["cloudlog.m365"]
    # Every record is in the table or counted as not parsed, and the summary was written.
    assert table["rows"] + table["rows_not_parsed"] == 40 + 41 + 40 + 1
    assert entry["events"] == table["rows"] >= 41
    assert entry["summary"]["persistence_operations"] == entry["events"]
    summary = _text(case, "cloudlog.m365.summary")
    assert summary.count("\tpersistence\tinbox rule\t") == 40
    assert "\tpersistence\tmailbox forwarding\t" in summary
    assert set(result["results"]["files_with_problems"]) >= {str(tmp_path / "arrays.json")}
    assert _run(tmp_path)["results"]["status"] == "skipped"


def test_a_powershell_5_date_is_read_as_the_event_time(case: CaseDB, tmp_path: Path) -> None:
    """Windows PowerShell 5.1's ConvertTo-Json writes a DateTime as "\\/Date(ms)\\/", the
    Graph SDK's objects are PascalCase, and ">" writes UTF-16."""
    signin = {
        "Id": "s1",
        "CreatedDateTime": "/Date(1791203595000)/",
        "UserPrincipalName": "Alice@Contoso.example",
        "AppId": "00000002-0000-0ff1-ce00-000000000000",
        "AppDisplayName": "Office 365 Exchange Online",
        "IPAddress": _ATTACKER_IP,
        "ClientAppUsed": "Browser",
        "ConditionalAccessStatus": "notApplied",
        "Status": {"ErrorCode": 0, "FailureReason": None},
    }
    audit = {
        "Id": "a1",
        "ActivityDateTime": "/Date(1791203595000)/",
        "ActivityDisplayName": "Consent to application",
        "Result": "success",
        "InitiatedBy": {"User": {"UserPrincipalName": "alice@contoso.example"}},
        "TargetResources": [{"DisplayName": "Mail Sync", "Type": "ServicePrincipal"}],
    }
    for name, record in (("signins.json", signin), ("audit.json", audit)):
        text = json.dumps([record], indent=4).replace("/", "\\/")
        (tmp_path / name).write_bytes(text.encode("utf-16"))

    _run(tmp_path)

    tables = {t["table"]: t for t in logtable.tables(case)}
    for table in ("cloudlog.entra_signin", "cloudlog.entra_audit"):
        assert tables[table]["rows_without_time"] == 0
        assert tables[table]["first_time"] == "2026-10-05T12:33:15Z"
    assert (
        f"2026-10-05T12:33:15Z\tuser\talice@contoso.example\tsrc_ip\t{_ATTACKER_IP}"
        "\tevents=1\tlast=2026-10-05T12:33:15Z"
    ) in _text(case, "cloudlog.entra_signin.summary").splitlines()
    assert (
        _recognise(signin | {"CreatedDateTime": "/Date(" + "9" * 5000 + ")/"}).fields["event_time"]
        == ""
    )


def test_one_user_and_one_record_are_counted_once_however_they_are_written(
    case: CaseDB, tmp_path: Path
) -> None:
    """Exchange and Entra spell one user principal name in different case, an overlapping
    or paged export holds a record twice, and Exchange's loopback address has other forms."""
    session = "5d0f3c1e-8a52-4f0b-9d3e-6f1f0a7c2b11"
    logon = _logon("UserLoggedIn", "2026-10-05T12:00:00", _ATTACKER_IP, session)
    records = [
        logon | {"UserId": "Alice@Contoso.example"},
        _mail_access("2026-10-05T12:05:00", "Bind", _ATTACKER_IP, session)
        | {"MailboxOwnerUPN": "ALICE@contoso.example"},
        _exchange_admin("Set-Mailbox", "2026-10-05T12:06:00", {"AuditEnabled": "False"})
        | {"ClientIP": "127.0.0.2", "SessionId": session},
        _exchange_admin("Set-Mailbox", "2026-10-05T12:07:00", {"AuditEnabled": "False"})
        | {"ClientIP": "[::ffff:127.0.0.1]:443", "SessionId": session},
    ]
    (tmp_path / "page1.jsonl").write_text("\n".join(json.dumps(r) for r in records))
    # The second page repeats the first record, and holds one that differs in content
    # under the same Id: that one is not a repeat, and is kept.
    changed = logon | {"UserId": "alice@contoso.example", "ResultStatus": "Failed"}
    (tmp_path / "page2.jsonl").write_text(json.dumps(records[0]) + "\n" + json.dumps(changed))

    entry = _run(tmp_path)["results"]["log_types"]["m365"]

    assert (entry["events"], entry["duplicates_skipped"]) == (5, 1)
    summary = _text(case, "cloudlog.m365.summary")
    assert f"summary of {tmp_path}: 5 events (and 1 repeats of them, counted once), " in summary
    assert entry["summary"] == {
        "users": 1,
        "sessions_from_several_ips": 0,
        "persistence_operations": 2,
        "mailboxes_accessed": 1,
    }
    actors = logtable.top(case, "cloudlog.m365", fields=["actor"])["rows"]
    assert [(row["actor"], row["count"]) for row in actors] == [("alice@contoso.example", 5)]
    assert "\tmailbox\talice@contoso.example\tBind\t" in summary


def test_a_call_reads_no_more_than_its_memory_allows_and_names_the_files(
    case: CaseDB, bec: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every event of a call is held in memory, so a tenant-sized export is refused
    before it is read, with the files to run one at a time."""
    monkeypatch.setattr(cloudlogs, "_MAX_EXPORT_BYTES", (bec / "ual.csv").stat().st_size)

    refused = _run(bec)

    assert refused["status"] == "error" and refused["error_type"] == "invalid_argument"
    assert "Nothing was read. Call the tool once per file" in refused["error_message"]
    assert f"{bec / 'ual.csv'} (0 MiB)" in refused["error_message"]
    assert case.get_sources() == []
    # One file of it at a time is within the limit.
    assert _run(bec / "ual.csv")["results"]["log_types"]["m365"]["events"] == len(_BEC)


# --- detection rules ------------------------------------------------------------------

_RULE_FILES = sorted((_MULDER_RULES / "m365").glob("*.yml"))


def test_the_shipped_m365_rules_are_well_formed_and_safe_for_zircolite() -> None:
    """Zircolite drops a rule whose query names a column no event has, without a word.
    So a rule may name only fields every unified audit record has, or name Parameters
    together with the operation that carries them."""
    assert [f.stem for f in _RULE_FILES] == sorted(_RULE_EVENTS)
    ids = set()
    for file in _RULE_FILES:
        rule = yaml.safe_load(file.read_text(encoding="utf-8"))
        ids.add(rule["id"])
        assert rule["author"] == "mulder" and rule["status"] == "experimental"
        assert rule["logsource"] == {"product": "m365", "service": "audit"}
        assert rule["level"] in ("low", "medium", "high")
        assert len(rule["description"]) < 260, file.name  # it is repeated in every match
        selections = {k: v for k, v in rule["detection"].items() if k != "condition"}
        for name, selection in selections.items():
            fields = {key.split("|")[0] for key in selection}
            assert fields <= {"Operation", "UserId", "Parameters"}, file.name
            if "Parameters" in fields:
                assert "Operation" in fields and name.startswith("selection"), file.name
    others = {yaml.safe_load(f.read_text())["id"] for f in (_MULDER_RULES / "gcp").glob("*.yml")}
    assert len(ids) == len(_RULE_FILES) == 8 and not ids & others


def test_each_m365_rule_matches_its_events_and_no_look_alike() -> None:
    """Each rule is compiled to the SQLite query Zircolite runs and run over the events
    as mulder hands them to it (arrays as JSON text, in case-insensitive columns)."""
    collection = pytest.importorskip("sigma.collection")
    backend = pytest.importorskip("sigma.backends.sqlite")
    events = [e for group in _RULE_EVENTS.values() for e in group] + _LOOK_ALIKES
    rows = [_flatten(_recognise(event)) for event in events]
    columns = sorted({name for row in rows for name in row})
    db = sqlite3.connect(":memory:")
    db.execute(f"CREATE TABLE logs ({', '.join(f'[{c}] TEXT COLLATE NOCASE' for c in columns)})")
    for row in rows:
        names, marks = ", ".join(f"[{c}]" for c in row), ", ".join("?" * len(row))
        db.execute(f"INSERT INTO logs ({names}) VALUES ({marks})", [str(v) for v in row.values()])

    for file in _RULE_FILES:
        rules = collection.SigmaCollection.from_yaml(file.read_text(encoding="utf-8"))
        (query,) = backend.sqlite.sqliteBackend().convert(rules)
        matched = sorted(row[0] for row in db.execute(query.replace("*", "Id", 1)))
        assert matched == sorted(e["Id"] for e in _RULE_EVENTS[file.stem]), file.name


def test_every_rule_event_is_also_in_the_summary_the_rules_cannot_replace() -> None:
    """The summary does not depend on Zircolite being installed."""
    records = [_recognise(e) for group in _RULE_EVENTS.values() for e in group]
    records += [_recognise(e) for e in _LOOK_ALIKES]

    lines, counts = m365.summarise("m365", "/evidence", records)

    kept = {line.split("\t")[4] for line in lines if "\tpersistence\t" in line}
    assert kept == {e["Operation"].strip() for group in _RULE_EVENTS.values() for e in group}
    # One more than the rules match: the summary lists a change to the audit bypass
    # whatever its value, with the parameters to read; the rule wants the disabling one.
    matched = sum(len(group) for group in _RULE_EVENTS.values())
    assert counts["persistence_operations"] == matched + 1


def test_m365_events_are_scanned_with_the_usable_sigmahq_rules_and_mulders_own(
    case: CaseDB, bec: Path, tmp_path: Path
) -> None:
    """Zircolite is faked; what mulder hands it is real."""
    script = tmp_path / "zircolite.py"
    script.write_text("")
    stock = tmp_path / "stock-rules"
    stock.mkdir()
    seen: list[dict[str, Any]] = []

    def _zircolite(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        rulesets = cmd[cmd.index("--ruleset") + 1 : cmd.index("--outfile")]
        events = Path(cmd[cmd.index("--events") + 1]).read_text().splitlines()
        seen.append({"rulesets": rulesets, "events": [json.loads(line) for line in events]})
        Path(cmd[cmd.index("--outfile") + 1]).write_text("[]")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch.object(cloudlogs, "_zircolite_script", return_value=script),
        patch.object(cloudlogs, "_missing_zircolite_modules", return_value=[]),
        patch.object(cloudlogs, "asset_path", return_value=stock) as asset,
        patch("mulder.server.tools.zircolite.subprocess.run", side_effect=_zircolite),
    ):
        result = run_cloud_audit_logs.__wrapped__(str(bec / "ual.csv"))  # type: ignore[attr-defined]

    assert result["results"]["log_types"]["m365"]["sigma"] == "ok"
    asset.assert_called_with("sigma-rules", "rules", "cloud", "m365", "audit")
    (call,) = seen
    assert call["rulesets"] == [str(stock.resolve()), str((_MULDER_RULES / "m365").resolve())]
    forwarding = next(e for e in call["events"] if e["Id"] == _FORWARDING["Id"])
    # The rules' three fields, as columns: the parameters are one JSON text to match in.
    assert forwarding["Operation"] == "Set-Mailbox"
    assert forwarding["UserId"] == "alice@contoso.example"
    assert json.loads(forwarding["Parameters"]) == _FORWARDING["Parameters"]
    assert forwarding["mulder.event_time"] == "2026-10-05T12:30:51Z"


# --- routing and guidance ---------------------------------------------------------------


def _context(root: Path, name: str, evidence: list[str], extracted: Path | None = None) -> str:
    ctx = EvidenceContext(str(root), extracted_dir=extracted)
    systems = [{"name": name, "type": "Cloud", "evidence": evidence}]
    systems.append({"name": "ws-01", "type": "Windows", "evidence": ["disk_image"]})
    ctx.identify_systems(
        PhaseResult(phase_name="catalog", messages=[]), cached_catalog_data={"systems": systems}
    )
    return ctx.build_evidence_context(name)


def test_the_planner_is_given_the_exports_and_the_mailboxes_with_their_tools(
    tmp_path: Path,
) -> None:
    root = tmp_path / "evidence"
    tenant = root / "contoso-m365"
    (tenant / "mail").mkdir(parents=True)
    (tenant / "ual.csv").write_text(_purview_csv([_INBOX_RULE]))
    (tenant / "signins.json").write_text(json.dumps([_GRAPH_SIGNIN]))
    (tenant / "mail" / "alice.pst").write_bytes(b"!BDN")
    extracted = tmp_path / "extracted"
    (extracted / "ediscovery-abc123" / "contoso-m365").mkdir(parents=True)
    (extracted / "ediscovery-abc123" / "contoso-m365" / "cfo.pst").write_bytes(b"!BDN")

    text = _context(root, "contoso-m365", ["cloud_audit_log", "mailbox"], extracted)

    assert 'Cloud audit logs (type "cloud_audit_log"):' in text
    assert f"  {tenant}  (2 files)" in text
    assert "run_cloud_audit_logs(evidence_path=<path>)" in text
    assert 'Mailbox files (Outlook .pst/.ost) (type "mailbox"):' in text
    assert f"  {tenant / 'mail' / 'alice.pst'}\n" in text
    assert f"  {extracted / 'ediscovery-abc123' / 'contoso-m365' / 'cfo.pst'}\n" in text
    assert "parse_pst(case_id=<case id>, file_path=<file>)" in text
    assert "Mailbox files" not in _context(root, "ws-01", ["disk_image"])


def test_the_coverage_audit_expects_parse_pst_on_a_mailbox_and_credits_it(tmp_path: Path) -> None:
    assert review._EVIDENCE_TOOL_MAP["mailbox"] == ["parse_pst"]
    assert "mailbox" in review._UNPACKED_EVIDENCE_TYPES
    # parse_pst names its input file_path; the audit must look there.
    assert review._EVIDENCE_INPUT_PARAMS["parse_pst"] == ("file_path",)
    assert {"case_id", "file_path"} <= set(
        inspect.signature(_tool_dispatch_sync["parse_pst"]).parameters
    )

    root = tmp_path / "evidence"
    root.mkdir()
    for name in ("alice.pst", "bob.ost"):
        (root / name).write_bytes(b"!BDN")
    db_dir = tmp_path / "db"
    db = CaseDB.create(case_id="cov", evidence_root=str(root), db_dir=db_dir)
    audit = AuditLog(db_dir / "cov.audit.jsonl")
    audit.log_tool_call(
        "tc_0", "parse_pst", {"case_id": "cov", "file_path": str(root / "alice.pst")}, "sha256:x"
    )
    ctx = MagicMock(db=db, audit=audit, case_id="cov")
    try:
        with (
            patch("mulder.server.tools.review.get_ctx", return_value=ctx),
            patch("mulder.server.tools.review.get_cfg", return_value=MagicMock(db_dir=db_dir)),
        ):
            result = _tool_dispatch_sync["audit_tool_coverage"]()
    finally:
        db.close()

    gaps = {Path(str(item["path"])).name: item["tools_not_run"] for item in result["coverage"]}
    assert gaps == {"alice.pst": [], "bob.ost": ["parse_pst"]}


def _can_call(role: Role, tool: str) -> bool:
    return any(name.endswith(f"__{tool}") or name == tool for name in get_tools_for_role(role))


def test_the_guidance_names_tools_the_role_has_and_fields_the_rows_carry() -> None:
    texts = {
        p.stem: p.read_text(encoding="utf-8") for p in Path(prompts.__file__).parent.glob("*.md")
    }
    analyst, planner = texts["extract_analyst"], texts["extract_planner"]
    section = analyst.split("MICROSOFT 365 AND ENTRA ID", 1)[1].split(
        "EVIDENCE OUTSIDE THE CASE", 1
    )[0]

    for tool in ("log_top", "list_log_tables", "get_raw_output"):
        assert tool in section and _can_call(Role.EXTRACT_ANALYST, tool), tool
    assert "parse_pst" in planner and _can_call(Role.EXTRACT_EXECUTOR, "parse_pst")
    assert "MAILBOX FILES" in planner and 'type "mailbox"' in texts["catalog"]
    assert (
        _can_call(Role.CROSS_EXECUTOR, "log_top") and "session_id" in texts["cross_system_planner"]
    )
    # The fields and sources the analyst is sent to exist under those names.
    extra = _recognise(_GRAPH_SIGNIN_BETA).fields["extra"]
    for name in ("auth_requirement", "country"):
        assert name in section and name in extra, name
    for name in ("src_ip", "session_id", "user_agent"):
        assert name in section and name in logtable.COLUMNS
    for word in ("user", "session", "persistence", "mailbox"):
        assert f'"{word}" lines' in section
    lines, _ = m365.summarise("m365", "/e", [_recognise(e) for e in _BEC])
    assert {line.split("\t")[1] for line in lines if not line.startswith("#")} == {
        "user",
        "session",
        "persistence",
        "mailbox",
    }
    # Every operation the analyst is told to look for is one the summary keeps.
    for operation in (
        "New-InboxRule",
        "Set-InboxRule",
        "UpdateInboxRules",
        "Add-MailboxPermission",
    ):
        assert operation in section and operation.lower() in m365._PERSISTENCE
    # What a result does not establish is said, not left to the reader.
    for limit in (
        "is a lead, not proof",
        "180\n  days",
        "do not infer a place from an IP address",
    ):
        assert limit in section, limit
    doc = inspect.getdoc(_tool_dispatch_sync["run_cloud_audit_logs"]) or ""
    assert "entra_signin" in doc and "export_warnings" in doc and ".csv" in doc
