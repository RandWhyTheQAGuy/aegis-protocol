"""
aegis_cli.main
~~~~~~~~~~~~~~
Command-line interface for Semantic Passport management.

Usage:
    aegis passport issue    --model-id <id> --model-version <ver>
                            --registry-key <key> --registry-version <ver>
                            [--ttl 86400] [--output passport.json]

    aegis passport verify   --passport passport.json
                            --registry-key <key> --registry-version <ver>

    aegis passport rotate   --passport passport.json
                            --incident-id <id>
                            --registry-key <key> --registry-version <ver>
                            [--output recovered.json]

    aegis vault verify      --vault vault.jsonl
    aegis vault export      --vault vault.jsonl [--format json|csv|nist]
                            [--output report.json]
    aegis vault search      --vault vault.jsonl --session-id <id>
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def _require_click():
    try:
        import click
        return click
    except ImportError:
        print("click is required. Install with: pip install aegis-protocol[cli]",
              file=sys.stderr)
        sys.exit(1)


def _require_aegis():
    try:
        import aegis
        return aegis
    except ImportError:
        print("aegis-protocol is required. Install with: pip install aegis-protocol",
              file=sys.stderr)
        sys.exit(1)


def main():
    click = _require_click()
    aegis = _require_aegis()

    @click.group()
    @click.version_option(package_name="aegis-protocol")
    def cli():
        """Aegis Protocol CLI — Semantic Passport and Audit Vault management."""

    # -----------------------------------------------------------------------
    # aegis passport
    # -----------------------------------------------------------------------

    @cli.group()
    def passport():
        """Semantic Passport management."""

    @passport.command("issue")
    @click.option("--model-id",          required=True, help="Agent model identifier.")
    @click.option("--model-version",     required=True, help="Agent version (semver or hash).")
    @click.option("--registry-key",      required=True, envvar="AEGIS_REGISTRY_KEY",
                  help="Registry HMAC key. Can also be set via AEGIS_REGISTRY_KEY env var.")
    @click.option("--registry-version",  required=True, envvar="AEGIS_REGISTRY_VERSION",
                  help="Registry version (semver). Can also be set via AEGIS_REGISTRY_VERSION.")
    @click.option("--policy-hash",       default=None,
                  help="SHA-256 of policy rule set. Auto-computed from defaults if omitted.")
    @click.option("--ttl",               default=86400, show_default=True,
                  help="Passport validity in seconds.")
    @click.option("--all-capabilities",  is_flag=True, default=True,
                  help="Enable all capabilities (default: True).")
    @click.option("--output", "-o",      default=None,
                  help="Output file path. Prints to stdout if omitted.")
    def issue(model_id, model_version, registry_key, registry_version,
              policy_hash, ttl, all_capabilities, output):
        """Issue a new Semantic Passport."""
        registry = aegis.PassportRegistry(registry_key, registry_version)
        caps     = aegis.Capabilities.full() if all_capabilities else aegis.Capabilities()

        if policy_hash is None:
            policy_hash = aegis.sha256_hex("aegis-default-policy-v0.1")

        passport = registry.issue(
            model_id, model_version, caps, policy_hash,
            now=int(time.time()), ttl_seconds=ttl,
        )

        data = json.dumps(passport.to_dict(), indent=2)

        if output:
            Path(output).write_text(data)
            click.echo(f"✓ Passport issued and saved to {output}")
            click.echo(f"  model_id:   {passport.model_id}")
            click.echo(f"  expires_at: {passport.expires_at}")
        else:
            click.echo(data)

    @passport.command("verify")
    @click.option("--passport",          required=True, type=click.Path(exists=True),
                  help="Path to passport JSON file.")
    @click.option("--registry-key",      required=True, envvar="AEGIS_REGISTRY_KEY")
    @click.option("--registry-version",  required=True, envvar="AEGIS_REGISTRY_VERSION")
    def verify(passport, registry_key, registry_version):
        """Verify a Semantic Passport's signature and expiry."""
        from aegis.passport import SemanticPassport
        from aegis.exceptions import PassportExpiredError, PassportSignatureError, \
            PassportRegistryMismatchError

        data = json.loads(Path(passport).read_text())
        p    = SemanticPassport.from_dict(data)
        reg  = aegis.PassportRegistry(registry_key, registry_version)
        now  = int(time.time())

        try:
            reg.verify(p, now=now)
            click.echo(f"✓ Passport valid")
            click.echo(f"  model_id:         {p.model_id}")
            click.echo(f"  registry_version: {p.registry_version}")
            click.echo(f"  expires_at:       {p.expires_at}")
            click.echo(f"  recovered:        {p.is_recovered()}")
            sys.exit(0)
        except PassportExpiredError as e:
            click.echo(f"✗ Passport EXPIRED (expired {e.expired_at}, now {e.now})",
                       err=True)
            sys.exit(1)
        except PassportSignatureError:
            click.echo(f"✗ Passport SIGNATURE INVALID — possible tampering", err=True)
            sys.exit(1)
        except PassportRegistryMismatchError as e:
            click.echo(
                f"✗ Registry version mismatch: "
                f"passport={e.passport_version}, local={e.local_version}",
                err=True,
            )
            sys.exit(1)

    @passport.command("rotate")
    @click.option("--passport",          required=True, type=click.Path(exists=True),
                  help="Path to existing passport JSON file.")
    @click.option("--incident-id",       required=True,
                  help="Incident ID from the resolved Entropy Flush.")
    @click.option("--registry-key",      required=True, envvar="AEGIS_REGISTRY_KEY")
    @click.option("--registry-version",  required=True, envvar="AEGIS_REGISTRY_VERSION")
    @click.option("--ttl",               default=3600, show_default=True,
                  help="Recovery passport validity in seconds (default: 1 hour).")
    @click.option("--output", "-o",      default=None,
                  help="Output file path. Prints to stdout if omitted.")
    def rotate(passport, incident_id, registry_key, registry_version, ttl, output):
        """Issue a recovery passport after an Entropy Flush incident."""
        from aegis.passport import SemanticPassport

        data = json.loads(Path(passport).read_text())
        p    = SemanticPassport.from_dict(data)
        reg  = aegis.PassportRegistry(registry_key, registry_version)
        now  = int(time.time())

        recovered = reg.issue_recovery_token(p, incident_id, now=now, ttl_seconds=ttl)
        result    = json.dumps(recovered.to_dict(), indent=2)

        if output:
            Path(output).write_text(result)
            click.echo(f"✓ Recovery passport issued and saved to {output}")
            click.echo(f"  recovery_token: {recovered.recovery_token}")
            click.echo(f"  expires_at:     {recovered.expires_at}")
        else:
            click.echo(result)

    # -----------------------------------------------------------------------
    # aegis vault
    # -----------------------------------------------------------------------

    @cli.group()
    def vault():
        """Cold Audit Vault management."""

    @vault.command("verify")
    @click.option("--vault", "-v",  required=True, type=click.Path(exists=True),
                  help="Path to vault JSONL file.")
    def vault_verify(vault):
        """Verify the cryptographic integrity of a vault chain."""
        from aegis.exceptions import VaultChainIntegrityError

        data   = Path(vault).read_text()
        v      = aegis.ColdAuditVault.from_jsonl(data, verify=False)

        try:
            v.verify_chain()
            click.echo(f"✓ Vault chain VALID ({len(v)} entries)")
            sys.exit(0)
        except VaultChainIntegrityError as e:
            click.echo(f"✗ Vault chain INTEGRITY FAILURE at sequence {e.sequence}: {e.detail}",
                       err=True)
            sys.exit(1)

    @vault.command("export")
    @click.option("--vault", "-v",   required=True, type=click.Path(exists=True),
                  help="Path to vault JSONL file.")
    @click.option("--format", "-f",  "fmt",
                  type=click.Choice(["json", "csv", "nist"]), default="json",
                  show_default=True, help="Output format.")
    @click.option("--output", "-o",  default=None,
                  help="Output file. Prints to stdout if omitted.")
    @click.option("--session-id",    default=None,
                  help="Filter entries by session ID.")
    @click.option("--event-type",    default=None,
                  help="Filter entries by event type.")
    def vault_export(vault, fmt, output, session_id, event_type):
        """Export vault entries for compliance reporting."""
        data = Path(vault).read_text()
        v    = aegis.ColdAuditVault.from_jsonl(data, verify=True)

        entries = list(v)
        if session_id:
            entries = [e for e in entries if e.session_id == session_id]
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]

        if fmt == "json":
            result = json.dumps([e.to_dict() for e in entries], indent=2)

        elif fmt == "csv":
            import csv, io
            buf = io.StringIO()
            fields = ["sequence", "timestamp", "event_type", "session_id",
                      "agent_id", "payload_hash", "entry_hash"]
            writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for e in entries:
                writer.writerow({f: getattr(e, f) for f in fields})
            result = buf.getvalue()

        elif fmt == "nist":
            # NIST AI RMF measurement function format
            result = json.dumps({
                "standard":    "NIST AI RMF",
                "measure":     "AI-1.4 — Audit and Accountability",
                "generated_at": int(time.time()),
                "entry_count":  len(entries),
                "chain_valid":  v.is_valid(),
                "events_by_type": {
                    et: len([e for e in entries if e.event_type == et])
                    for et in aegis.VALID_EVENT_TYPES
                },
                "entries": [e.to_dict() for e in entries],
            }, indent=2)

        if output:
            Path(output).write_text(result)
            click.echo(f"✓ Exported {len(entries)} entries to {output} ({fmt})")
        else:
            click.echo(result)

    @vault.command("search")
    @click.option("--vault", "-v",   required=True, type=click.Path(exists=True))
    @click.option("--session-id",    default=None)
    @click.option("--agent-id",      default=None)
    @click.option("--event-type",    default=None)
    @click.option("--payload-hash",  default=None)
    def vault_search(vault, session_id, agent_id, event_type, payload_hash):
        """Search vault entries by field."""
        data    = Path(vault).read_text()
        v       = aegis.ColdAuditVault.from_jsonl(data, verify=False)
        entries = list(v)

        if session_id:
            entries = [e for e in entries if e.session_id == session_id]
        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        if payload_hash:
            entries = [e for e in entries if e.payload_hash == payload_hash]

        click.echo(f"Found {len(entries)} entries:")
        for e in entries:
            click.echo(
                f"  [{e.sequence}] {e.event_type:20s} "
                f"agent={e.agent_id:20s} "
                f"session={e.session_id[:12]}..."
            )

    cli()


if __name__ == "__main__":
    main()
