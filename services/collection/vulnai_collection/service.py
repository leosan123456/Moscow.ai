"""`CollectionService`: orquestração da etapa `03_collection_enrichment`.

Fingerprint (nuclei) e verificação de imagem de contêiner (trivy) tocam infraestrutura do
cliente, então passam por `ScopeGuard` como qualquer outra ação. A correlação com CVE/NVD
e CISA KEV roda depois, sobre dado já coletado — essas duas fontes são catálogos públicos,
não ativos do cliente, então não passam pelo gate.
"""

from __future__ import annotations

from vulnai_shared.clock import Clock, utcnow
from vulnai_shared.enums import ActionClass, Confidence, FindingStatus, Severity
from vulnai_shared.models import Finding, Vulnerability
from vulnai_authorization import ScopeGuard
from vulnai_collection.errors import ParseError
from vulnai_collection.kev import KevCatalog, StaticKevCatalog
from vulnai_collection.nuclei import NucleiMatch
from vulnai_collection.nuclei import build_command as build_nuclei_command
from vulnai_collection.nuclei import parse_jsonl as parse_nuclei_jsonl
from vulnai_collection.nvd import CveRecord, NvdClient, StaticNvdCatalog
from vulnai_collection.repository import (
    FindingRepository,
    InMemoryFindingRepository,
    InMemoryVulnerabilityRepository,
    VulnerabilityRepository,
)
from vulnai_collection.runner import ToolRunner
from vulnai_collection.severity import from_cvss
from vulnai_collection.severity import normalize as normalize_severity
from vulnai_collection.trivy import TrivyVulnerability
from vulnai_collection.trivy import build_command as build_trivy_command
from vulnai_collection.trivy import parse_json as parse_trivy_json


class CollectionService:
    def __init__(
        self,
        *,
        guard: ScopeGuard,
        runner: ToolRunner,
        client_id: str,
        engagement_id: str,
        findings: FindingRepository | None = None,
        vulnerabilities: VulnerabilityRepository | None = None,
        nvd: NvdClient | None = None,
        kev: KevCatalog | None = None,
        clock: Clock = utcnow,
    ) -> None:
        self._guard = guard
        self._runner = runner
        self._client_id = client_id
        self._engagement_id = engagement_id
        self._findings = findings or InMemoryFindingRepository()
        self._vulnerabilities = vulnerabilities or InMemoryVulnerabilityRepository()
        self._nvd = nvd or StaticNvdCatalog()
        self._kev = kev or StaticKevCatalog()
        self._clock = clock

    # -------------------------------------------------------------- fingerprint
    def fingerprint_scan(
        self,
        raw_target: str,
        *,
        asset_id: str,
        service_id: str | None = None,
        tags: str | None = None,
        tool: str = "nuclei",
    ) -> list[Finding]:
        """Roda templates de detecção não destrutiva contra um alvo e grava os achados."""
        kwargs = {"tags": tags} if tags is not None else {}
        with self._guard.touch(raw_target, ActionClass.ACTIVE_NON_INTRUSIVE, tool=tool) as target:
            command = build_nuclei_command(target.value, **kwargs)
            result = self._runner.run(command, timeout=180.0)

        if not result.ok and not result.stdout.strip():
            raise ParseError(f"{tool} terminou com código {result.returncode}: {result.stderr[:500]}")

        matches = parse_nuclei_jsonl(result.stdout)
        return [
            self._save_from_nuclei(match, asset_id=asset_id, service_id=service_id, tool=tool)
            for match in matches
        ]

    def _save_from_nuclei(
        self, match: NucleiMatch, *, asset_id: str, service_id: str | None, tool: str
    ) -> Finding:
        vulnerability_id = None
        severity = normalize_severity(match.severity)
        if match.cve_ids:
            vulnerability = self._enrich_cve(match.cve_ids[0])
            vulnerability_id = vulnerability.id
            if severity is Severity.NONE and vulnerability.cvss_score is not None:
                severity = from_cvss(vulnerability.cvss_score)

        candidate = Finding(
            client_id=self._client_id,
            engagement_id=self._engagement_id,
            asset_id=asset_id,
            service_id=service_id,
            vulnerability_id=vulnerability_id,
            title=match.name,
            description=match.description,
            severity=severity,
            # Template deu match — é mais que uma suspeita estatística, mas ainda não
            # passou por confirmação/triagem. A redução de FP fica para o núcleo de IA (M2/M3).
            confidence=Confidence.FIRM,
            status=FindingStatus.NEW,
            evidence=f"nuclei template={match.template_id} matched_at={match.matched_at}",
            source_tool=tool,
        )
        return self._findings.upsert(candidate)

    # -------------------------------------------------------- imagem de contêiner
    def scan_container_image(
        self, image_ref: str, *, asset_id: str, tool: str = "trivy"
    ) -> list[Finding]:
        """Verifica uma imagem de contêiner. Puxar a imagem já é ler infraestrutura do
        cliente, então o host do registro precisa estar no escopo contratado."""
        registry_host = image_ref.split("/", 1)[0] if "/" in image_ref else image_ref
        with self._guard.touch(registry_host, ActionClass.PASSIVE, tool=tool):
            command = build_trivy_command(image_ref)
            result = self._runner.run(command, timeout=300.0)

        if not result.ok:
            raise ParseError(f"{tool} terminou com código {result.returncode}: {result.stderr[:500]}")

        vulnerabilities = parse_trivy_json(result.stdout)
        return [
            self._save_from_trivy(vuln, asset_id=asset_id, tool=tool) for vuln in vulnerabilities
        ]

    def _save_from_trivy(self, vuln: TrivyVulnerability, *, asset_id: str, tool: str) -> Finding:
        vulnerability = self._enrich_cve(vuln.cve_id)
        severity = normalize_severity(vuln.severity)
        if severity is Severity.NONE and vulnerability.cvss_score is not None:
            severity = from_cvss(vulnerability.cvss_score)

        description = f"pacote {vuln.pkg_name} {vuln.installed_version}"
        if vuln.fixed_version:
            description += f", corrigido em {vuln.fixed_version}"

        candidate = Finding(
            client_id=self._client_id,
            engagement_id=self._engagement_id,
            asset_id=asset_id,
            vulnerability_id=vulnerability.id,
            title=vuln.title or f"{vuln.cve_id} em {vuln.pkg_name}",
            description=description,
            severity=severity,
            confidence=Confidence.FIRM,
            status=FindingStatus.NEW,
            evidence=(
                f"trivy target={vuln.target} pkg={vuln.pkg_name}@{vuln.installed_version} "
                f"cve={vuln.cve_id}"
            ),
            source_tool=tool,
        )
        return self._findings.upsert(candidate)

    # ------------------------------------------------------------- enriquecimento
    def _enrich_cve(self, cve_id: str) -> Vulnerability:
        """Correlaciona com NVD e CISA KEV, cacheando no catálogo compartilhado.

        Um CVE que a API do NVD não conhece (ainda não publicado, id inventado por
        template malformado) ainda vira registro — com o que se sabe (o próprio id e o
        veredito do KEV) — para que o achado não fique sem `vulnerability_id`.
        """
        existing = self._vulnerabilities.get_by_cve(cve_id)
        record: CveRecord | None = self._nvd.get(cve_id)

        candidate = Vulnerability(
            cve_id=cve_id,
            title=record.title if record else (existing.title if existing else cve_id),
            description=record.description if record else (existing.description if existing else None),
            cvss_vector=record.cvss_vector if record else (existing.cvss_vector if existing else None),
            cvss_score=record.cvss_score if record else (existing.cvss_score if existing else None),
            in_cisa_kev=self._kev.contains(cve_id),
            references=record.references if record else (existing.references if existing else ()),
            published_at=record.published_at if record else (existing.published_at if existing else None),
        )
        return self._vulnerabilities.upsert(candidate)

    # --------------------------------------------------------------------- consulta
    def findings(self) -> list[Finding]:
        return self._findings.list_for_engagement(self._client_id, self._engagement_id)
