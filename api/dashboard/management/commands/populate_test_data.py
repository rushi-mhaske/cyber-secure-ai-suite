import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import (
    BehaviorEvent,
    DocumentAnalysis,
    MalwareScan,
    ModuleType,
    PhishingScan,
    RiskLevel,
    SecurityAlert,
)
from dashboard.services import behavior as behavior_service
from dashboard.services import phishing as phishing_service

User = get_user_model()


class Command(BaseCommand):
    help = 'Populate cybersecurity dashboard with representative sample data'

    def add_arguments(self, parser):
        parser.add_argument('--phishing', type=int, default=120, help='Number of phishing scans to create')
        parser.add_argument('--documents', type=int, default=45, help='Number of document analyses to create')
        parser.add_argument('--behavior-events', type=int, default=180, help='Number of behavior events to create')
        parser.add_argument('--malware', type=int, default=60, help='Number of malware scans to create')
        parser.add_argument('--alerts', type=int, default=80, help='Number of alerts to create')

    def handle(self, *args, **options):
        phishing_count = options['phishing']
        document_count = options['documents']
        behavior_count = options['behavior_events']
        malware_count = options['malware']
        alerts_count = options['alerts']

        self.stdout.write(self.style.SUCCESS('Preparing cyber telemetry sample data...'))

        # Ensure baseline admin user exists
        admin_user, created = User.objects.get_or_create(
            email='superadmin@yopmail.com',
            defaults={
                'first_name': 'Super',
                'last_name': 'Admin',
                'is_staff': True,
                'is_superuser': True,
            },
        )
        if created:
            admin_user.set_password('test@123')
            admin_user.save()
            self.stdout.write(self.style.SUCCESS(f'Created admin user: {admin_user.email}'))

        self._create_phishing_scans(phishing_count, admin_user)
        self._create_document_analyses(document_count, admin_user)
        self._create_behavior_events(behavior_count)
        self._create_malware_scans(malware_count, admin_user)
        self._create_security_alerts(alerts_count, admin_user)

        self.stdout.write(self.style.SUCCESS('\n=== Population Summary ==='))
        self.stdout.write(f'Phishing Scans: {PhishingScan.objects.count()}')
        self.stdout.write(f'Document Analyses: {DocumentAnalysis.objects.count()}')
        self.stdout.write(f'Behavior Events: {BehaviorEvent.objects.count()}')
        self.stdout.write(f'Malware Scans: {MalwareScan.objects.count()}')
        self.stdout.write(f'Security Alerts: {SecurityAlert.objects.count()}')
        self.stdout.write(self.style.SUCCESS('=== Done ==='))

    # ------------------------------------------------------------------ #
    # Generators
    # ------------------------------------------------------------------ #

    def _create_phishing_scans(self, count: int, user):
        domains = [
            'secure-paypal.com',
            'login-verification.net',
            '0ffice365-support.com',
            'update-your-account.info',
            'safe-bank.co',
            'apple.id-reset.net',
            'zoom-video.app',
            'microsoftsupport.live',
            'vpn-security-alert.com',
        ]
        templates = [
            'Urgent: Your account will be suspended within 24 hours unless you verify your information immediately.',
            'Security notice: multiple login attempts detected. Reset your password to continue.',
            'Invoice overdue. Please download the attached PDF to avoid service interruption.',
            'We detected unusual activity from a new device. Confirm the activity within the next 15 minutes.',
            'Your payment could not be processed. Update billing information here.',
        ]

        PhishingScan.objects.all().delete()

        for _ in range(count):
            domain = random.choice(domains)
            target_url = f"https://{domain}/{random.randint(100, 9999)}"
            raw_content = random.choice(templates)
            risk_score = max(0, min(100, random.gauss(55, 20)))
            risk_level = phishing_service.calculate_risk_level(risk_score)

            PhishingScan.objects.create(
                user=user,
                input_type=random.choice(list(PhishingScan.InputType.values)),
                target_url=target_url,
                raw_content=raw_content,
                reputation_score=max(0, 100 - risk_score),
                risk_score=risk_score,
                risk_level=risk_level,
                detections={
                    'domain': {'domain': domain, 'risk': risk_score / 2, 'reasons': ['Synthetic domain in high-risk TLD']},
                    'content': {'risk': risk_score / 3, 'findings': ['Contains urgency keywords', 'Links to credential harvest']} ,
                },
                recommendations=['Quarantine message', 'Add domain to watch list'],
                metadata={'domain': domain},
                created_at=timezone.now() - timedelta(hours=random.randint(0, 240)),
            )

        self.stdout.write(self.style.SUCCESS(f'Created {count} phishing scans'))

    def _create_document_analyses(self, count: int, user):
        DocumentAnalysis.objects.all().delete()

        for idx in range(count):
            verdict = random.choices(
                population=list(DocumentAnalysis.Verdict.values),
                weights=[0.55, 0.25, 0.20],
            )[0]
            risk_level = {
                DocumentAnalysis.Verdict.AUTHENTIC: RiskLevel.LOW,
                DocumentAnalysis.Verdict.SUSPICIOUS: RiskLevel.MEDIUM,
                DocumentAnalysis.Verdict.FORGED: RiskLevel.HIGH,
            }[verdict]

            DocumentAnalysis.objects.create(
                user=user,
                uploaded_file=f"documents/sample_{idx}.pdf",
                file_name=f"Vendor-Contract-{idx}.pdf",
                file_type='application/pdf',
                file_size=random.randint(120_000, 2_000_000),
                sha256=f"{random.getrandbits(128):032x}",
                ela_score=max(0, min(100, random.gauss(35 if verdict != 'authentic' else 15, 12))),
                text_confidence=max(0, min(100, random.gauss(80, 10))),
                semantic_score=max(0, min(100, random.gauss(60 if verdict == 'forged' else 30, 15))),
                verdict=verdict,
                risk_level=risk_level,
                findings={
                    'ocr': f"OCR extracted {random.randint(120, 1200)} tokens",
                    'semantic': ['Mismatch in totals', 'Different fonts detected'] if verdict != 'authentic' else [],
                },
                ocr_text='Lorem ipsum dolor sit amet...' if verdict != 'authentic' else '',
                created_at=timezone.now() - timedelta(hours=random.randint(0, 240)),
            )

        self.stdout.write(self.style.SUCCESS(f'Created {count} document analyses'))

    def _create_behavior_events(self, count: int):
        BehaviorEvent.objects.all().delete()
        actors = ['alice@corp.com', 'bob@corp.com', 'charlie@corp.com', 'dana@corp.com']
        locations = ['New York, US', 'London, UK', 'Singapore', 'Sydney, AU', 'Berlin, DE']
        devices = ['MacOS Chrome', 'Windows Edge', 'iOS Safari', 'Android Chrome', 'Linux Firefox']

        for _ in range(count):
            actor = random.choice(actors)
            occurred_at = timezone.now() - timedelta(hours=random.randint(0, 240))
            event = BehaviorEvent.objects.create(
                actor_identifier=actor,
                event_type=random.choice(list(BehaviorEvent.EventType.values)),
                occurred_at=occurred_at,
                location=random.choice(locations),
                device=random.choice(devices),
                metadata={'ip': f"192.0.2.{random.randint(1, 250)}", 'resource': random.choice(['/finance', '/hr', '/r&d'])},
            )
            behavior_service.detect_and_update(event)

        self.stdout.write(self.style.SUCCESS(f'Created {count} behavior events'))

    def _create_malware_scans(self, count: int, user):
        MalwareScan.objects.all().delete()
        verdict_choices = list(MalwareScan.Verdict.values)

        for idx in range(count):
            verdict = random.choices(verdict_choices, weights=[0.55, 0.2, 0.2, 0.05])[0]
            risk_level = {
                MalwareScan.Verdict.CLEAN: RiskLevel.LOW,
                MalwareScan.Verdict.SUSPICIOUS: RiskLevel.MEDIUM,
                MalwareScan.Verdict.MALICIOUS: RiskLevel.HIGH,
                MalwareScan.Verdict.QUARANTINED: RiskLevel.CRITICAL,
            }[verdict]
            scan = MalwareScan.objects.create(
                user=user,
                uploaded_file=f"malware/payload_{idx}.bin",
                file_name=f"payload_{idx}.bin",
                file_type='application/x-dosexec',
                file_size=random.randint(10_000, 8_000_000),
                sha256=f"{random.getrandbits(160):040x}",
                entropy=round(random.uniform(5.5, 7.9), 3),
                signature_hits=['MZ header', 'Suspicious Powershell'] if verdict in {MalwareScan.Verdict.MALICIOUS, MalwareScan.Verdict.QUARANTINED} else [],
                heuristic_findings=['High entropy', 'Uses obfuscated strings'] if verdict != MalwareScan.Verdict.CLEAN else [],
                risk_score=random.uniform(10, 95),
                risk_level=risk_level,
                verdict=verdict,
                quarantine_path=f'quarantine/{idx}' if verdict == MalwareScan.Verdict.QUARANTINED else '',
                policy_applied='auto_quarantine' if verdict == MalwareScan.Verdict.QUARANTINED else 'manual_review' if verdict == MalwareScan.Verdict.MALICIOUS else '',
                external_references={'vt_permalink': f'https://www.virustotal.com/gui/file/{random.getrandbits(64):016x}'},
                created_at=timezone.now() - timedelta(hours=random.randint(0, 240)),
            )

        self.stdout.write(self.style.SUCCESS(f'Created {count} malware scans'))

    def _create_security_alerts(self, count: int, user):
        SecurityAlert.objects.all().delete()
        modules = list(ModuleType.values)

        for _ in range(count):
            module = random.choice(modules)
            severity = random.choice(list(RiskLevel.values))
            status = random.choice(list(SecurityAlert.Status.values))
            SecurityAlert.objects.create(
                module=module,
                title=f"{module.title()} alert {random.randint(100, 999)}",
                description="Automated detection surfaced this event requiring triage.",
                severity=severity,
                status=status,
                insight={'module': module, 'correlationId': random.randint(1_000_000, 9_999_999)},
                remediation=['Investigate root cause', 'Notify incident commander'],
                acknowledged_by=user if status in {SecurityAlert.Status.INVESTIGATING, SecurityAlert.Status.MITIGATED} else None,
                acknowledged_at=timezone.now() - timedelta(hours=random.randint(0, 72)) if status != SecurityAlert.Status.NEW else None,
                resolved_at=timezone.now() - timedelta(hours=random.randint(0, 48)) if status == SecurityAlert.Status.MITIGATED else None,
            )

        self.stdout.write(self.style.SUCCESS(f'Created {count} security alerts'))
