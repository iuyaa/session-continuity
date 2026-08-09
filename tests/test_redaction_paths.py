from __future__ import annotations

# ruff: noqa: E402

import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
sys.dont_write_bytecode = True

from session_continuity.contracts import DomainCode, PathSafetyError, RedactionError
from session_continuity.paths import (
    ensure_no_reparse_or_symlink,
    ensure_path_within,
    is_hardlinked_file,
    is_path_within,
    is_symlink,
    is_valid_windows_path_syntax,
    open_verified_readonly,
    stat_is_reparse_point,
    validate_windows_path_syntax,
    windows_path_is_within,
)
from session_continuity.redaction import (
    RedactionCategory,
    assert_no_residual_sensitive_data,
    redact_output,
    redact_structured,
    residual_categories,
)


class RedactionCoverageTests(unittest.TestCase):
    def test_text_patterns_remove_sensitive_values_and_count_categories(self) -> None:
        cases = (
            (
                "quoted secret",
                "api_key='fixtureSecretValue123'",
                "fixtureSecretValue123",
                RedactionCategory.CREDENTIAL,
            ),
            (
                "authorization header",
                "Authorization: Bearer fixtureHeaderToken123",
                "fixtureHeaderToken123",
                RedactionCategory.CREDENTIAL,
            ),
            (
                "cookie header",
                "Cookie: fixture_session=fixtureCookieValue123",
                "fixtureCookieValue123",
                RedactionCategory.CREDENTIAL,
            ),
            (
                "jwt",
                "eyJmaXh0dXJl.eyJzdWJqZWN0.c2lnbmF0dXJl",
                "eyJmaXh0dXJl.eyJzdWJqZWN0.c2lnbmF0dXJl",
                RedactionCategory.CREDENTIAL,
            ),
            (
                "pem private key",
                "-----BEGIN PRIVATE KEY-----\nRklYVFVSRQ==\n-----END PRIVATE KEY-----",
                "RklYVFVSRQ==",
                RedactionCategory.PRIVATE_KEY,
            ),
            (
                "url userinfo",
                "https://fixture-user:fixture-password@fixture.invalid/resource",
                "fixture-user:fixture-password",
                RedactionCategory.URL_USERINFO,
            ),
            (
                "private URL",
                "http://10.20.30.40:8080/private/report",
                "10.20.30.40",
                RedactionCategory.PRIVATE_URL,
            ),
            (
                "phone",
                "+1 (555) 123-4567",
                "555",
                RedactionCategory.PHONE,
            ),
            (
                "known token prefix",
                "github" + "_pat_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
                "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
                RedactionCategory.CREDENTIAL,
            ),
            (
                "high entropy value",
                "aB3dE5fG7hI9jK2mN4pQ6rS8tU0vW1xYz",
                "aB3dE5fG7hI9jK2mN4pQ6rS8tU0vW1xYz",
                RedactionCategory.SECRET,
            ),
            (
                "email",
                "fixture.user@fixture.invalid",
                "fixture.user@fixture.invalid",
                RedactionCategory.EMAIL,
            ),
            (
                "ipv4",
                "192.0.2.10",
                "192.0.2.10",
                RedactionCategory.IP_ADDRESS,
            ),
            (
                "ipv6",
                "2001:db8::10",
                "2001:db8::10",
                RedactionCategory.IP_ADDRESS,
            ),
            (
                "windows path",
                r"C:\fixture\reports\state.txt",
                r"C:\fixture\reports\state.txt",
                RedactionCategory.FILESYSTEM_PATH,
            ),
            (
                "unc path",
                r"\\fixture-server\fixture-share\reports\state.txt",
                r"\\fixture-server\fixture-share\reports\state.txt",
                RedactionCategory.FILESYSTEM_PATH,
            ),
            (
                "posix path",
                "/srv/fixture/reports/state.txt",
                "/srv/fixture/reports/state.txt",
                RedactionCategory.FILESYSTEM_PATH,
            ),
            (
                "home path",
                "~/fixture/reports/state.txt",
                "~/fixture/reports/state.txt",
                RedactionCategory.FILESYSTEM_PATH,
            ),
        )

        for label, source, needle, category in cases:
            with self.subTest(label=label):
                result = redact_output(source)
                self.assertNotIn(needle, result.value)
                self.assertGreaterEqual(result.counts[category], 1)
                self.assertEqual((), residual_categories(result.value))

    def test_sensitive_structured_keys_are_suppressed_by_category(self) -> None:
        source = {
            "clientSecret": "fixture-structured-secret",
            "api_key": "fixture-structured-key",
            "privateKey": "fixture-structured-private-key",
            "nested": {"safe": "visible fixture value"},
        }

        result = redact_structured(source)

        self.assertEqual("[REDACTED:secret]", result.value["clientSecret"])
        self.assertEqual("[REDACTED:credential]", result.value["api_key"])
        self.assertEqual("[REDACTED:private_key]", result.value["privateKey"])
        self.assertEqual("visible fixture value", result.value["nested"]["safe"])
        self.assertEqual(1, result.counts[RedactionCategory.SECRET])
        self.assertEqual(1, result.counts[RedactionCategory.CREDENTIAL])
        self.assertEqual(1, result.counts[RedactionCategory.PRIVATE_KEY])

    def test_public_https_urls_are_preserved_as_action_context(self) -> None:
        source = "https://example.com/org/repository/issues/123?view=compact#details"

        result = redact_output(source)

        self.assertEqual(source, result.value)
        self.assertEqual(0, result.counts.total)

    def test_safe_relative_source_paths_survive_entropy_scanning(self) -> None:
        paths = (
            "frontend/src/modules/jobs/JobProfileHistoryModal.vue",
            "frontend/src/modules/jobs/JobsPage.vue",
            "frontend/src/modules/rpa/RpaNodeManagementModal.vue",
            "frontend/src/modules/jobs/JobProfileHistoryModal.vue:123",
            "frontend/src/modules/jobs/JobProfileHistoryModal.vue#L123",
        )
        source = "\n".join(paths)

        result = redact_output(source)

        self.assertEqual(source, result.value)
        self.assertEqual(0, result.counts.total)
        self.assertEqual((), residual_categories(result.value))

    def test_relative_file_exemption_does_not_hide_sensitive_values(self) -> None:
        standalone = "aB3dE5fG7hI9jK2mN4pQ6rS8tU0vW1xYz.vue"
        traversal = "../frontend/src/modules/jobs/JobProfileHistoryModal.vue"
        known_token = (
            "src/github_pat_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6/token.txt"
        )

        standalone_result = redact_output(standalone)
        traversal_result = redact_output(traversal)
        token_result = redact_output(known_token)

        self.assertIn("[REDACTED:secret]", standalone_result.value)
        self.assertIn("[REDACTED:filesystem_path]", traversal_result.value)
        self.assertIn("[REDACTED:credential]", token_result.value)
        self.assertEqual((), residual_categories(standalone_result.value))
        self.assertEqual((), residual_categories(traversal_result.value))
        self.assertEqual((), residual_categories(token_result.value))

    def test_private_urls_with_userinfo_are_fully_redacted(self) -> None:
        sources = (
            "https://fixture-user:fixture-pass@service.internal/private/report",
            "http://fixture-user:fixture-pass@10.20.30.40:8080/private/report",
        )

        for source in sources:
            with self.subTest(source=source):
                result = redact_output(source)
                self.assertEqual("[REDACTED:private_url]", result.value)
                self.assertEqual(1, result.counts[RedactionCategory.PRIVATE_URL])
                self.assertEqual((), residual_categories(result.value))

    def test_relative_file_exemption_rejects_entropy_bearing_segments(self) -> None:
        secret = "aB3dE5fG7hI9jK2mN4pQ6rS8tU0vW1xYz"
        sources = (
            f"src/{secret}/config.py",
            f"src/{secret}.vue",
            f"'{secret}/nested/config.py'",
            "src/aB3dE5fG7hI9jK2/mN4pQ6rS8tU0vW1xYz/config.py",
            "src/a1b2c3d4e5f6g7h8/i9j0k1l2m3n4o5p6/config.py",
            "frontend/src/modules/abcdefghijklmnop/qrstuvwxyzabcdef/Widget.vue",
            "frontend/src/modules/jobs/aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDe.vue",
            "frontend/src/modules/jobs/QazWseDrfTgyUhjIklOpqMnb.vue",
        )

        for source in sources:
            with self.subTest(source=source):
                result = redact_output(source)
                self.assertIn("[REDACTED:secret]", result.value)
                self.assertEqual((), residual_categories(result.value))

    def test_session_ids_and_content_hashes_are_not_treated_as_secrets(self) -> None:
        source = (
            "session_id=123e4567-e89b-12d3-a456-426614174000 "
            f"sha256={'a' * 64}"
        )

        result = redact_output(source)

        self.assertEqual(source, result.value)
        self.assertEqual(0, result.counts.total)

    def test_known_residuals_fail_closed_with_stable_domain_code(self) -> None:
        residuals = (
            "Authorization: Bearer fixtureResidualToken123",
            "-----BEGIN PRIVATE KEY-----",
            "fixture.residual@fixture.invalid",
            "198.51.100.24",
            r"C:\fixture\residual.txt",
        )

        for source in residuals:
            with self.subTest(source=source):
                with self.assertRaises(RedactionError) as raised:
                    assert_no_residual_sensitive_data(source)
                self.assertEqual(DomainCode.REDACTION_RESIDUAL, raised.exception.code)
                self.assertTrue(raised.exception.context.get("categories"))


class WindowsPathSyntaxTests(unittest.TestCase):
    def test_drive_absolute_and_complete_unc_paths_are_accepted(self) -> None:
        accepted = (
            r"C:\fixture\reports\state.txt",
            r"\\fixture-server\fixture-share\reports\state.txt",
        )

        for source in accepted:
            with self.subTest(source=source):
                candidate = validate_windows_path_syntax(source)
                self.assertTrue(candidate.is_absolute())
                self.assertTrue(is_valid_windows_path_syntax(source))

    def test_unsafe_windows_path_forms_are_rejected(self) -> None:
        rejected = (
            r"C:fixture\state.txt",
            r"\\fixture-server",
            r"\\?\C:\fixture\state.txt",
            r"\\.\PhysicalDrive0",
            r"\??\C:\fixture\state.txt",
            r"C:\fixture\state.txt:zone.identifier",
            r"C:\fixture\CON.txt",
            r"C:\fixture\COM1.log",
            r"C:\fixture\..\outside\state.txt",
            "C:\\fixture\\trailing.\\state.txt",
            "C:\\fixture\\trailing \\state.txt",
        )

        for source in rejected:
            with self.subTest(source=source):
                with self.assertRaises(PathSafetyError):
                    validate_windows_path_syntax(source)
                self.assertFalse(is_valid_windows_path_syntax(source))

    def test_windows_containment_is_component_based_not_prefix_based(self) -> None:
        root = r"C:\Project"

        self.assertTrue(windows_path_is_within(r"c:\project\child\item.txt", root))
        self.assertTrue(windows_path_is_within(r"C:\Project", root))
        self.assertFalse(
            windows_path_is_within(r"C:\Project", root, allow_equal=False)
        )
        self.assertFalse(
            windows_path_is_within(r"C:\Project-Sibling\item.txt", root)
        )
        self.assertFalse(windows_path_is_within(r"D:\Project\item.txt", root))
        self.assertFalse(windows_path_is_within(r"C:Project\item.txt", root))


class LocalPathIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        base = Path(self._temporary.name)
        self.root = base / "project"
        self.sibling = base / "project-sibling"
        self.root.mkdir()
        self.sibling.mkdir()

    def test_local_containment_rejects_traversal_and_sibling_prefix(self) -> None:
        child = self.root / "nested" / "item.txt"
        child.parent.mkdir()
        child.write_text("synthetic fixture", encoding="utf-8")
        sibling_file = self.sibling / "item.txt"
        sibling_file.write_text("synthetic sibling", encoding="utf-8")

        self.assertTrue(is_path_within(child, self.root))
        self.assertEqual(child.resolve(), ensure_path_within(child, self.root))
        self.assertFalse(is_path_within(sibling_file, self.root))
        with self.assertRaises(PathSafetyError) as raised:
            ensure_path_within(self.root / ".." / self.sibling.name / "item.txt", self.root)
        self.assertEqual(DomainCode.PATH_OUTSIDE_ROOT, raised.exception.code)

    def test_symlink_or_reparse_component_is_rejected_when_supported(self) -> None:
        target = self.root / "target.txt"
        target.write_text("synthetic target", encoding="utf-8")
        link = self.root / "linked.txt"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symbolic links are not available: {error}")

        self.assertTrue(is_symlink(link))
        with self.assertRaises(PathSafetyError):
            ensure_no_reparse_or_symlink(link, self.root)
        with self.assertRaises(PathSafetyError):
            open_verified_readonly(link, self.root)

    def test_reparse_attribute_is_detected(self) -> None:
        self.assertTrue(
            stat_is_reparse_point(SimpleNamespace(st_file_attributes=0x400))
        )
        self.assertFalse(stat_is_reparse_point(SimpleNamespace(st_file_attributes=0)))

    def test_hardlinked_regular_file_is_rejected_when_supported(self) -> None:
        original = self.root / "original.txt"
        alias = self.root / "alias.txt"
        original.write_text("synthetic hardlink fixture", encoding="utf-8")
        try:
            os.link(original, alias)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard links are not available: {error}")

        self.assertTrue(is_hardlinked_file(original))
        self.assertTrue(is_hardlinked_file(alias))
        with self.assertRaises(PathSafetyError):
            open_verified_readonly(alias, self.root)


if __name__ == "__main__":
    unittest.main()
