"""Documentation recovery requires completed package publication."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import docs
import resume_release


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.repository = "gsmlg-dev/http_fetch"
        self.run = {"repository": {"full_name": self.repository}, "event": "workflow_dispatch",
                    "path": ".github/workflows/release.yml", "status": "completed",
                    "conclusion": "failure", "head_sha": self.sha}
        self.steps = [{"name": name, "conclusion": "success"} for name in resume_release.REQUIRED_STEPS]
        self.steps.extend([
            {"name": "Commit version and create immutable tag", "conclusion": "skipped"},
            {"name": resume_release.DOCS_STEP, "conclusion": "failure"},
        ])
        self.jobs = [{"name": resume_release.PORTABLE_JOB, "conclusion": "failure", "steps": self.steps},
                     {"name": "Publish optional abyss_raw after the portable release", "conclusion": "skipped"}]

    def validate(self):
        resume_release.validate_provenance(self.run, self.jobs, self.repository, self.sha)

    def test_documentation_only_failure_accepted(self):
        self.validate()

    def test_wrong_run_provenance_rejected(self):
        for field, value in (("event", "push"), ("path", ".github/workflows/ci.yml"),
                             ("status", "in_progress"), ("conclusion", "success"),
                             ("head_sha", "b" * 40), ("repository", {"full_name": "other/repo"})):
            with self.subTest(field=field):
                original = copy.deepcopy(self.run)
                self.run[field] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.run = original

    def test_every_required_gate_must_exist_and_pass_before_docs(self):
        for name in resume_release.REQUIRED_STEPS:
            for state in ("failure", "skipped", None):
                with self.subTest(name=name, state=state):
                    original = copy.deepcopy(self.steps)
                    if state is None:
                        self.steps[:] = [step for step in self.steps if step["name"] != name]
                    else:
                        next(step for step in self.steps if step["name"] == name)["conclusion"] = state
                    with self.assertRaisesRegex(ValueError, "required release gate"):
                        self.validate()
                    self.steps[:] = original
        self.steps.insert(0, self.steps.pop(-1))
        with self.assertRaisesRegex(ValueError, "before docs"):
            self.validate()

    def test_other_failure_rejected(self):
        self.steps[-1]["conclusion"] = "success"
        with self.assertRaisesRegex(ValueError, "only documentation"):
            self.validate()
        self.steps[-1]["conclusion"] = "failure"
        self.steps.append({"name": "Unexpected failure", "conclusion": "failure"})
        with self.assertRaisesRegex(ValueError, "unrelated release failure"):
            self.validate()
        self.steps.pop()
        self.jobs[-1]["conclusion"] = "failure"
        with self.assertRaisesRegex(ValueError, "unrelated failed release job"):
            self.validate()

    def test_duplicate_job_or_step_rejected(self):
        self.jobs.append(copy.deepcopy(self.jobs[0]))
        with self.assertRaises(ValueError):
            self.validate()
        self.jobs.pop()
        self.steps.append(copy.deepcopy(self.steps[0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.validate()

    def test_artifact_recovery_cannot_run_from_different_source(self):
        with patch.object(resume_release.subprocess, "check_output", side_effect=[self.sha, "b" * 40]), \
                patch.object(resume_release, "stage_sources") as stage:
            with self.assertRaisesRegex(ValueError, "exact verified source tag"):
                resume_release.artifacts("1.0.0-rc.4", Path("/archives"), Path("/stage"), self.sha)
            stage.assert_not_called()

    def test_missing_published_portable_blocks_completion(self):
        with patch.object(resume_release.subprocess, "check_output", return_value=self.sha), \
                patch.object(resume_release, "source_version", return_value="1.0.0-rc.4"), \
                patch.object(resume_release, "stage_sources"), \
                patch.object(resume_release, "audit_package"), \
                patch.object(resume_release.subprocess, "run"), \
                patch.object(resume_release, "release_status", return_value="missing"), \
                patch.object(resume_release, "verify_assets") as github:
            with self.assertRaisesRegex(ValueError, "published portable archive required"):
                resume_release.artifacts("1.0.0-rc.4", Path("/archives"), Path("/stage"), self.sha)
            github.assert_not_called()


class LockedDocumentationTests(unittest.TestCase):
    def test_docs_dependency_resolution_uses_reviewed_lock_before_first_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "mix.lock").write_bytes(b"reviewed tooling pins\n")
            source = root / "stage" / "abyss"
            source.mkdir(parents=True)
            (source / "mix.exs").write_text('def project do\n  [\n    deps: deps()\n  ]\nend\n')
            commands = []

            def command(args, *, cwd, check):
                self.assertEqual((cwd / "mix.lock").read_bytes(), (root / "mix.lock").read_bytes())
                self.assertTrue(check)
                commands.append(args)

            with patch.object(docs, "ROOT", root), patch.object(docs, "PACKAGES", ("abyss",)), \
                    patch.object(docs.subprocess, "run", side_effect=command):
                docs.run("1.0.0-rc.4", root / "stage", publish=True)
            self.assertEqual(commands, [["mix", "deps.get"], ["mix", "docs"],
                                        ["mix", "hex.publish", "docs", "--yes"]])

    def test_recovery_native_lane_reuses_publication_and_starts_independently_of_docs(self):
        root = Path(__file__).resolve().parents[2]
        existing = (root / ".github/workflows/release.yml").read_text().split("\n  native-release:", 1)[1]
        recovery = (root / ".github/workflows/release-complete.yml").read_text().split("\n  native-release:", 1)[1]
        self.assertEqual(recovery, existing.replace("needs: release", "needs: complete")
                         .replace("needs.release.outputs.source_sha", "needs.complete.outputs.source_sha"))


if __name__ == "__main__":
    unittest.main()
