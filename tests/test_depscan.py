"""Test suite for depscan. Standard library only: `python3 -m unittest discover tests`.

No test here touches the network. The OSV matching tests feed the client
recorded advisory shapes instead, which is what makes them meaningful: the
GitHub Actions case exists precisely because the live API gets it wrong.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from depscan import cvss, purl, versions  # noqa: E402
from depscan.config import Config, IgnoreRule  # noqa: E402
from depscan.discovery import dedupe  # noqa: E402
from depscan.models import Component, Finding, ScanResult, Vulnerability  # noqa: E402
from depscan.osv import _matches, _to_vulnerability  # noqa: E402
from depscan.parsers import ci, node_pkgs, other_pkgs, python_pkgs  # noqa: E402
from depscan.state import State  # noqa: E402


class TempTree(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path


class TestVersions(unittest.TestCase):
    def test_ordering(self) -> None:
        cases = [
            ("1.2.0", "1.10.0", -1),   # numeric, not lexicographic
            ("2.19.0", "2.19", 0),     # trailing zeros are implicit
            ("3.0", "3.0.0", 0),
            ("1.2.0-rc1", "1.2.0", -1),
            ("1.0.0-alpha", "1.0.0-beta", -1),
            ("1.0.0", "1.0.0.post1", -1),
            ("v45.0.7", "46.0.1", -1),  # tag prefixes are stripped
            ("1.0.0+build5", "1.0.0", 0),  # build metadata is not ordering data
        ]
        for a, b, expected in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(versions.compare(a, b), expected)
                self.assertEqual(versions.compare(b, a), -expected)

    def test_in_range_simple(self) -> None:
        events = [{"introduced": "0"}, {"fixed": "46.0.1"}]
        self.assertTrue(versions.in_range("45.0.7", events))
        self.assertFalse(versions.in_range("46.0.1", events))
        self.assertFalse(versions.in_range("46.1.0", events))

    def test_in_range_disjoint(self) -> None:
        """Two separate affected windows in one range must not merge."""
        events = [{"introduced": "1.0"}, {"fixed": "1.2"},
                  {"introduced": "1.4"}, {"fixed": "1.6"}]
        self.assertTrue(versions.in_range("1.1", events))
        self.assertFalse(versions.in_range("1.3", events))
        self.assertTrue(versions.in_range("1.5", events))
        self.assertFalse(versions.in_range("1.7", events))
        self.assertFalse(versions.in_range("0.9", events))

    def test_in_range_last_affected(self) -> None:
        events = [{"introduced": "2.0"}, {"last_affected": "2.5"}]
        self.assertTrue(versions.in_range("2.5", events))
        self.assertFalse(versions.in_range("2.6", events))

    def test_lowest_fix_picks_an_actual_upgrade(self) -> None:
        self.assertEqual(
            versions.lowest_fix("2.19.0", ["2.3.0", "2.20.0", "2.31.0"]), "2.20.0"
        )
        # Every fix is below the installed version: report the lowest rather
        # than silently claiming there is nothing to do.
        self.assertEqual(versions.lowest_fix("9.0", ["1.0", "2.0"]), "1.0")
        self.assertIsNone(versions.lowest_fix("1.0", []))


class TestCvss(unittest.TestCase):
    def test_known_scores(self) -> None:
        # Published base scores for well-known CVEs.
        cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),   # Log4Shell
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1),    # CVE-2023-32681
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ]
        for vector, expected in cases:
            with self.subTest(vector=vector):
                self.assertEqual(cvss.base_score(vector), expected)

    def test_unusable_vectors(self) -> None:
        self.assertIsNone(cvss.base_score(""))
        self.assertIsNone(cvss.base_score("CVSS:2.0/AV:N"))
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:Z/AC:L"))

    def test_labels(self) -> None:
        self.assertEqual(cvss.label_for_score(9.8), "CRITICAL")
        self.assertEqual(cvss.label_for_score(7.0), "HIGH")
        self.assertEqual(cvss.label_for_score(3.9), "LOW")
        # GitHub's wording is normalised onto the CVSS scale.
        self.assertEqual(cvss.normalize_label("MODERATE"), "MEDIUM")
        self.assertEqual(cvss.normalize_label(None), "UNKNOWN")


class TestPythonParsers(TempTree):
    def test_requirements_forms(self) -> None:
        path = self.write("requirements.txt", """
# comment
requests==2.19.0
Django >= 3.2, <4      # a range cannot be matched
PyYAML==5.3.1 --hash=sha256:abc123
uvicorn[standard]==0.17.0
backports.zoneinfo==0.2.1; python_version < "3.9"
--index-url https://example.internal/simple
git+https://github.com/psf/cachecontrol@v0.12.6#egg=cachecontrol
./local-package
""")
        found = {c.name: c for c in python_pkgs.parse_requirements(path, "p")}
        self.assertEqual(found["requests"].version, "2.19.0")
        self.assertIsNone(found["django"].version, "a range must not be read as a pin")
        self.assertEqual(found["pyyaml"].version, "5.3.1")
        self.assertEqual(found["pyyaml"].integrity, "sha256:abc123")
        self.assertEqual(found["uvicorn"].version, "0.17.0", "extras must be stripped")
        self.assertEqual(found["backports-zoneinfo"].version, "0.2.1",
                         "PEP 503 normalisation applies to the name")
        self.assertEqual(found["cachecontrol"].relation, "vcs")
        self.assertEqual(found["cachecontrol"].vcs_url,
                         "https://github.com/psf/cachecontrol")
        self.assertNotIn("./local-package", found)

    def test_requirements_follows_includes(self) -> None:
        self.write("extra.txt", "jinja2==2.11.2\n")
        path = self.write("requirements.txt", "requests==2.19.0\n-r extra.txt\n")
        names = {c.name for c in python_pkgs.parse_requirements(path, "p")}
        self.assertEqual(names, {"requests", "jinja2"})

    def test_requirements_circular_include_terminates(self) -> None:
        self.write("b.txt", "-r a.txt\nflask==2.0.0\n")
        path = self.write("a.txt", "-r b.txt\nrequests==2.19.0\n")
        names = {c.name for c in python_pkgs.parse_requirements(path, "p")}
        self.assertEqual(names, {"requests", "flask"})

    def test_pyproject_pep621_and_poetry(self) -> None:
        path = self.write("pyproject.toml", """
[project]
name = "x"
dependencies = ["pandas==1.3.0", "pillow>=8"]
[project.optional-dependencies]
dev = ["pytest==7.0.0"]
[tool.poetry.dependencies]
python = "^3.11"
urllib3 = "1.26.4"
rich = "^13.0"
""")
        found = {c.name: c for c in python_pkgs.parse_pyproject(path, "p")}
        self.assertEqual(found["pandas"].version, "1.3.0")
        self.assertIsNone(found["pillow"].version)
        self.assertEqual(found["pytest"].version, "7.0.0")
        self.assertEqual(found["urllib3"].version, "1.26.4")
        self.assertIsNone(found["rich"].version, "a caret range is not a pin")
        self.assertNotIn("python", found, "the python constraint is not a package")

    def test_malformed_toml_is_not_fatal(self) -> None:
        path = self.write("pyproject.toml", "[project\nbroken = ")
        self.assertEqual(python_pkgs.parse_pyproject(path, "p"), [])

    def test_installed_metadata(self) -> None:
        d = self.root / "numpy-1.21.0.dist-info"
        d.mkdir()
        (d / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: numpy\nVersion: 1.21.0\n\nVersion: 9.9.9\n"
        )
        found = python_pkgs.parse_installed(d, "p")
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].name, found[0].version), ("numpy", "1.21.0"))
        self.assertEqual(found[0].relation, "installed",
                         "the body after the header must not be read as metadata")


class TestNodeParsers(TempTree):
    def test_package_lock_v3(self) -> None:
        path = self.write("package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root"},
                "node_modules/lodash": {"version": "4.17.15", "integrity": "sha512-x"},
                "node_modules/a/node_modules/ms": {"version": "0.7.1"},
                "node_modules/linked": {"version": "1.0.0", "link": True},
            },
        }))
        found = {c.name: c for c in node_pkgs.parse_package_lock(path, "p")}
        self.assertEqual(found["lodash"].version, "4.17.15")
        self.assertEqual(found["lodash"].relation, "direct")
        self.assertEqual(found["ms"].relation, "transitive")
        self.assertNotIn("linked", found, "workspace links are not downloads")

    def test_package_lock_v1_nested(self) -> None:
        path = self.write("package-lock.json", json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "express": {"version": "4.17.1",
                            "dependencies": {"ms": {"version": "0.7.1"}}},
            },
        }))
        found = {c.name: c for c in node_pkgs.parse_package_lock(path, "p")}
        self.assertEqual(found["express"].relation, "direct")
        self.assertEqual(found["ms"].relation, "transitive")

    def test_yarn_lock_scoped_names(self) -> None:
        path = self.write("yarn.lock", '''
"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.17.0"

lodash@^4.17.15:
  version "4.17.21"
''')
        found = {c.name: c.version for c in node_pkgs.parse_yarn_lock(path, "p")}
        self.assertEqual(found["@babel/core"], "7.17.0",
                         "the scope separator must not be read as the version split")
        self.assertEqual(found["lodash"], "4.17.21")

    def test_pnpm_lock_shapes(self) -> None:
        path = self.write("pnpm-lock.yaml", """
lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
  '@babel/core@7.17.0':
    resolution: {integrity: sha512-y}
  /old-style/1.0.0:
    resolution: {integrity: sha512-z}
""")
        found = {c.name: c.version for c in node_pkgs.parse_pnpm_lock(path, "p")}
        self.assertEqual(found.get("lodash"), "4.17.21")
        self.assertEqual(found.get("@babel/core"), "7.17.0")
        self.assertEqual(found.get("old-style"), "1.0.0")

    def test_package_json_ranges_are_not_pins(self) -> None:
        path = self.write("package.json", json.dumps({
            "dependencies": {"lodash": "4.17.15", "express": "^4.17.1",
                             "local": "file:../x",
                             "forked": "github:acme/forked#v2.0.0"},
        }))
        found = {c.name: c for c in node_pkgs.parse_package_json(path, "p")}
        self.assertEqual(found["lodash"].version, "4.17.15")
        self.assertIsNone(found["express"].version)
        self.assertNotIn("local", found)
        self.assertEqual(found["forked"].vcs_url, "https://github.com/acme/forked")


class TestOtherParsers(TempTree):
    def test_go_mod(self) -> None:
        path = self.write("go.mod", """
module example.com/x
go 1.21
require (
	github.com/gin-gonic/gin v1.6.0
	golang.org/x/crypto v0.1.0 // indirect
)
require github.com/pkg/errors v0.9.1
replace github.com/bad/pkg => ./local
""")
        found = {c.name: c for c in other_pkgs.parse_go_mod(path, "p")}
        self.assertEqual(found["github.com/gin-gonic/gin"].version, "v1.6.0")
        self.assertEqual(found["golang.org/x/crypto"].relation, "transitive")
        self.assertEqual(found["github.com/pkg/errors"].version, "v0.9.1")
        self.assertNotIn("github.com/bad/pkg", found,
                         "a locally replaced module no longer comes from upstream")

    def test_pom_resolves_properties(self) -> None:
        path = self.write("pom.xml", """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
  </dependencies>
</project>""")
        found = other_pkgs.parse_pom(path, "p")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, "org.apache.logging.log4j:log4j-core")
        self.assertEqual(found[0].version, "2.14.1")

    def test_gemfile_lock_nesting(self) -> None:
        path = self.write("Gemfile.lock", """GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.11.0)
      racc (~> 1.4)
    racc (1.5.2)

PLATFORMS
  ruby
""")
        found = {c.name: c.version for c in other_pkgs.parse_gemfile_lock(path, "p")}
        self.assertEqual(found, {"nokogiri": "1.11.0", "racc": "1.5.2"},
                         "a dependency line under a spec is not itself a gem entry")

    def test_cargo_lock_git_source(self) -> None:
        path = self.write("Cargo.lock", """
[[package]]
name = "serde"
version = "1.0.130"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "forked"
version = "0.1.0"
source = "git+https://github.com/acme/forked?branch=main#deadbeef"
""")
        found = {c.name: c for c in other_pkgs.parse_cargo_lock(path, "p")}
        self.assertEqual(found["serde"].integrity, "abc")
        self.assertEqual(found["forked"].relation, "vcs")
        self.assertEqual(found["forked"].vcs_url, "https://github.com/acme/forked")


class TestCiParsers(TempTree):
    def test_workflow_uses(self) -> None:
        path = self.write(".github/workflows/ci.yml", """
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v45.0.7
      - uses: actions/cache/restore@v3
      - uses: acme/act@8f152de45cc393bb48ce5d89d36b731f54556e65
      - uses: ./.github/actions/local
""")
        found = {c.name: c for c in ci.parse_workflow(path, "p")}
        self.assertEqual(found["actions/checkout"].version, "v4")
        self.assertEqual(found["tj-actions/changed-files"].version, "v45.0.7")
        self.assertEqual(found["actions/cache"].version, "v3",
                         "a subpath action still resolves to its repository")
        self.assertIsNone(found["acme/act"].version,
                          "a 40-char SHA is not a version range can be matched against")
        self.assertEqual(found["acme/act"].vcs_ref,
                         "8f152de45cc393bb48ce5d89d36b731f54556e65")
        self.assertNotIn("./.github/actions/local", found)

    def test_dockerfile_stages(self) -> None:
        path = self.write("Dockerfile", """
FROM python:3.9-slim AS base
RUN echo hi
FROM base AS final
FROM gcr.io/distroless/static@sha256:abc123
""")
        found = ci.parse_dockerfile(path, "p")
        names = [(c.name, c.version) for c in found]
        self.assertIn(("python", "3.9-slim"), names)
        self.assertIn(("gcr.io/distroless/static", "sha256:abc123"), names)
        self.assertNotIn("base", [n for n, _ in names],
                         "a build-stage alias is not an image to pull")


class TestOsvMatching(unittest.TestCase):
    """The client-side matching that covers OSV's GitHub Actions gap."""

    ADVISORY = {
        "id": "GHSA-mrrh-fwg8-r2c3",
        "summary": "tj-actions changed-files leaks secrets",
        "affected": [{
            "package": {"ecosystem": "GitHub Actions", "name": "tj-actions/changed-files"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "46.0.1"}]}],
        }],
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-200"]},
        "aliases": ["CVE-2025-30066"],
    }

    def test_matches_affected_version(self) -> None:
        self.assertTrue(
            _matches(self.ADVISORY, "GitHub Actions", "tj-actions/changed-files", "45.0.7")
        )
        self.assertTrue(
            _matches(self.ADVISORY, "GitHub Actions", "tj-actions/changed-files", "v45.0.7")
        )

    def test_rejects_fixed_version(self) -> None:
        self.assertFalse(
            _matches(self.ADVISORY, "GitHub Actions", "tj-actions/changed-files", "46.0.1")
        )

    def test_rejects_other_package(self) -> None:
        self.assertFalse(
            _matches(self.ADVISORY, "GitHub Actions", "actions/checkout", "45.0.7")
        )
        self.assertFalse(
            _matches(self.ADVISORY, "npm", "tj-actions/changed-files", "45.0.7")
        )

    def test_to_vulnerability_derives_score(self) -> None:
        vuln = _to_vulnerability(self.ADVISORY)
        self.assertEqual(vuln.severity, "HIGH")
        self.assertEqual(vuln.cvss_score, 10.0)
        self.assertEqual(vuln.cve_ids, ["CVE-2025-30066"])
        self.assertEqual(vuln.cwe_ids, ["CWE-200"])

    def test_severity_falls_back_to_the_vector(self) -> None:
        record = dict(self.ADVISORY, database_specific={})
        self.assertEqual(_to_vulnerability(record).severity, "CRITICAL")


class TestIgnoreRules(unittest.TestCase):
    def _finding(self, vuln_id="GHSA-x", package="requests", project="api") -> Finding:
        return Finding(
            component=Component(name=package, version="1.0", ecosystem="PyPI",
                                project=project, source_file="/x", manifest_type="r"),
            vulnerability=Vulnerability(id=vuln_id, aliases=["CVE-2020-1"]),
        )

    def test_matching_and_scoping(self) -> None:
        self.assertTrue(IgnoreRule(id="GHSA-x").matches(self._finding()))
        self.assertTrue(IgnoreRule(id="CVE-2020-1").matches(self._finding()),
                        "an alias must match too")
        self.assertFalse(IgnoreRule(id="GHSA-y").matches(self._finding()))
        self.assertFalse(
            IgnoreRule(id="GHSA-x", project="other").matches(self._finding())
        )
        self.assertTrue(IgnoreRule(id="*", package="requests").matches(self._finding()))

    def test_expiry_restores_the_finding(self) -> None:
        self.assertTrue(
            IgnoreRule(id="GHSA-x", expires="2999-01-01").matches(self._finding())
        )
        self.assertFalse(
            IgnoreRule(id="GHSA-x", expires="2020-01-01").matches(self._finding()),
            "an expired acceptance must stop hiding the finding",
        )
        self.assertFalse(
            IgnoreRule(id="GHSA-x", expires="not-a-date").matches(self._finding()),
            "an unparseable date must fail safe, not hide the finding",
        )


class TestState(TempTree):
    def _result(self, ids: list[str]) -> ScanResult:
        result = ScanResult(root="/r", started_at="now")
        result.findings = [
            Finding(
                component=Component(name="p", version="1.0", ecosystem="PyPI",
                                    project="proj", source_file="/x", manifest_type="r"),
                vulnerability=Vulnerability(id=i),
            )
            for i in ids
        ]
        return result

    def test_first_run_is_a_baseline(self) -> None:
        state = State(self.root / "state.json")
        first = self._result(["A", "B"])
        state.mark_new(first.findings)
        self.assertFalse(any(f.is_new for f in first.findings),
                         "the first run must not report everything as new")
        state.record(first)

        state2 = State(self.root / "state.json")
        second = self._result(["A", "B", "C"])
        state2.mark_new(second.findings)
        self.assertEqual([f.vulnerability.id for f in second.findings if f.is_new], ["C"])

    def test_resolved_then_reintroduced_is_new_again(self) -> None:
        path = self.root / "state.json"
        first = self._result(["A"])
        s1 = State(path)
        s1.mark_new(first.findings)
        s1.record(first)

        s2 = State(path)
        fixed = self._result([])
        s2.mark_new(fixed.findings)
        s2.record(fixed)

        s3 = State(path)
        back = self._result(["A"])
        s3.mark_new(back.findings)
        self.assertTrue(back.findings[0].is_new)

    def test_corrupt_state_does_not_raise(self) -> None:
        path = self.root / "state.json"
        path.write_text("{not json", encoding="utf-8")
        State(path)  # must not raise


class TestPurl(unittest.TestCase):
    def test_shapes(self) -> None:
        def c(name, version, eco):
            return Component(name=name, version=version, ecosystem=eco,
                             project="p", source_file="/x", manifest_type="m")
        self.assertEqual(purl.for_component(c("requests", "2.19.0", "PyPI")),
                         "pkg:pypi/requests@2.19.0")
        self.assertEqual(purl.for_component(c("@babel/core", "7.1.0", "npm")),
                         "pkg:npm/%40babel/core@7.1.0")
        self.assertEqual(
            purl.for_component(c("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven")),
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        self.assertEqual(purl.for_component(c("github.com/gin-gonic/gin", "v1.6.0", "Go")),
                         "pkg:golang/github.com/gin-gonic/gin@v1.6.0")
        self.assertIsNone(purl.for_component(c("x", "1", "git-submodule")))


class TestDedupe(unittest.TestCase):
    def test_pinned_record_wins_over_a_range(self) -> None:
        def c(version, relation, manifest):
            return Component(name="requests", version=version, ecosystem="PyPI",
                             project="p", source_file="/" + manifest,
                             manifest_type=manifest, relation=relation)
        out = dedupe([
            c(None, "direct", "pyproject.toml"),
            c("2.19.0", "installed", "site-packages"),
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].version, "2.19.0")

    def test_same_package_in_two_projects_is_kept(self) -> None:
        a = Component(name="x", version="1.0", ecosystem="PyPI", project="one",
                      source_file="/a", manifest_type="r")
        b = Component(name="x", version="1.0", ecosystem="PyPI", project="two",
                      source_file="/b", manifest_type="r")
        self.assertEqual(len(dedupe([a, b])), 2)


class TestSummary(unittest.TestCase):
    def test_ignored_findings_leave_the_counts(self) -> None:
        result = ScanResult(root="/r", started_at="now")
        comp = Component(name="p", version="1", ecosystem="PyPI", project="x",
                         source_file="/f", manifest_type="r")
        live = Finding(component=comp,
                       vulnerability=Vulnerability(id="A", severity="CRITICAL"))
        hidden = Finding(component=comp,
                         vulnerability=Vulnerability(id="B", severity="CRITICAL"),
                         ignored=True)
        result.findings = [live, hidden]
        summary = result.summary()
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(summary["ignored"], 1)
        self.assertEqual(summary["by_severity"]["CRITICAL"], 1)

    def test_kev_outranks_severity_in_the_priority_order(self) -> None:
        comp = Component(name="p", version="1", ecosystem="PyPI", project="x",
                         source_file="/f", manifest_type="r")
        critical = Finding(component=comp,
                           vulnerability=Vulnerability(id="A", severity="CRITICAL"))
        exploited = Finding(component=comp,
                            vulnerability=Vulnerability(id="B", severity="HIGH", kev=True))
        self.assertEqual(
            [f.vulnerability.id for f in sorted([critical, exploited],
                                                key=lambda f: f.priority)],
            ["B", "A"],
            "something being exploited right now outranks a worse theoretical score",
        )


class TestConfig(TempTree):
    def test_load(self) -> None:
        path = self.write("depscan.toml", """
[scan]
root = "~/projects"
exclude = ["archive"]
include_installed = false
[report]
fail_on = "critical"
formats = ["markdown"]
[[ignore]]
id = "GHSA-x"
reason = "not reachable"
expires = "2030-01-01"
""")
        cfg = Config.load(path)
        self.assertEqual(cfg.excludes, {"archive"})
        self.assertFalse(cfg.include_installed)
        self.assertEqual(cfg.fail_on, "critical")
        self.assertEqual(len(cfg.ignores), 1)
        self.assertEqual(cfg.ignores[0].expires, "2030-01-01")

    def test_missing_config_is_an_error_only_when_named(self) -> None:
        self.assertIsNone(Config.load(None).root)
        with self.assertRaises(FileNotFoundError):
            Config.load(self.root / "nope.toml")


if __name__ == "__main__":
    unittest.main(verbosity=2)
