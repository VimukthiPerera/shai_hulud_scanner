"""GitHub code search scanner for compromised libraries."""

from __future__ import annotations

import asyncio
import json
import sys
import base64
from typing import Optional

from .models import SearchResult, AffectedRepository
from .output import Colors, log_progress, log_detection, log_debug


class GitHubScanner:
    def __init__(self, org: str, concurrency: int = 10):
        self.org = org
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limit_delay = 0.3
        self.results: list[SearchResult] = []
        self.results_lock = asyncio.Lock()
        self.detection_count = 0

    async def _fetch_and_verify(
        self, repo: str, file_path: str, lib_name: str, lib_version: str
    ) -> Optional[list[tuple[int, str]]]:
        """
        Fetch file content, parse JSON, and verify exact package match.
        Returns list of (line_number, line_content) if verified, None if not a real match.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/contents/{file_path}',
                '--jq', '.content',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return None

            content = base64.b64decode(stdout.decode().strip()).decode('utf-8')

            # Parse JSON and verify exact match
            try:
                pkg_data = json.loads(content)
            except json.JSONDecodeError:
                return None

            # Check if this is a real match by parsing the JSON structure
            if not self._verify_package_match(pkg_data, lib_name, lib_version):
                log_debug(f"False positive filtered: {lib_name}@{lib_version} in {repo}/{file_path}")
                return None

            # Find line numbers for matched content
            lines = content.split('\n')
            matched = []
            for line_no, line in enumerate(lines, start=1):
                # Look for exact package name as a JSON key
                if f'"{lib_name}"' in line:
                    matched.append((line_no, line))
                elif lib_version in line:
                    matched.append((line_no, line))

            return matched[:10] if matched else [(1, f"{lib_name}@{lib_version}")]

        except Exception as e:
            log_debug(f"Error fetching {repo}/{file_path}: {e}")
            return None

    def _verify_package_match(
        self, pkg_data: dict, lib_name: str, lib_version: str
    ) -> bool:
        """
        Verify that the package.json or package-lock.json contains
        an exact match for lib_name at lib_version.
        """
        # Check package-lock.json structure (v2/v3)
        if 'packages' in pkg_data:
            for pkg_path, pkg_info in pkg_data.get('packages', {}).items():
                if pkg_info.get('name') == lib_name:
                    if pkg_info.get('version') == lib_version:
                        return True
                # Also check nested node_modules path
                if pkg_path.endswith(f'node_modules/{lib_name}'):
                    if pkg_info.get('version') == lib_version:
                        return True

        # Check package-lock.json v1 dependencies
        if 'dependencies' in pkg_data:
            if self._check_dependencies(pkg_data['dependencies'], lib_name, lib_version):
                return True

        # Check package.json dependencies
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            deps = pkg_data.get(dep_type, {})
            if lib_name in deps:
                version_spec = deps[lib_name]
                # Exact version match or version in spec
                if version_spec == lib_version or lib_version in version_spec:
                    return True

        return False

    def _check_dependencies(
        self, deps: dict, lib_name: str, lib_version: str
    ) -> bool:
        """Recursively check dependencies in package-lock.json v1 format."""
        if lib_name in deps:
            dep_info = deps[lib_name]
            if isinstance(dep_info, dict):
                if dep_info.get('version') == lib_version:
                    return True
                # Check nested dependencies
                if 'dependencies' in dep_info:
                    if self._check_dependencies(dep_info['dependencies'], lib_name, lib_version):
                        return True

        # Check all nested dependencies
        for dep_name, dep_info in deps.items():
            if isinstance(dep_info, dict) and 'dependencies' in dep_info:
                if self._check_dependencies(dep_info['dependencies'], lib_name, lib_version):
                    return True

        return False

    async def search_library(
        self, lib_name: str, lib_version: str, index: int, total: int
    ) -> list[SearchResult]:
        """Search for a specific library version in package files."""
        async with self.semaphore:
            log_progress(f"({index}/{total}) Scanning: {lib_name}@{lib_version}")

            search_query = (
                f'"{lib_name}" "{lib_version}" org:{self.org} '
                f'filename:package.json OR filename:package-lock.json'
            )

            log_debug(f"Query: {search_query}")

            try:
                proc = await asyncio.create_subprocess_exec(
                    'gh', 'api', '-X', 'GET', 'search/code',
                    '--field', f'q={search_query}',
                    '--field', 'per_page=100',
                    '--jq', '.items[] | {repository: .repository.full_name, file: .path, url: .html_url, text_matches: .text_matches}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    error_msg = stderr.decode().strip()
                    log_debug(f"API error: {error_msg}")
                    if 'rate limit' in error_msg.lower():
                        print(
                            f"{Colors.YELLOW}[RATE LIMITED]{Colors.NC} "
                            f"{lib_name}@{lib_version} - waiting 60s",
                            file=sys.stderr
                        )
                        await asyncio.sleep(60)
                        return await self.search_library(lib_name, lib_version, index, total)
                    return []

                results = []
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            item = json.loads(line)

                            # Verify the match by fetching and parsing the actual file
                            matched_lines = await self._fetch_and_verify(
                                item['repository'], item['file'],
                                lib_name, lib_version
                            )

                            # Skip false positives (verification returned None)
                            if matched_lines is None:
                                continue

                            result = SearchResult(
                                repository=item['repository'],
                                file=item['file'],
                                url=item['url'],
                                library=lib_name,
                                version=lib_version
                            )
                            results.append(result)

                            log_detection(
                                lib_name, lib_version,
                                item['repository'], item['file'], item['url'],
                                matched_lines=matched_lines
                            )

                            async with self.results_lock:
                                self.detection_count += 1

                        except json.JSONDecodeError:
                            continue

                await asyncio.sleep(self.rate_limit_delay)
                return results

            except Exception as e:
                print(
                    f"{Colors.RED}[ERROR]{Colors.NC} Searching {lib_name}@{lib_version}: {e}",
                    file=sys.stderr
                )
                return []

    async def scan_libraries(
        self, libraries: list[tuple[str, str]]
    ) -> list[SearchResult]:
        """Scan all libraries concurrently with real-time output."""
        total = len(libraries)

        tasks = [
            self.search_library(name, version, idx + 1, total)
            for idx, (name, version) in enumerate(libraries)
        ]

        all_results = await asyncio.gather(*tasks)
        return [r for results in all_results for r in results]

    def aggregate_results(
        self, results: list[SearchResult]
    ) -> list[AffectedRepository]:
        """Group results by repository."""
        repos: dict[str, AffectedRepository] = {}

        for r in results:
            if r.repository not in repos:
                repos[r.repository] = AffectedRepository(
                    repository=r.repository,
                    affected_libraries=[],
                    files_affected=[]
                )

            lib_entry = {
                'library': r.library,
                'version': r.version,
                'file': r.file,
                'url': r.url
            }

            if lib_entry not in repos[r.repository].affected_libraries:
                repos[r.repository].affected_libraries.append(lib_entry)

            if r.file not in repos[r.repository].files_affected:
                repos[r.repository].files_affected.append(r.file)

        return list(repos.values())
