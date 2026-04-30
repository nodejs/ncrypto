#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


NODE_REPOSITORY = 'https://github.com/nodejs/node.git'
STATE_FILE = Path('.github/sync-node-ncrypto.json')
MAPPINGS = {
    'deps/ncrypto/ncrypto.h': Path('include/ncrypto.h'),
    'deps/ncrypto/ncrypto.cc': Path('src/ncrypto.cpp'),
    'deps/ncrypto/engine.cc': Path('src/engine.cpp'),
}
SOURCE_SUFFIXES = ('.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx')


class SyncError(Exception):
    pass


def run(
    args: Sequence[str],
    *,
    input_data: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and result.returncode != 0:
        command = ' '.join(args)
        stderr = result.stderr.decode(errors='replace').strip()
        raise SyncError(f'{command} failed: {stderr}')
    return result


def git(args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return run(('git', *args), check=check)


def repo_root() -> Path:
    return Path(git(('rev-parse', '--show-toplevel')).stdout.decode().strip())


def fetch_ref(repository: str, ref: str) -> str:
    if not ref:
        raise SyncError('ref cannot be empty')

    git(('fetch', '--no-tags', '--depth=1', repository, ref))
    return git(('rev-parse', 'FETCH_HEAD^{commit}')).stdout.decode().strip()


def load_state(path: Path) -> str | None:
    if not path.exists():
        return None

    with path.open(encoding='utf-8') as file:
        state = json.load(file)

    node_commit = state.get('node_commit')
    if node_commit is not None and not isinstance(node_commit, str):
        raise SyncError(f'{path} has an invalid node_commit value')
    return node_commit or None


def write_state(path: Path, node_commit: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {'node_commit': node_commit}
    with path.open('w', encoding='utf-8') as file:
        json.dump(state, file, indent=2)
        file.write('\n')


def node_file(commit: str, path: str) -> bytes:
    return git(('show', f'{commit}:{path}')).stdout


def node_ncrypto_files(commit: str) -> list[str]:
    output = git(('ls-tree', '-r', '--name-only', commit, '--', 'deps/ncrypto')).stdout.decode()
    return [line for line in output.splitlines() if line]


def check_unmapped_files(commit: str) -> None:
    mapped = set(MAPPINGS)
    unmapped = [
        path
        for path in node_ncrypto_files(commit)
        if path.endswith(SOURCE_SUFFIXES) and path not in mapped
    ]
    if unmapped:
        files = '\n'.join(f'- {path}' for path in unmapped)
        raise SyncError(f'nodejs/node added unmapped deps/ncrypto source/header files:\n{files}')


def mapped_files_different_from_node(commit: str) -> list[str]:
    return [
        str(destination)
        for source, destination in MAPPINGS.items()
        if destination.read_bytes() != node_file(commit, source)
    ]


def write_temp_file(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


def merge_file(
    *,
    source: str,
    destination: Path,
    base_sha: str,
    target_sha: str,
    temporary_directory: Path,
) -> tuple[bytes, bool]:
    base = write_temp_file(temporary_directory, 'base', node_file(base_sha, source))
    theirs = write_temp_file(temporary_directory, 'theirs', node_file(target_sha, source))
    ours = write_temp_file(temporary_directory, 'ours', destination.read_bytes())
    result = git(
        (
            'merge-file',
            '-p',
            '--diff3',
            '-L',
            f'nodejs/ncrypto:{destination}',
            '-L',
            f'nodejs/node:{source}@{base_sha[:12]}',
            '-L',
            f'nodejs/node:{source}@{target_sha[:12]}',
            str(ours),
            str(base),
            str(theirs),
        ),
        check=False,
    )
    if result.returncode >= 128:
        stderr = result.stderr.decode(errors='replace').strip()
        raise SyncError(f'failed to merge {source} into {destination}: {stderr}')
    return result.stdout, result.returncode != 0


def has_changes(paths: Sequence[Path]) -> bool:
    result = git(('status', '--porcelain', '--', *(str(path) for path in paths)))
    return bool(result.stdout.strip())


def write_github_output(values: dict[str, str | bool | Sequence[str]]) -> None:
    output_path = os.environ.get('GITHUB_OUTPUT')
    if not output_path:
        return

    with Path(output_path).open('a', encoding='utf-8') as file:
        for key, value in values.items():
            if isinstance(value, bool):
                file.write(f'{key}={str(value).lower()}\n')
            elif isinstance(value, str):
                file.write(f'{key}={value}\n')
            else:
                file.write(f'{key}<<EOF\n')
                file.write('\n'.join(value))
                file.write('\nEOF\n')


def sync(args: argparse.Namespace) -> int:
    root = repo_root()
    os.chdir(root)

    state_path = Path(args.state_file)
    current_state = load_state(state_path)
    base_ref = args.base_node_ref or current_state
    if base_ref is None:
        raise SyncError(f'{state_path} does not record a node_commit; pass --base-node-ref to bootstrap the sync')

    base_sha = fetch_ref(args.node_repository, base_ref)
    target_sha = fetch_ref(args.node_repository, args.node_ref)

    check_unmapped_files(target_sha)

    if current_state is None and base_sha == target_sha:
        differing_files = mapped_files_different_from_node(target_sha)
        if differing_files:
            files = '\n'.join(f'- {path}' for path in differing_files)
            raise SyncError(
                'refusing to bootstrap sync state from identical base and target Node commits because the mapped '
                f'standalone files differ from nodejs/node:\n{files}\n'
                'Pass the previous imported nodejs/node commit as --base-node-ref, not the target commit.'
            )

    conflicts: list[str] = []
    would_change = current_state != target_sha
    with tempfile.TemporaryDirectory(prefix='sync-node-ncrypto-') as temporary_directory_name:
        temporary_directory = Path(temporary_directory_name)
        for source, destination in MAPPINGS.items():
            merged, conflicted = merge_file(
                source=source,
                destination=destination,
                base_sha=base_sha,
                target_sha=target_sha,
                temporary_directory=temporary_directory,
            )
            if destination.read_bytes() != merged:
                would_change = True
            if not args.dry_run:
                destination.write_bytes(merged)
            if conflicted:
                conflicts.append(str(destination))

    if not args.dry_run:
        write_state(state_path, target_sha)

    paths = [*MAPPINGS.values(), state_path]
    changed = would_change if args.dry_run else has_changes(paths)
    outputs = {
        'base_sha': base_sha,
        'target_sha': target_sha,
        'target_short_sha': target_sha[:12],
        'has_changes': changed,
        'has_conflicts': bool(conflicts),
        'conflicts': conflicts,
        'branch_name': f'sync-node-ncrypto/{target_sha[:12]}',
    }
    write_github_output(outputs)

    print(f'Base node commit:   {base_sha}')
    print(f'Target node commit: {target_sha}')
    print(f'Changed files:      {str(changed).lower()}')
    print(f'Conflicts:          {str(bool(conflicts)).lower()}')
    for path in conflicts:
        print(f'Conflict:           {path}')

    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Sync nodejs/node deps/ncrypto into standalone ncrypto.')
    parser.add_argument('--node-repository', default=NODE_REPOSITORY)
    parser.add_argument('--node-ref', default='main')
    parser.add_argument('--base-node-ref', default='')
    parser.add_argument('--state-file', default=str(STATE_FILE))
    parser.add_argument('--dry-run', action='store_true')
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    try:
        return sync(parse_args(argv))
    except SyncError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
