import tempfile
from typing import Any, cast, Callable, Sequence, IO
import pygit2
from pygit2.repository import Repository
import logging
import re
import httpx
import asyncio
import yaml
import io
from pathlib import PurePath
from httpx_retries import RetryTransport
from dataclasses import dataclass

from . import json_schema, utils

logger = logging.getLogger(__name__)


class CrdRepository:
    def __init__(
        self,
        owner: str,
        name: str,
        git_url: str,
        crd_globs: str | Sequence[str] | None,
        *,
        get_crd_urls: Callable[[str], str | Sequence[str]] | None = None,
        tag_regex: str = r"^v[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}$",
        exclude_tag_regex: str | None = None,
    ) -> None:
        self.owner = owner
        self.name = name
        self.git_url = git_url

        self.get_crd_urls = get_crd_urls
        self.crd_globs = [crd_globs] if isinstance(crd_globs, str) else crd_globs
        self.tag_regex = re.compile(tag_regex)
        self.tag_exclude_regex = re.compile(exclude_tag_regex) if exclude_tag_regex else None

        self.git = Repository()

    async def get_refs(self) -> dict[str, str]:
        remote = self.git.remotes.create_anonymous(self.git_url)

        return {
            f"v{remote.name.lstrip('refs/tags/').lstrip('v')}": remote.name
            for remote in remote.list_heads()
            if remote.name is not None
            and remote.name.startswith("refs/tags/")
            and self.tag_regex.match(remote.name.lstrip("refs/tags/"))
            and (self.tag_exclude_regex is None or not self.tag_exclude_regex.match(remote.name.lstrip("refs/tags/")))
        }

    def git_files(self, ref):
        @dataclass
        class File:
            path: PurePath
            blob: pygit2.Blob

        def encode_tree(tree: pygit2.Tree, root: PurePath = PurePath(), *, accumulator: list[File] = []) -> list[File]:
            for obj in tree:
                assert obj.name is not None, "We assume git objects in a tree always have a name."
                if isinstance(obj, pygit2.Tree):
                    encode_tree(obj, root / obj.name)
                elif isinstance(obj, pygit2.Blob):
                    accumulator.append(File(root / obj.name, obj))
                else:
                    logger.debug(f"Ignoring git object at {root / obj.name}")

            return accumulator

        with tempfile.TemporaryDirectory() as path:
            git = pygit2.init_repository(path, bare=True)
            remote = git.remotes.create("origin", self.git_url)
            transfer = remote.fetch([ref], depth=1)

            assert transfer.total_objects != 0

            obj = git.revparse_single(ref)
            commit = obj.peel(pygit2.Commit)

            return encode_tree(commit.tree)

    async def generate_json_schema_from_urls(self, ref: str, buffer_size=io.DEFAULT_BUFFER_SIZE, **kwargs) -> None:
        assert self.get_crd_urls is not None
        async with httpx.AsyncClient(follow_redirects=True, timeout=60, transport=RetryTransport()) as client:
            urls = self.get_crd_urls(ref)
            if isinstance(urls, str):
                urls = [urls]

            responses = await asyncio.gather(*[client.get(url) for url in urls])

            if len(responses) <= 0:
                logger.warning(f"No CRDs found for {self.owner}/{self.name} ref {ref} from url {','.join(urls)}")
                return

            def test_and_reset(test: Callable[[IO[bytes]], bool], file: IO[bytes]):
                file.seek(0)
                return test(file)

            def get_url_crd_streams():
                for response in responses:
                    yield io.BufferedReader(utils.IterStream(response.iter_bytes(buffer_size)), buffer_size=buffer_size)

            json_schema.generate(get_url_crd_streams(), **kwargs)

    def generate_json_schema_from_globs(self, ref: str, **kwargs) -> None:
        assert self.crd_globs is not None
        files = self.git_files(ref)
        blobs = [file.blob for file in files if any(file.path.full_match(glob) for glob in self.crd_globs)]

        if len(blobs) <= 0:
            logger.warning(f"No CRDs found for {self.owner}/{self.name} ref {ref} via glob {','.join(self.crd_globs)}")
            return

        def get_crd_streams():
            for blob in blobs:
                with pygit2.BlobIO(blob) as file:
                    yield file

        json_schema.generate(get_crd_streams(), **kwargs)


class HelmCrdRepository(CrdRepository):
    def __init__(
        self, repository_url: str, *args, is_git_tag_start_with_v=True, use_app_version_for_git_tag=False, **kwargs
    ) -> None:
        self.repository_url = repository_url
        self.is_git_tag_start_with_v = is_git_tag_start_with_v
        self.use_app_version_for_git_tag = use_app_version_for_git_tag
        super().__init__(*args, **kwargs)

    async def get_refs(self):
        remotes = await super().get_refs()

        async with httpx.AsyncClient(follow_redirects=True, timeout=60, transport=RetryTransport()) as client:
            r = await client.get(self.repository_url)
            r.raise_for_status()
            index = yaml.safe_load(r.text)

            helm_versions = {
                f"{'v' if self.is_git_tag_start_with_v else ''}{entry['appVersion' if self.use_app_version_for_git_tag else 'version'].lstrip('v')}": entry
                for entry in cast(list[dict[Any, Any]], index.get("entries", []).get(self.name, []))
                if "version" in entry
            }

            verion_refs = {
                f"v{helm_versions[version]['version'].lstrip('v')}": remote
                for version, remote in remotes.items()
                if version in helm_versions
            }

            if len(verion_refs) <= 0:
                logger.warning(
                    f"The Helm versions for {self.name} do no match git tags, you probably need to set use_app_version_for_git_tag."
                )

            return verion_refs
