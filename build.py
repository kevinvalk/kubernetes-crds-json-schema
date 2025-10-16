import tempfile
from typing import Any, cast, Callable, Sequence, Iterator, Generator
import pygit2
from pygit2.repository import Repository
import logging
import re
import httpx
import asyncio
import yaml
import io
from pathlib import Path, PurePath
from httpx_retries import RetryTransport
import json
from dataclasses import dataclass


logging.basicConfig(level=logging.INFO)
logging.getLogger("httpx").setLevel(level=logging.WARN)
logger = logging.getLogger(__name__)


class IterStream(io.RawIOBase):
    def __init__(self, iterator: Iterator[Any]):
        self.leftover = None
        self.iterator = iterator

    def readable(self):
        return True

    def readinto(self, b):
        try:
            length = len(b)  # We're supposed to return at most this much
            chunk = self.leftover or next(self.iterator)
            output, self.leftover = chunk[:length], chunk[length:]
            b[: len(output)] = output
            return len(output)
        except StopIteration:
            return 0  # indicate EOF


@dataclass
class Schema:
    kind: str
    group: str
    version: str
    definition: dict[Any, Any]


def additional_properties(data):
    "This recreates the behavior of kubectl at https://github.com/kubernetes/kubernetes/blob/225b9119d6a8f03fcbe3cc3d590c261965d928d0/pkg/kubectl/validation/schema.go#L312"
    new = {}
    try:
        for k, v in data.items():
            new_v = v
            if isinstance(v, dict):
                if "properties" in v:
                    if "additionalProperties" not in v:
                        v["additionalProperties"] = False
                new_v = additional_properties(v)
            else:
                new_v = v
            new[k] = new_v
        return new
    except AttributeError:
        return data


def replace_int_or_string(data):
    new = {}
    try:
        for k, v in data.items():
            new_v = v
            if isinstance(v, dict):
                if "format" in v and v["format"] == "int-or-string":
                    new_v = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
                else:
                    new_v = replace_int_or_string(v)
            elif isinstance(v, list):
                new_v = list()
                for x in v:
                    new_v.append(replace_int_or_string(x))
            else:
                new_v = v
            new[k] = new_v
        return new
    except AttributeError:
        return data


def allow_null_optional_fields(data, parent=None, grand_parent=None, key=None):
    new = {}
    try:
        for k, v in data.items():
            new_v = v
            if isinstance(v, dict):
                new_v = allow_null_optional_fields(v, data, parent, k)
            elif isinstance(v, list):
                new_v = [allow_null_optional_fields(el, v, parent, k) for el in v]
            elif isinstance(v, str):
                is_non_null_type = k == "type" and v != "null"
                has_required_field = grand_parent and "required" in grand_parent
                if is_non_null_type and not has_required_field:
                    new_v = [v, "null"]
            new[k] = new_v
        return new
    except AttributeError:
        return data


def append_no_duplicates(obj, key, value):
    """
    Given a dictionary, lookup the given key, if it doesn't exist create a new array.
    Then check if the given value already exists in the array, if it doesn't add it.
    """
    if key not in obj:
        obj[key] = []
    if value not in obj[key]:
        obj[key].append(value)


def generate(
    streams: Generator[io.IOBase], output_path: Path | None = None, filename_format: str = "{kind}-{group}-{version}"
):
    schemas: list[Schema] = []
    if output_path is None:
        output_path = Path.cwd()

    output_path.mkdir(parents=True, exist_ok=True)

    for stream in streams:
        for y in yaml.safe_load_all(stream):
            if y is None or "kind" not in y:
                continue
            if y["kind"] != "CustomResourceDefinition":
                continue

            if "spec" in y and "validation" in y["spec"] and "openAPIV3Schema" in y["spec"]["validation"]:
                schemas.append(
                    Schema(
                        kind=y["spec"]["names"]["kind"],
                        group=y["spec"]["group"],
                        version=y["spec"]["version"],
                        definition=y["spec"]["validation"]["openAPIV3Schema"],
                    )
                )

            elif "spec" in y and "versions" in y["spec"]:
                for version in y["spec"]["versions"]:
                    if "schema" in version and "openAPIV3Schema" in version["schema"]:
                        schemas.append(
                            Schema(
                                kind=y["spec"]["names"]["kind"],
                                group=y["spec"]["group"],
                                version=version["name"],
                                definition=version["schema"]["openAPIV3Schema"],
                            )
                        )

    # Write down all separate schema files.
    for schema in schemas:
        filename = output_path / (
            filename_format.format(
                kind=schema.kind,
                group=schema.group.split(".")[0],
                version=schema.version,
            ).lower()
            + ".json"
        )

        schema = additional_properties(schema.definition)
        schema = replace_int_or_string(schema)

        # Dealing with user input here..
        with filename.open("w") as file:
            file.write(json.dumps(schema, indent=2))
            logger.debug(f"Generating file {filename}")

    # Make a single definitions file that has the enum field set for kind and apiVersion so we can have automatic matching
    # for JSON schema.
    with (output_path / "_definitions.json").open("w") as definitions_file:
        definitions: dict[str, dict[Any, Any]] = {}

        # NOTE: No deep copy is needed as we already wrote the schema files, so let's modify the original structures.
        for schema in schemas:
            append_no_duplicates(
                schema.definition["properties"]["apiVersion"], "enum", f"{schema.group}/{schema.version}"
            )
            append_no_duplicates(schema.definition["properties"]["kind"], "enum", schema.kind)

            # Sometimes it happens that metadata field is not "allowed" in a schema which obviously is a mistake!
            # TODO: Can we really not reference the "internal" type io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta? Specifically,
            # we need to not specify the scheme here as then we are locking this to a version...
            if "metadata" not in schema.definition["properties"]:
                schema.definition["properties"]["metadata"] = {"type": "object"}

            definitions[f"{schema.group}.{schema.version}.{schema.kind}"] = schema.definition

        definitions_file.write(json.dumps({"definitions": definitions}, indent=2))

    # Finally we write the main schema file that can be used to automatically validate any Flux2 schema using oneOf
    # semantics.
    with (output_path / "all.json").open("w") as all_file:
        refs = [
            {"$ref": f"_definitions.json#/definitions/{schema.group}.{schema.version}.{schema.kind}"}
            for schema in schemas
        ]
        all_file.write(json.dumps({"oneOf": refs}, indent=2))


class CrdRepository:
    def __init__(
        self,
        owner: str,
        name: str,
        git_url: str,
        crd_globs: str | list[str] | None,
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
            remote.name.lstrip("refs/tags/"): remote.name
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
        async with httpx.AsyncClient(follow_redirects=True, transport=RetryTransport()) as client:
            urls = self.get_crd_urls(ref)
            if isinstance(urls, str):
                urls = [urls]

            responses = await asyncio.gather(*[client.get(url) for url in urls])

            if len(responses) <= 0:
                logger.warning(f"No CRDs found for {self.owner}/{self.name} ref {ref} from url {','.join(urls)}")
                return

            def get_url_crd_streams():
                for response in responses:
                    yield io.BufferedReader(IterStream(response.iter_bytes(buffer_size)), buffer_size=buffer_size)

            generate(get_url_crd_streams(), **kwargs)

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

        generate(get_crd_streams(), **kwargs)


class HelmCrdRepository(CrdRepository):
    def __init__(self, repository_url: str, *args, **kwargs) -> None:
        self.repository_url = repository_url
        super().__init__(*args, **kwargs)

    async def get_refs(self):
        remotes = await super().get_refs()

        async with httpx.AsyncClient(follow_redirects=True, transport=RetryTransport()) as client:
            r = await client.get(self.repository_url)
            r.raise_for_status()
            index = yaml.safe_load(r.text)

            helm_versions = [
                f"v{entry['version'].lstrip('v')}"
                for entry in cast(list[dict[Any, Any]], index.get("entries", []).get(self.name, []))
                if "version" in entry
            ]

            return {version: remote for version, remote in remotes.items() if version in helm_versions}


repositories: list[CrdRepository] = [
    HelmCrdRepository(
        "https://pkgs.tailscale.com/helmcharts/index.yaml",
        "tailscale",
        "tailscale-operator",
        "https://github.com/tailscale/tailscale.git",
        "cmd/k8s-operator/deploy/crds/*.y*ml",
        exclude_tag_regex=r"v1.56.[0-1]$",  # These initial versions did not had CRDs
    ),
    CrdRepository(
        "mariadb-operator",
        "mariadb-operator",
        "https://github.com/mariadb-operator/mariadb-operator.git",
        "deploy/crds/*.y*ml",
        exclude_tag_regex=r"v0\.0\.[0-4]$",  # Old versions
    ),
    CrdRepository(
        "mittwald",
        "kubernetes-secret-generator",
        "https://github.com/mittwald/kubernetes-secret-generator.git",
        "deploy/crds/*.y*ml",
        # Before 3.3.3 (until 3.3.2) there was no CRD support so lets only start from v3.4 (to make the regex easier...)
        exclude_tag_regex=r"(v[0-2]\..*?\..*?|v3\.[0-3]\.[0-9]+?)$",
    ),
    CrdRepository(
        "zalando",
        "postgres-operator",
        "https://github.com/zalando/postgres-operator.git",
        "manifests/*.crd.y*ml",
        exclude_tag_regex=r"v1\.[0-2]\.0$",  # These initial versions had CRDs only within templates
    ),
    CrdRepository(
        "longhorn",
        "longhorn",
        "https://github.com/longhorn/longhorn.git",
        None,
        get_crd_urls=lambda ref: f"https://github.com/longhorn/longhorn/releases/download/{ref.lstrip('ref/tags/')}/longhorn.yaml",
        exclude_tag_regex=r"v0\.[0-9]{1,}\.[0-9]{1,}$",
    ),
    CrdRepository(
        "cert-manager",
        "cert-manager",
        "https://github.com/cert-manager/cert-manager.git",
        None,
        get_crd_urls=lambda ref: f"https://github.com/cert-manager/cert-manager/releases/download/{ref.lstrip('ref/tags/')}/cert-manager.crds.yaml",
        exclude_tag_regex=r"v0\.[0-9]{1,}\.[0-9]{1,}$",
    ),
    CrdRepository(
        "kyverno",
        "kyverno",
        "https://github.com/kyverno/kyverno.git",
        "config/crds/**/*.y*ml",
        exclude_tag_regex=r"(v0\.|v1\.[0-5]\.)",  # Ignore old versions that did not had config files in the above glob.
    ),
]


async def pull():
    async with asyncio.TaskGroup() as tg:
        for repository in repositories:
            for version, ref in (await repository.get_refs()).items():
                path = Path("schemas") / repository.owner / repository.name / version
                if not path.exists():
                    logger.info(f"Retrieving {repository.owner}/{repository.name} {version} via {ref}")

                    if repository.crd_globs is not None:
                        tg.create_task(
                            asyncio.to_thread(repository.generate_json_schema_from_globs, ref, output_path=path)
                        )
                    elif repository.get_crd_urls is not None:
                        tg.create_task(repository.generate_json_schema_from_urls(ref, output_path=path))
                    else:
                        raise RuntimeError("Either crd_globs OR get_crd_urls has to be provided")


if __name__ == "__main__":
    asyncio.run(pull())
