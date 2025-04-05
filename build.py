# Let's do some VIBE coding! I want to have an elegant Python 3.12+ script that has definitions that contain:
# - repository URL (to a Git repository)
# - main branch name
# - regex to match against tags (probably semver)
# - regex to exclude tags
# - a function or URL to "retrieve" one or multiple files from the repository. This might simple be an URL with placeholders, or can be a function that maybe does a git clone, copies some files etc.

# For all these definitions go through them in such a way that we can call the function/URL for each tag that matches the regex (and excluding the exclude regex) for each defined repository.

# Some important notes:
# - Use Python types always
# - The definitions should be easy to add and will be many
# - The to be called code I will write myself.

# Can you generate this in beaitful elegent nice Python 3.12+ code?
#
import contextlib
from typing import Any, cast, Callable, Sequence, Iterator
from pygit2.repository import Repository
import logging
import re
import httpx
import asyncio
import yaml
import io
from pathlib import Path
import json
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IterStream(io.RawIOBase):
    def __init__(self, iterator: Iterator[Any]):
        self.leftover = None
        self.iterator = iterator

    def readable(self):
        return True

    def readinto(self, b):
        try:
            l = len(b)  # We're supposed to return at most this much
            chunk = self.leftover or next(self.iterator)
            output, self.leftover = chunk[:l], chunk[l:]
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


def generate(*streams: io.IOBase, output_path: Path | None = None, filename_format: str = "{kind}-{group}-{version}"):
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
            print("{filename}".format(filename=filename))

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
            definitions[f"{schema.group}.{schema.version}.{schema.kind}"] = schema.definition

        definitions_file.write(json.dumps({"definitions": definitions}, indent=2))

    # Finally we write a flux2 main schema file that can be used to automatically validate any Flux2 schema using oneOf
    # semantics.
    with (output_path / "all.json").open("w") as all_file:
        refs = [
            {"$ref": f"_definitions.json#/definitions/{schema.group}.{schema.version}.{schema.kind}"}
            for schema in schemas
        ]
        all_file.write(json.dumps({"oneOf": refs}, indent=2))


class CrdsRepository:
    def __init__(
        self,
        name: str,
        url: str,
        get_crd_url: Callable[[str], str | Sequence[str]] | None = None,
        *,
        main_branch: str = "main",
        tag_regex: str = r"^v[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}$",
        exclude_tag_regex: str | None = None,
    ) -> None:
        self.name = name
        self.url = url
        self.get_crd_url = get_crd_url
        self.main_branch = main_branch
        self.tag_regex = re.compile(tag_regex)
        self.tag_exclude_regex = re.compile(exclude_tag_regex) if exclude_tag_regex else None

        self.git = Repository()

    def get_refs(self):
        remote = self.git.remotes.create_anonymous(self.url)

        return {
            remote["name"]: remote
            for remote in cast(
                list[dict[str, Any]],
                remote.ls_remotes(),
            )
            if remote["name"].startswith("refs/tags/")
            and self.tag_regex.match(remote["name"].lstrip("refs/tags/"))
            and (
                self.tag_exclude_regex is None or not self.tag_exclude_regex.match(remote["name"].lstrip("refs/tags/"))
            )
        }

    @contextlib.asynccontextmanager
    async def get_crds(self, ref: str, buffer_size=io.DEFAULT_BUFFER_SIZE):
        if self.get_crd_url is None:
            raise NotImplementedError(
                "You need to either extend the CrdsRepository class and implement get_crds or pass a crd_url"
            )

        async with httpx.AsyncClient(follow_redirects=True) as client:
            urls = self.get_crd_url(ref)
            if isinstance(urls, str):
                urls = [urls]

            responses = await asyncio.gather(*[client.get(url) for url in urls])

            yield [
                io.BufferedReader(IterStream(response.iter_bytes(buffer_size)), buffer_size=buffer_size)
                for response in responses
            ]

    async def generate_json_schema(self, ref: str, **kwargs):
        async with self.get_crds(ref) as files:
            generate(*files, **kwargs)


# Example usage:
repositories = [
    CrdsRepository(
        "mariadb-operator",
        "https://github.com/mariadb-operator/mariadb-operator.git",
        lambda ref: f"https://raw.githubusercontent.com/mariadb-operator/mariadb-operator/{ref}/deploy/crds/crds.yaml",
        exclude_tag_regex=r"v0\.0\.[0-4]$",
    ),
    CrdsRepository(
        "kubernetes-secret-generator",
        "https://github.com/mittwald/kubernetes-secret-generator.git",
        lambda ref: (
            f"https://raw.githubusercontent.com/mittwald/kubernetes-secret-generator/{ref}/deploy/crds/secretgenerator.mittwald.de_basicauths_crd.yaml",
            f"https://raw.githubusercontent.com/mittwald/kubernetes-secret-generator/{ref}/deploy/crds/secretgenerator.mittwald.de_sshkeypairs_crd.yaml",
            f"https://raw.githubusercontent.com/mittwald/kubernetes-secret-generator/{ref}/deploy/crds/secretgenerator.mittwald.de_stringsecrets_crd.yaml",
        ),
        # Before 3.3.3 (until 3.3.2) there was no CRD support so lets only start from v3.4 (to make the regex easier...)
        exclude_tag_regex=r"(v[0-2]\..*?\..*?|v3\.[0-3]\.[0-9]+?)$",
    ),
    CrdsRepository(
        "longhorn",
        "https://github.com/longhorn/longhorn.git",
        lambda ref: f"https://github.com/longhorn/longhorn/releases/download/{ref.lstrip('ref/tags/')}/longhorn.yaml",
        exclude_tag_regex=r"v0\.[0-9]{1,}\.[0-9]{1,}$",
    ),
    CrdsRepository(
        "cert-manager",
        "https://github.com/cert-manager/cert-manager.git",
        lambda ref: f"https://github.com/cert-manager/cert-manager/releases/download/{ref.lstrip('ref/tags/')}/cert-manager.crds.yaml",
        exclude_tag_regex=r"v0\.[0-9]{1,}\.[0-9]{1,}$",
    ),
    CrdsRepository(
        "postgres-operator",
        "https://github.com/zalando/postgres-operator",
        lambda ref: (
            f"https://raw.githubusercontent.com/zalando/postgres-operator/{ref}/charts/postgres-operator/crds/operatorconfigurations.yaml",
            f"https://raw.githubusercontent.com/zalando/postgres-operator/{ref}/charts/postgres-operator/crds/postgresqls.yaml",
            f"https://raw.githubusercontent.com/zalando/postgres-operator/{ref}/charts/postgres-operator/crds/postgresteams.yaml",
        ),
        exclude_tag_regex=r"v1\.[0-5]\.[0-9]{1,}$",
    ),
]


async def pull():
    async with asyncio.TaskGroup() as tg:
        for repository in repositories:
            for ref in repository.get_refs().keys():
                path = Path("schemas") / repository.name / ref.lstrip("refs/tags/")
                if not path.exists():
                    logger.info(f"Retrieving {repository.name} {ref}")
                    tg.create_task(repository.generate_json_schema(ref, output_path=path))


if __name__ == "__main__":
    asyncio.run(pull())
