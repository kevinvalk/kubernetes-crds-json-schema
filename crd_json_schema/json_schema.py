from typing import Any, Generator
import logging
import yaml

import io
from pathlib import Path
import json
from dataclasses import dataclass


logger = logging.getLogger(__name__)


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
