import asyncio
import logging
from pathlib import Path
from crd_json_schema.repository import CrdRepository

logging.basicConfig(level=logging.INFO)
logging.getLogger("httpx").setLevel(level=logging.WARN)

logger = logging.getLogger(__name__)


async def generate(root: Path, *repositories: CrdRepository):
    async with asyncio.TaskGroup() as tg:
        for repository in repositories:
            for version, ref in (await repository.get_refs()).items():
                path = root / repository.owner / repository.name / version
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
