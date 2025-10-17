from pathlib import Path
import asyncio
from crd_json_schema.repository import HelmCrdRepository, CrdRepository
from crd_json_schema.main import generate


if __name__ == "__main__":
    asyncio.run(
        generate(
            Path("schemas"),
            HelmCrdRepository(
                "https://pkgs.tailscale.com/helmcharts/index.yaml",
                "tailscale",
                "tailscale-operator",
                "https://github.com/tailscale/tailscale.git",
                ("cmd/k8s-operator/deploy/crds/*.yaml", "cmd/k8s-operator/deploy/crds/*.yml"),
                exclude_tag_regex=r"v1.56.[0-1]$",  # These initial versions did not had CRDs
            ),
            CrdRepository(
                "fluxcd",
                "flux2",
                "https://github.com/fluxcd/flux2.git",
                None,
                get_crd_urls=lambda ref: f"https://github.com/fluxcd/flux2/releases/download/{ref.lstrip('ref/tags/')}/install.yaml",
                exclude_tag_regex=r"v0\.[0-4]\.",  # These initial versions did not had the install.yaml bundle
            ),
            CrdRepository(
                "mariadb-operator",
                "mariadb-operator",
                "https://github.com/mariadb-operator/mariadb-operator.git",
                ("deploy/crds/*.yaml", "deploy/crds/*.yml"),
                exclude_tag_regex=r"v0\.0\.[0-4]$",  # Old versions
            ),
            CrdRepository(
                "mittwald",
                "kubernetes-secret-generator",
                "https://github.com/mittwald/kubernetes-secret-generator.git",
                ("deploy/crds/*.yaml", "deploy/crds/*.yml"),
                # Before 3.3.3 (until 3.3.2) there was no CRD support so lets only start from v3.4 (to make the regex easier...)
                exclude_tag_regex=r"(v[0-2]\..*?\..*?|v3\.[0-3]\.[0-9]+?)$",
            ),
            CrdRepository(
                "zalando",
                "postgres-operator",
                "https://github.com/zalando/postgres-operator.git",
                ("charts/postgres-operator/crds/*.yaml", "charts/postgres-operator/crds/*.yml"),
                exclude_tag_regex=r"v1\.[0-2]\.0$",  # These initial versions had CRDs only within templates
            ),
            CrdRepository(
                "cilium",
                "cilium",
                "https://github.com/cilium/cilium.git",
                ("pkg/k8s/apis/cilium.io/client/crds/**/*.yaml", "pkg/k8s/apis/cilium.io/client/crds/**/*.yml"),
                exclude_tag_regex=r"(v0\.|v1\.[0-9]\.)",  # Skip old version with different location CRD
            ),
            CrdRepository(
                "longhorn",
                "longhorn",
                "https://github.com/longhorn/longhorn.git",
                None,
                get_crd_urls=lambda ref: f"https://github.com/longhorn/longhorn/releases/download/{ref.lstrip('ref/tags/')}/longhorn.yaml",
                exclude_tag_regex=r"v0\.[0-9]{1,}\.[0-9]{1,}$",
            ),
            HelmCrdRepository(
                "https://charts.jetstack.io/index.yaml",
                "cert-manager",
                "cert-manager",
                "https://github.com/cert-manager/cert-manager.git",
                None,
                get_crd_urls=lambda ref: f"https://github.com/cert-manager/cert-manager/releases/download/{ref.lstrip('ref/tags/')}/cert-manager.crds.yaml",
                exclude_tag_regex=r"v0\.[0-9]{1,}\.[0-9]{1,}$",
            ),
            HelmCrdRepository(
                "https://kyverno.github.io/kyverno/index.yaml",
                "kyverno",
                "kyverno",
                "https://github.com/kyverno/kyverno.git",
                ("config/crds/**/*.yaml", "config/crds/**/*.yml"),
                use_app_version_for_git_tag=True,
                exclude_tag_regex=r"(v0\.|v1\.[0-5]\.)",  # Ignore old versions that did not had config files in the above glob.
            ),
        )
    )
