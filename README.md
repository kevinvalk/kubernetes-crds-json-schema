# JSON Schemas for Kubernetes CRDs

Collection of JSON Schemas that allow for validation of CRDs via JSON Schema right within your editor.

**These are nightly updated with new versions!**

## Usage

Create your collection file as **json-schema-kubernetes-with-crds.json**
```json
{
  "oneOf": [
    {
      "$ref": "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/v1.33.5-standalone-strict/all.json"
    },
    {
      "$ref": "https://raw.githubusercontent.com/fluxcd-community/flux2-schemas/main/all.json"
    },
    {
      "$ref": "https://raw.githubusercontent.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/mariadb-operator/mariadb-operator/v25.08.0/all.json?registryUrl=https://helm.mariadb.com/mariadb-operator/index.yaml&datasource=helm"
    },
    {
      "$ref": "https://raw.githubusercontent.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/longhorn/longhorn/v1.10.0/all.json?registryUrl=https://charts.longhorn.io/&datasource=helm"
    },
    {
      "$ref": "https://raw.githubusercontent.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/cert-manager/cert-manager/v1.19.1/all.json?registryUrl=https://charts.jetstack.io/&datasource=helm"
    },
    {
      "$ref": "https://raw.githubusercontent.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/tailscale/tailscale-operator/v1.88.4/all.json?registryUrl=https://pkgs.tailscale.com/helmcharts/&datasource=helm"
    },
    {
      "$ref": "https://raw.githubusercontent.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/kyverno/kyverno/v3.4.4/all.json?registryUrl=https://kyverno.github.io/kyverno/&datasource=helm"
    },
    {
      "$ref": "https://raw.githubusercontent.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/cilium/cilium/v1.18.2/all.json?registryUrl=https://helm.cilium.io/&datasource=helm"
    },
    {
      "$ref": "https://raw.githubusercontent.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/zalando/postgres-operator/v1.14.0/all.json"
    }
  ]
}
```
Now enable in VSCode or Zed via YAML extension

### VSCode
```jsonc
{
  "yaml.schemas": {
    "kubernetes": "", // We disable the default kubernetes so we control the version.
    "./json-schema-kubernetes-with-crds.json": [
      "*.yaml",
      "!kustomization.yaml",
      "!cspell.yaml",
      "!.github/**/*"
    ]
  },
}
```

### Zed
```json
{
  "lsp": {
    "yaml-language-server": {
      "settings": {
        "yaml": {
          "schemas": {
            "kubernetes": "", // We disable the default kubernetes so we control the version.
            // IMPORTANT: Significant bug as reported in https://github.com/zed-industries/zed/issues/30938
            "./json-schema-kubernetes-with-crds.json": [
              "*.yaml",
              "!kustomization.yaml",
              "!cspell.yaml",
              "!.github/**/*"
            ]
          }
        }
      }
    }
  }
}
```


## Renovate
If you want to also ensure your CRDs are in sync with your actual deployed versions you can use a custom regex manager for renovate like so
```jsonc
{
  // ...
  "customManagers": [
    {
      // We want to also update and keep in sync our JSON Schemas with our actual packages usage.
      "customType": "regex",
      "managerFilePatterns": ["/(?:^|/)json-schema-kubernetes-with-crds\\.json$/"],
      "matchStrings": [
        "https://raw\\.githubusercontent\\.com/kevinvalk/kubernetes-crds-json-schema/refs/heads/main/schemas/(?<owner>[^/]+)/(?<depName>[^/]+)/(?<currentValue>v?[^/]+)/[^?\"]*\\??(?:(?:datasource=(?<datasource>[^&\"]+)|registryUrl=(?<registryUrl>[^&\"]+)|[^=&\"]+=[^&\"]+)&?)*"
      ],
      "packageNameTemplate": "{{# unless registryUrl }}{{{ owner }}}/{{/ unless }}{{{ depName }}}",
      "datasourceTemplate": "{{# if datasource }}{{{ datasource }}}{{ else }}github-releases{{/ if }}"
    }
  ]
}
```

## TODO

- To support Flux2 we need to have a way to unpack the get_crd_urls as in Flux2 they are released as `crd-schemas.tar.gz`
