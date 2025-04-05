# JSON Schemas for Kubernetes CRDs

First version of this repository to start building a repository that can be used to have JSON Schema validation of custom Kubernetes resources

```json
{
  "oneOf": [
    {
      "$ref": "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/v1.31.6-standalone-strict/all.json"
    },
    {
      "$ref": "https://raw.githubusercontent.com/fluxcd-community/flux2-schemas/main/all.json"
    }
  ]
}
```
