Schöne Befehle

```Shell
kubectl get secret sh.helm.release.v1.demo.v2 -n threetier -o jsonpath='{.data.release}' | base64 -d | base64 -d | gzip -d | python3 -m json.tool
```
