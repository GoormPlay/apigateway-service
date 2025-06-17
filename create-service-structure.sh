#!/bin/bash
SERVICE_NAME="$1"
NAMESPACE="$2"
SERVICE_PORT="$3"

mkdir -p "k8s/helm/base"
mkdir -p "k8s/external-secret"
mkdir -p "k8s/argocd"

cat > "k8s/helm/values.yaml" <<EOF
image:
  repository: roin09/$SERVICE_NAME
  tag: latest

service:
  port: 80
  targetPort: $SERVICE_PORT

env:
  useConfigMap: true
  useSecret: true
EOF

cat > "k8s/helm/Chart.yaml" <<EOF
apiVersion: v2
name: $SERVICE_NAME
version: 0.1.0
dependencies:
  - name: base-template
    version: 0.1.0
    repository: "file://./base"
EOF

cat > "k8s/argocd/application.yaml" <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: $SERVICE_NAME
spec:
  project: default
  source:
    repoURL: https://github.com/GoormPlay/$SERVICE_NAME.git
    targetRevision: deploy
    path: helm
  destination:
    server: https://kubernetes.default.svc
    namespace: $NAMESPACE
  syncPolicy:
    automated:
      selfHeal: true
      prune: true
EOF
