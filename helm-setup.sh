#!/bin/bash

SERVICE_NAME="$1"
NAMESPACE="$2"
SERVICE_PORT="$3"

if [ -z "$SERVICE_NAME" ] || [ -z "$NAMESPACE" ] || [ -z "$SERVICE_PORT" ]; then
  echo "❌ 사용법: ./helm-setup.sh [서비스이름] [네임스페이스] [Spring포트]"
  exit 1
fi

# ----------------------------
# create-service-structure.sh
# ----------------------------
cat > create-service-structure.sh <<'EOS'
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
EOS

# ----------------------------
# create-external-secret-chart.sh
# ----------------------------
cat > create-external-secret-chart.sh <<'EOS'
#!/bin/bash
SERVICE_NAME="$1"
NAMESPACE="$2"
CHART_DIR="k8s/external-secret-chart"
mkdir -p "$CHART_DIR/templates"

cat > "$CHART_DIR/Chart.yaml" <<EOF
apiVersion: v2
name: external-secret-chart
description: Helm Chart for ExternalSecret-based config/secret injection
version: 0.1.0
appVersion: "1.0"
EOF

cat > "$CHART_DIR/values.yaml" <<EOF
serviceName: $SERVICE_NAME
namespace: $NAMESPACE

secrets:
  - SPRING_PROFILES_ACTIVE
  - SPRING_SERVER_PORT
  - S3_FRONTEND_ORIGIN
  - KAFKA_BOOTSTRAP_SERVERS
  - KAFKA_SCHEMA_REGISTRY_SERVER

secureSecrets:
  - MONGODB_URI
  - MYSQL_HOST
  - MYSQL_PORT
  - MYSQL_DB_NAME
  - MONGO_DB_NAME
  - MYSQL_USER
  - MYSQL_PASSWORD
  - IMGBB_API_KEY
EOF

cat > "$CHART_DIR/templates/configmap-secret.yaml" <<'EOF'
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ .Values.serviceName }}-config
  namespace: {{ .Values.namespace }}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets
    kind: ClusterSecretStore
  target:
    name: {{ .Values.serviceName }}-config
    creationPolicy: Owner
  data:
  {{- range .Values.secrets }}
    - secretKey: {{ . }}
      remoteRef:
        key: {{ $.Values.serviceName }}/config
        property: {{ . }}
  {{- end }}
EOF

cat > "$CHART_DIR/templates/secret-secret.yaml" <<'EOF'
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ .Values.serviceName }}-secret
  namespace: {{ .Values.namespace }}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets
    kind: ClusterSecretStore
  target:
    name: {{ .Values.serviceName }}-secret
    creationPolicy: Owner
  data:
  {{- range .Values.secureSecrets }}
    - secretKey: {{ . }}
      remoteRef:
        key: {{ $.Values.serviceName }}/secret
        property: {{ . }}
  {{- end }}
EOF
EOS

# 권한 부여
chmod +x create-service-structure.sh
chmod +x create-external-secret-chart.sh

# 실행
./create-service-structure.sh "$SERVICE_NAME" "$NAMESPACE" "$SERVICE_PORT"
./create-external-secret-chart.sh "$SERVICE_NAME" "$NAMESPACE"
