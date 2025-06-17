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
