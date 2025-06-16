#!/bin/bash

SERVICE_NAME="$1"
NAMESPACE="$2"
SERVICE_PORT="$3"

if [ -z "$SERVICE_NAME" ] || [ -z "$NAMESPACE" ] || [ -z "$SERVICE_PORT" ]; then
  echo "❌ 사용법: ./gnr-helm.sh [서비스이름] [네임스페이스] [Spring포트]"
  exit 1
fi

CHART_DIR="helm-charts/$SERVICE_NAME"
mkdir -p "$CHART_DIR/templates"

# Chart.yaml
cat > "$CHART_DIR/Chart.yaml" <<EOF
apiVersion: v2
name: $SERVICE_NAME
description: A Helm chart for $SERVICE_NAME
version: 0.1.0
appVersion: "1.0"
EOF

# values.yaml
cat > "$CHART_DIR/values.yaml" <<EOF
replicaCount: 1

image:
  repository: roin09/$SERVICE_NAME
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 80
  targetPort: $SERVICE_PORT

config:
  SPRING_PROFILES_ACTIVE: prod
  SPRING_SERVER_PORT: "$SERVICE_PORT"
  EUREKA_URL: http://eureka-service.eureka.svc.cluster.local:8761/eureka
  S3_FRONTEND_ORIGIN: http://goorm-front.s3-website.ap-northeast-2.amazonaws.com
  KAFKA_BOOTSTRAP_SERVERS: 43.201.43.88:9092, 15.165.234.219:9092, 15.165.234.219:9092
  KAFKA_SCHEMA_REGISTRY_SERVER: 3.38.204.173:8081

resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 300m
    memory: 512Mi

hpa:
  enabled: true
  minReplicas: 1
  maxReplicas: 5
  targetCPUUtilizationPercentage: 70

topologySpreadConstraints:
  enabled: true
  maxSkew: 1
  topologyKey: topology.kubernetes.io/zone

podAntiAffinity:
  enabled: true

useSecret: false
EOF

# deployment.yaml
cat > "$CHART_DIR/templates/deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Release.Namespace }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Chart.Name }}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: {{ .Chart.Name }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: {{ .Values.service.targetPort }}
          envFrom:
            - configMapRef:
                name: {{ .Chart.Name }}-config
          {{- if .Values.useSecret }}
            - secretRef:
                name: {{ .Chart.Name }}-secret
          {{- end }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
      {{- if .Values.topologySpreadConstraints.enabled }}
      topologySpreadConstraints:
        - maxSkew: {{ .Values.topologySpreadConstraints.maxSkew }}
          topologyKey: {{ .Values.topologySpreadConstraints.topologyKey }}
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: {{ .Chart.Name }}
      {{- end }}
      {{- if .Values.podAntiAffinity.enabled }}
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                topologyKey: "kubernetes.io/hostname"
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - {{ .Chart.Name }}
      {{- end }}
EOF

# service.yaml
cat > "$CHART_DIR/templates/service.yaml" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Release.Namespace }}
spec:
  type: {{ .Values.service.type }}
  selector:
    app: {{ .Chart.Name }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: {{ .Values.service.targetPort }}
      protocol: TCP
EOF

# configmap.yaml
cat > "$CHART_DIR/templates/configmap.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Chart.Name }}-config
  namespace: {{ .Release.Namespace }}
data:
  SPRING_PROFILES_ACTIVE: {{ .Values.config.SPRING_PROFILES_ACTIVE | quote }}
  SPRING_SERVER_PORT: {{ .Values.config.SPRING_SERVER_PORT | quote }}
  EUREKA_URL: {{ .Values.config.EUREKA_URL | quote }}
  S3_FRONTEND_ORIGIN: {{ .Values.config.S3_FRONTEND_ORIGIN | quote }}
  KAFKA_BOOTSTRAP_SERVERS: {{ .Values.config.KAFKA_BOOTSTRAP_SERVERS | quote }}
  KAFKA_SCHEMA_REGISTRY_SERVER: {{ .Values.config.KAFKA_SCHEMA_REGISTRY_SERVER | quote }}
EOF

# hpa.yaml
cat > "$CHART_DIR/templates/hpa.yaml" <<EOF
{{- if .Values.hpa.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ .Chart.Name }}-hpa
  namespace: {{ .Release.Namespace }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ .Chart.Name }}
  minReplicas: {{ .Values.hpa.minReplicas }}
  maxReplicas: {{ .Values.hpa.maxReplicas }}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .Values.hpa.targetCPUUtilizationPercentage }}
{{- end }}
EOF

echo "✅ Helm Chart 생성 완료: $CHART_DIR"
