#!/bin/bash

SERVICE_NAME=$1
NAMESPACE=$2
SERVICE_PORT=$3

if [ -z "$SERVICE_NAME" ] || [ -z "$NAMESPACE" ] || [ -z "$SERVICE_PORT" ]; then
  echo "❌ 사용법: ./generate-k8s.sh [서비스이름] [네임스페이스] [Spring포트]"
  exit 1
fi

mkdir -p k8s

# 1. Deployment
cat > k8s/deployment.yml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $SERVICE_NAME
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: $SERVICE_NAME
  template:
    metadata:
      labels:
        app: $SERVICE_NAME
    spec:
      containers:
        - name: $SERVICE_NAME
          image: roin09/$SERVICE_NAME:latest
          ports:
            - containerPort: $SERVICE_PORT
          envFrom:
            - configMapRef:
                name: $SERVICE_NAME-config
            - secretRef:
                name: $SERVICE_NAME-secret
EOF

# 2. Service
cat > k8s/service.yml <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $SERVICE_NAME
  namespace: $NAMESPACE
spec:
  selector:
    app: $SERVICE_NAME
  ports:
    - protocol: TCP
      port: 80
      targetPort: $SERVICE_PORT
EOF

# 3. ConfigMap
cat > k8s/configmap.yml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: $SERVICE_NAME-config
  namespace: $NAMESPACE
data:
  SPRING_PROFILES_ACTIVE: prod
  SPRING_SERVER_PORT: "$SERVICE_PORT"
  EUREKA_URL: http://eureka-service.default.svc.cluster.local:8761/eureka
EOF

# 4. Secret (기본 비어 있음)
cat > k8s/secret.yml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: $SERVICE_NAME-secret
  namespace: $NAMESPACE
type: Opaque
stringData:
  MONGODB_URL: ""
  MYSQL_HOST: ""
  MYSQL_PORT: ""
  MYSQL_USER: ""
  MYSQL_PASSWORD: ""
  IMGBB_API_KEY: ""
EOF

# 5. kustomization.yml
cat > k8s/kustomization.yml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yml
  - service.yml
  - configmap.yml
  - sealed-${SERVICE_NAME}-secret.yml
EOF

echo "✅ k8s/ 폴더 생성 완료 (Spring Port: $SERVICE_PORT)"
