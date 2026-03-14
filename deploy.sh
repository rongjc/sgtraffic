#!/usr/bin/env bash
# Deploy APK Scanner to Google Cloud Run
# Usage: ./deploy.sh <PROJECT_ID> <REGION>
# Example: ./deploy.sh my-gcp-project us-central1

set -euo pipefail

PROJECT_ID="${1:?Usage: ./deploy.sh <PROJECT_ID> <REGION>}"
REGION="${2:?Usage: ./deploy.sh <PROJECT_ID> <REGION>}"
REPO="$REGION-docker.pkg.dev/$PROJECT_ID/apk-scanner"

echo "==> Configuring project: $PROJECT_ID  region: $REGION"
gcloud config set project "$PROJECT_ID"

# 1. Create Artifact Registry repo (idempotent)
gcloud artifacts repositories create apk-scanner \
  --repository-format=docker \
  --location="$REGION" \
  --quiet 2>/dev/null || true

# 2. Authenticate Docker
gcloud auth configure-docker "$REGION-docker.pkg.dev" --quiet

# 3. Build & push images
echo "==> Building and pushing API image..."
docker build -t "$REPO/api:latest" -f packages/api/Dockerfile .
docker push "$REPO/api:latest"

echo "==> Building and pushing Analyzer image..."
docker build -t "$REPO/analyzer:latest" packages/analyzer/
docker push "$REPO/analyzer:latest"

echo "==> Building and pushing Web image..."
docker build -t "$REPO/web:latest" -f packages/web/Dockerfile .
docker push "$REPO/web:latest"

# 4. Create the MONGODB_URI secret (skip if already exists)
echo "==> Setting up secrets..."
if ! gcloud secrets describe apk-scanner-secrets --project="$PROJECT_ID" &>/dev/null; then
  echo "  Creating secret apk-scanner-secrets..."
  echo -n "${MONGODB_URI:?Set MONGODB_URI env var before deploying}" | \
    gcloud secrets create apk-scanner-secrets \
      --data-file=- \
      --replication-policy=automatic
  # Store as a key in the secret — for the YAML's secretKeyRef we use a single-value secret
  # Alternatively, store per key; adjust cloud-run.yaml accordingly.
else
  echo "  Secret already exists — update manually if needed."
fi

# 5. Deploy API + Analyzer (multi-container) to Cloud Run
echo "==> Deploying API + Analyzer to Cloud Run..."
sed "s|REGION|$REGION|g; s|PROJECT_ID|$PROJECT_ID|g" cloud-run.yaml | \
  gcloud run services replace - --region="$REGION"

gcloud run services add-iam-policy-binding apk-scanner \
  --region="$REGION" \
  --member="allUsers" \
  --role="roles/run.invoker" 2>/dev/null || true

# 6. Deploy Web frontend as a separate Cloud Run service
echo "==> Deploying Web frontend..."
API_URL=$(gcloud run services describe apk-scanner --region="$REGION" --format="value(status.url)")
gcloud run deploy apk-scanner-web \
  --image="$REPO/web:latest" \
  --region="$REGION" \
  --platform=managed \
  --allow-unauthenticated \
  --set-env-vars="API_URL=$API_URL"

WEB_URL=$(gcloud run services describe apk-scanner-web --region="$REGION" --format="value(status.url)")
echo ""
echo "==> Deployment complete!"
echo "    API:     $API_URL"
echo "    Web UI:  $WEB_URL"
