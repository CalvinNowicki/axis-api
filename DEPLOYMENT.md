============================================================
DEPLOYMENT.md
AXIS – Deployment Playbook (API + Web)
Last updated: 2025-12-28

GOAL
	•	axis-api runs on AWS App Runner from an ECR image
	•	axis-web runs on Vercel
	•	axis-web calls axis-api directly from the browser (CORS must be correct)

⸻

SECTION A — axis-api (FastAPI) to AWS App Runner (ECR)

A0) Preconditions
	•	AWS CLI installed and working
	•	Docker Desktop installed and running
	•	You can authenticate to AWS (profile axis-stg)
	•	ECR repo exists (axis-api)
	•	App Runner service exists (axis-api)
	•	DynamoDB tables exist:
	•	axis_rings
	•	axis_trackers
	•	axis_bricks

A1) Verify AWS identity and disable pager (prevents “stuck in less”)
Commands:
export AWS_PAGER=””
aws sts get-caller-identity –profile axis-stg

A2) ECR repository info
Constants:
PROFILE=“axis-stg”
REGION=“us-west-2”
ACCOUNT_ID=“148761682818”
REPO=“axis-api”

Image URI (no tag):
IMAGE_URI=”${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPO}”

A3) Dockerfile requirements (App Runner health check + PORT)
CRITICAL: App Runner expects your container to listen on the PORT it provides.
	•	Do NOT hardcode the port.
	•	Your CMD must use ${PORT}.

Recommended CMD pattern:
CMD [“sh”, “-c”, “uvicorn app.main:app –host 0.0.0.0 –port ${PORT:-8080}”]

Notes:
	•	Local default can be 8080 (or 8000). App Runner will override with PORT.
	•	Health check path must exist. Use /health.

A4) Health check endpoint requirement
	•	Ensure FastAPI exposes GET /health returning 200 quickly.
	•	If /health is slow or missing, App Runner will fail deployment.

Local test:
curl -i http://127.0.0.1:/health

A5) Multi-arch image requirement (Mac M1 + App Runner)
CRITICAL: App Runner runs on linux/amd64. On a Mac M1 you must publish an amd64 image.
Best practice: publish a multi-arch manifest (amd64 + arm64).

Verification (after push):
docker buildx imagetools inspect “${IMAGE_URI}:vX”

You should see BOTH:
	•	Platform: linux/amd64
	•	Platform: linux/arm64

If you only see linux/arm64 (or “unknown/unknown”), App Runner can fail or behave strangely.

A6) ECR login (required before push)
Commands:
aws ecr get-login-password –profile “$PROFILE” –region “$REGION” 
| docker login –username AWS –password-stdin “${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com”

A7) Build + push (multi-arch) — the safe “known-good” approach
Recommended tag style:
TAG=“v5”  (increment each deploy)

Commands (run from ~/dev/axis-api):
export AWS_PAGER=””
PROFILE=“axis-stg”
REGION=“us-west-2”
ACCOUNT_ID=“148761682818”
REPO=“axis-api”
TAG=“vX”
IMAGE_URI=”${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPO}”

cd ~/dev/axis-api

aws ecr get-login-password –profile “$PROFILE” –region “$REGION” 
| docker login –username AWS –password-stdin “${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com”

docker buildx build 
–platform linux/amd64,linux/arm64 
-t “${IMAGE_URI}:${TAG}” 
–push 
.

docker buildx imagetools inspect “${IMAGE_URI}:${TAG}”

If Docker Desktop isn’t running, you’ll see:
	•	Cannot connect to the Docker daemon …
Fix: open Docker Desktop and wait until it’s “running”, then rerun.

A8) App Runner configuration (must match runtime)
App Runner service region:
	•	App Runner service is in us-east-1 (IMPORTANT)
	•	Image is in ECR us-west-2 (this is OK, but App Runner must have access)

App Runner settings to ensure:
	•	Port: must match the PORT your container binds to (App Runner passes PORT)
	•	If you configure App Runner port as 8080, set PORT=8080 in App Runner env vars OR ensure it uses default.
	•	Best: set App Runner service port and PORT env var consistently.
	•	Health check:
	•	Protocol: HTTP
	•	Path: /health
	•	Port: set to the same port your container uses (via PORT)
	•	Timeout/interval defaults are fine
	•	Observability:
	•	Enable App Runner logs (CloudWatch group exists at /aws/apprunner/…)

A9) Required environment variables in App Runner (axis-api)
Minimum required (example values):
	•	AWS_REGION=us-west-2
	•	AXIS_AWS_REGION=us-west-2
	•	AXIS_TABLE_RINGS=axis_rings
	•	AXIS_TABLE_TRACKERS=axis_trackers
	•	AXIS_TABLE_BRICKS=axis_bricks

CORS variable (IMPORTANT):
	•	AXIS_CORS_ORIGINS must contain FRONTEND origins ONLY
Example:
https://axis-web-one.vercel.app,http://localhost:3000

DO NOT include your API domain in AXIS_CORS_ORIGINS
	•	Wrong:
https://xuy2dcpsap.us-east-1.awsapprunner.com
	•	Correct:
https://axis-web-one.vercel.app

Reason:
	•	CORS compares the browser Origin header (the website domain), not the API domain.

Also ensure your FastAPI middleware reads the correct variable name:
	•	AXIS_CORS_ORIGINS (plural)
Avoid:
	•	AXIS_CORS_ORIGIN (singular)

A10) Validate API after App Runner deploy
Find the App Runner default domain:
https://.us-east-1.awsapprunner.com

Test:
curl -i https://.us-east-1.awsapprunner.com/health

Test dashboard with a user header:
curl -s https://.us-east-1.awsapprunner.com/v1/dashboard/today 
-H “x-user-id: calvin”
echo

A11) Common failure modes and what they mean
	1.	“Health check failed … Check your configured port number”

	•	Container isn’t listening where App Runner expects.
Fix:
	•	Use CMD with ${PORT}
	•	Make App Runner port and PORT env var consistent (e.g., 8080)
	•	Confirm /health exists

	2.	“No application logs / logs never load”

	•	Often means container never started or crashed instantly.
Fix:
	•	Confirm CMD works locally with PORT set
	•	Confirm image is linux/amd64 compatible

	3.	CORS preflight blocked (no Access-Control-Allow-Origin)

	•	CORS origins configured wrong.
Fix:
	•	AXIS_CORS_ORIGINS must include Vercel domain and localhost.
	•	Do not include API domain.

	4.	App Runner can pull image but still fails health check

	•	This often indicates: app didn’t start (crash) OR bound wrong port.
Fix:
	•	Verify CMD uses ${PORT}
	•	Verify multi-arch includes linux/amd64
	•	Verify startup doesn’t depend on missing AWS creds

A12) Local container “simulate App Runner” test
Run local with PORT set (example 8080):
docker run –rm -p 8080:8080 
-e PORT=8080 
-e AWS_REGION=us-west-2 
-e AXIS_AWS_REGION=us-west-2 
-e AXIS_TABLE_RINGS=axis_rings 
-e AXIS_TABLE_TRACKERS=axis_trackers 
-e AXIS_TABLE_BRICKS=axis_bricks 
“${IMAGE_URI}:${TAG}”

Then:
curl -i http://127.0.0.1:8080/health

Note:
	•	This does NOT include App Runner IAM auth. It only verifies the container starts and listens on PORT.

⸻

SECTION B — axis-web (Next.js) to Vercel

B0) Preconditions
	•	axis-web is a Next.js app (App Router)
	•	You have Vercel CLI installed and logged in
	•	You have a Vercel project linked (created .vercel)

B1) Deploy
From ~/dev/axis-web:
vercel –prod

B2) Environment variables (Vercel)
You need:
	•	NEXT_PUBLIC_AXIS_API_BASE = https://
	•	NEXT_PUBLIC_AXIS_USER_ID = calvin   (temporary V1)

Set via CLI:
vercel env add NEXT_PUBLIC_AXIS_API_BASE production
vercel env add NEXT_PUBLIC_AXIS_USER_ID production

Then redeploy:
vercel –prod

B3) Pull env locally if needed
If you want local env to match Vercel:
vercel env pull .env.local

If prompted to overwrite .env.local, answer “y” only if you want Vercel to become your source of truth locally.

B4) Common issue: Vercel “Authentication Required” on deployed URL
This is Vercel Deployment Protection.
Fix:
	•	In Vercel project settings, disable protection for production OR configure appropriate access.
	•	If you see “Authentication Required” in curl, this is not your app; it’s Vercel protection.

B5) CORS expectations (most important)
Because axis-web fetches from the browser:
	•	The browser Origin is: https://axis-web-one.vercel.app (or whichever prod domain)
	•	axis-api must allow that origin in AXIS_CORS_ORIGINS

If the browser console shows:
	•	“blocked by CORS policy: No Access-Control-Allow-Origin”
Fix:
	•	Update AXIS_CORS_ORIGINS in App Runner to include the Vercel domain.
	•	Redeploy App Runner (or restart) if required.

⸻

SECTION C — Known-good “Full redeploy” checklist
	1.	axis-api

	•	Ensure Docker Desktop running
	•	Ensure Dockerfile uses ${PORT}
	•	Build and push multi-arch to ECR with new tag
	•	Confirm imagetools inspect shows linux/amd64
	•	Update App Runner to new image tag
	•	Confirm health check path /health
	•	Confirm App Runner env vars include:
	•	AXIS_TABLE_*
	•	AXIS_AWS_REGION
	•	AXIS_CORS_ORIGINS includes Vercel domain
	•	Test /health and /v1/dashboard/today

	2.	axis-web

	•	Ensure NEXT_PUBLIC_AXIS_API_BASE points at App Runner https domain
	•	Deploy with vercel –prod
	•	Verify browser console has no CORS errors
	•	Verify UI loads dashboard data

============================================================
END

If you want, I can also write a tiny “RELEASE.sh” script next that does:
	•	buildx multi-arch build + push
	•	prints the image tag
	•	runs imagetools inspect
	•	reminds you exactly what to paste into App Runner
