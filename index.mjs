import crypto from "crypto";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const REGION = process.env.AWS_REGION;
const FRONTEND = process.env.FRONTEND_ORIGIN || "https://uploads.avacompli.com";
const BUCKET = process.env.S3_BUCKET;
const UPLOAD_ROLE_ARN = process.env.UPLOAD_ROLE_ARN;
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || ".avacompli.com";
const JWT_SECRET = process.env.JWT_SECRET;

const s3 = new S3Client({ region: REGION });
const sts = new STSClient({ region: REGION });

// Bootstrap demo users
const users = new Map();
(function seedUsers() {
  const seed = process.env.ADMIN_BOOTSTRAP || "";
  seed
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const [clientId, pw] = pair.split(":");
      users.set(clientId.toLowerCase(), {
        clientId: clientId.toLowerCase(),
        password: pw,
        displayName: clientId,
      });
    });
})();

function signToken(payload, hours = 8) {
  const exp = Date.now() + hours * 60 * 60 * 1000;
  const body = Buffer.from(JSON.stringify({ ...payload, exp })).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [body, sig] = token.split(".");
  const expect = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  if (sig !== expect) return null;
  const data = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  if (Date.now() > data.exp) return null;
  return data;
}

function response(status, body, extraHeaders = {}) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": FRONTEND,
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Headers": "Content-Type,Authorization",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

function parseJson(body) {
  try {
    return JSON.parse(body || "{}");
  } catch {
    return {};
  }
}

function getAuthToken(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  const cookie = event.headers?.cookie || event.headers?.Cookie || "";
  const match = cookie.match(/session=([^;]+)/);
  return match ? match[1] : null;
}

function safeExt(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ["pdf", "docx", "doc"].includes(ext) ? "." + ext : "";
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function sessionPolicyForClient(clientId) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ListForPrefix",
        Effect: "Allow",
        Action: ["s3:ListBucket", "s3:ListBucketMultipartUploads"],
        Resource: `arn:aws:s3:::${BUCKET}`,
        Condition: { StringLike: { "s3:prefix": [`clients/${clientId}/incoming/*`] } },
      },
      {
        Sid: "PutToPrefix",
        Effect: "Allow",
        Action: ["s3:PutObject", "s3:AbortMultipartUpload"],
        Resource: `arn:aws:s3:::${BUCKET}/clients/${clientId}/incoming/*`,
      },
    ],
  };
}

async function handleLogin(event) {
  console.log("📥 Incoming /api/login event:", JSON.stringify(event, null, 2));

  const { clientId, password } = parseJson(event.body);
  if (!clientId || !password) return response(400, { error: "clientId and password required" });
  const user = users.get(clientId.toLowerCase());
  if (!user || user.password !== password) return response(401, { error: "Invalid credentials" });

  const token = signToken({ clientId: user.clientId, displayName: user.displayName }, 8);
  const cookie = [
    `session=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=None",
    `Domain=${COOKIE_DOMAIN}`,
    "Path=/",
    "Max-Age=28800",
  ].join("; ");
  return response(
    200,
    { token, clientId: user.clientId, displayName: user.displayName },
    { "Set-Cookie": cookie }
  );
}

async function handleUploadToken(event, user) {
  console.log("📥 Incoming /api/upload-token event:", JSON.stringify(event, null, 2));

  const { originalName } = parseJson(event.body);
  const base = (originalName || "document").toString();
  const ext = safeExt(base);
  const key = `clients/${user.clientId}/incoming/${today()}-${crypto.randomUUID()}${ext}`;

  await sts.send(
    new AssumeRoleCommand({
      RoleArn: UPLOAD_ROLE_ARN,
      RoleSessionName: `upload-${user.clientId}`,
      ExternalId: "avacompli-upload",
      Policy: JSON.stringify(sessionPolicyForClient(user.clientId)),
      DurationSeconds: 900,
    })
  );

  const presignedUrl = await getSignedUrl(
    s3,
    new PutObjectCommand({
      Bucket: BUCKET,
      Key: key,
      Metadata: { "original-filename": base, "client-id": user.clientId },
    }),
    { expiresIn: 900 }
  );

  return response(200, { bucket: BUCKET, key, region: REGION, presignedUrl });
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") {
    return response(200, { ok: true });
  }
  const route = `${event.requestContext?.http?.method} ${event.requestContext?.http?.path}`;
  if (route === "POST /api/login") {
    return handleLogin(event);
  }
  if (route === "POST /api/upload-token") {
    const token = getAuthToken(event);
    const data = verifyToken(token);
    if (!data) return response(401, { error: "Unauthorized" });
    return handleUploadToken(event, data);
  }
  return response(404, { error: "Not found" });
};
