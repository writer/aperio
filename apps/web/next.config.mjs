import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";
const connectApiBaseUrl = process.env.NEXT_PUBLIC_CONNECT_API_BASE_URL ?? "";
const isDev = process.env.NODE_ENV !== "production";

// apiProxyTarget is the upstream Go API that Next proxies /api/v1/* requests
// to in dev. The Go service emits relative URLs for report artifacts and
// other static-streaming endpoints; without this proxy those URLs would
// resolve against the Next origin (localhost:3000) and 404. Same-origin
// proxying also keeps iframes inside the page CSP (default-src 'self')
// and avoids cross-port cookie surprises.
const apiProxyTarget = (
  process.env.APERIO_API_PROXY_TARGET ||
  process.env.NEXT_PUBLIC_CONNECT_API_BASE_URL ||
  "http://localhost:4100"
).replace(/\/$/, "");
const scriptSrc = isDev
  ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
  : "script-src 'self' 'unsafe-inline'";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typedRoutes: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "base-uri 'self'",
              "frame-ancestors 'none'",
              "object-src 'none'",
              scriptSrc,
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data:",
              `connect-src 'self' ${apiBaseUrl} ${connectApiBaseUrl}`.trim()
            ].join("; ")
          },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()"
          }
        ]
      }
    ];
  },
  async rewrites() {
    // Proxy /api/v1/* to the Go API so the browser stays same-origin with
    // the Next dev server. Critical for report artifact streaming
    // (/api/v1/admin/reports/:id/{html,pdf}) where the backend emits
    // relative URLs that an iframe + <a download> need to be able to
    // navigate to from the page origin.
    return [
      {
        source: "/compliance/reports/render",
        destination: `${apiProxyTarget}/api/v1/compliance/reports/render`
      },
      {
        source: "/api/v1/:path*",
        destination: `${apiProxyTarget}/api/v1/:path*`
      }
    ];
  },
  turbopack: {
    root: path.resolve(__dirname, "../..")
  },
  transpilePackages: ["@aperio/shared"]
};

export default nextConfig;
