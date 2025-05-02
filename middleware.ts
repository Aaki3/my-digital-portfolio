import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextResponse, NextRequest } from "next/server";

// Only import Arcjet dynamically (lazy) to avoid running it in dev.
const isProd = process.env.NODE_ENV === "production";

const isProtectedRoute = createRouteMatcher([
  "/admin",
  "/resources(.*)",
  "/projects",
]);

const customMiddleware = clerkMiddleware(async (authPromise, req: NextRequest) => {
  // Clerk protection
  const auth = await authPromise;
  if (isProtectedRoute(req)) {
    await auth.protect();
  }

  // Arcjet protection (only in production)
  if (isProd) {
    try {
      const arcjet = (await import("@arcjet/next")).default;
      const { shield, detectBot, tokenBucket } = await import("@arcjet/next");

      const aj = arcjet({
        key: process.env.ARCJET_KEY!,
        characteristics: ["ip.src"],
        rules: [
          shield({ mode: "LIVE" }),
          detectBot({
            mode: "LIVE",
            allow: ["CATEGORY:SEARCH_ENGINE", "CATEGORY:MONITOR", "CATEGORY:PREVIEW"],
          }),
          tokenBucket({ mode: "LIVE", refillRate: 5, interval: 10, capacity: 10 }),
        ],
      });

      const decision = await aj.protect(req);

      if (decision.isDenied()) {
        return NextResponse.json(
          { error: "Access Denied", reason: decision.reason },
          { status: 403 }
        );
      }
    } catch (error) {
      console.warn("Arcjet error:", error);
      // fail-safe: let request continue
    }
  }
});

export const middleware = customMiddleware;

export const config = {
  matcher: [
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)",
  ],
};
