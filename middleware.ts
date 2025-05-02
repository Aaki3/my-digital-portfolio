import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextResponse, NextRequest } from "next/server";

const isProd = process.env.NODE_ENV === "production";

const isProtectedRoute = createRouteMatcher([
  "/admin",
  "/resources(.*)",
  "/projects",
]);

// Clerk + Arcjet Middleware combo
const customMiddleware = clerkMiddleware(async (authPromise, req: NextRequest) => {
  const auth = await authPromise;

  if (isProtectedRoute(req)) {
    await auth.protect();
  }

  // Arcjet only in production
  if (isProd) {
    try {
      const arcjet = (await import("@arcjet/next")).default;
      const { shield, detectBot, tokenBucket } = await import("@arcjet/next");

      const aj = arcjet({
        key: process.env.ARCJET_KEY!,
        allowWhenUnavailable: true, // ✅ Fallback for dev or network errors
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
      console.warn("Arcjet failed, allowing request. Reason:", error);
    }
  }
});

export const middleware = isProd ? customMiddleware : () => NextResponse.next(); // ✅ Skip in dev

export const config = {
  matcher: [
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)",
  ],
};
