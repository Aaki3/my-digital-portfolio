import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";
import arcjet, { detectBot, shield, tokenBucket } from "@arcjet/next";

// ------------- Clerk Setup -------------
const isProtectedRoute = createRouteMatcher([
  '/admin',
  '/resources(.*)',
  '/projects',
]);

const clerkHandler = clerkMiddleware(async (auth, req) => {
  if (isProtectedRoute(req)) {
    await auth.protect();
  }
});

// ------------- Arcjet Setup -------------
const aj = arcjet({
  key: process.env.ARCJET_KEY!,
  characteristics: ["ip.src"],
  rules: [
    shield({ mode: "LIVE" }),
    detectBot({
      mode: "LIVE",
      allow: [
        "CATEGORY:SEARCH_ENGINE", // Allow Google, Bing, etc.
        "CATEGORY:MONITOR",        // (optional) Allow uptime bots like Pingdom
        "CATEGORY:PREVIEW",        // (optional) Allow Slack, Discord previews
      ],
    }),
    tokenBucket({ mode: "LIVE", refillRate: 5, interval: 10, capacity: 10 }),
  ],
});

// ------------- Combined Middleware -------------
export async function middleware(req: Request) {
  // 1. Arcjet protection
  const decision = await aj.protect(req, { requested: 1 });

  if (decision.isDenied()) {
    return new NextResponse(JSON.stringify({
      error: "Access Denied",
      reason: decision.reason,
    }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  }

  // 2. Clerk authentication
  return clerkHandler(req);
}

// ------------- Match Config -------------
export const config = {
  matcher: [
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/(api|trpc)(.*)',
  ],
};
