import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";
import arcjet, { detectBot, shield, tokenBucket } from "@arcjet/next";
import { get } from "@vercel/edge-config";

// Clerk route protection
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

export async function middleware(req: Request) {
  let arcjetKey: string | undefined;

  // Check if we're in production (Vercel)
  if (process.env.VERCEL) {
    arcjetKey = await get('ARCJET_KEY');
  } else {
    // Fallback for localhost using .env
    arcjetKey = process.env.ARCJET_KEY;
  }

  if (!arcjetKey) {
    return new NextResponse(
      JSON.stringify({ error: "Missing Arcjet key" }),
      { status: 500, headers: { "content-type": "application/json" } }
    );
  }

  const aj = arcjet({
    key: arcjetKey,
    characteristics: ["ip.src"],
    rules: [
      shield({ mode: "LIVE" }),
      detectBot({
        mode: "LIVE",
        allow: [
          "CATEGORY:SEARCH_ENGINE",
          "CATEGORY:MONITOR",
          "CATEGORY:PREVIEW",
        ],
      }),
      tokenBucket({ mode: "LIVE", refillRate: 5, interval: 10, capacity: 10 }),
    ],
  });

  const decision = await aj.protect(req, { requested: 1 });

  if (decision.isDenied()) {
    return new NextResponse(
      JSON.stringify({ error: "Access Denied", reason: decision.reason }),
      { status: 403, headers: { "content-type": "application/json" } }
    );
  }

  return clerkHandler(req);
}

export const config = {
  matcher: [
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/(api|trpc)(.*)',
  ],
};
