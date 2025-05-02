import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextRequest } from "next/server";

const isProtectedRoute = createRouteMatcher([
  "/admin",
  "/resources(.*)",
  "/projects",
]);

const customMiddleware = clerkMiddleware(async (authPromise, req: NextRequest) => {
  const auth = await authPromise;

  if (isProtectedRoute(req)) {
    await auth.protect(); // Only Clerk logic here
  }

  // ❌ REMOVE Arcjet logic from middleware — causes WASM errors!
});

export const middleware = customMiddleware;

export const config = {
  matcher: [
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)",
  ],
};
