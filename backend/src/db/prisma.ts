import { PrismaClient } from "../generated/client";

declare global {
  // eslint-disable-next-line no-var
  var __anydashPrisma: PrismaClient | undefined;
}

const prismaClient = globalThis.__anydashPrisma ?? new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalThis.__anydashPrisma = prismaClient;
}

export { prismaClient as prisma };
