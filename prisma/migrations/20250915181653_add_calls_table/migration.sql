-- CreateEnum
CREATE TYPE "public"."CallType" AS ENUM ('VOICE', 'VIDEO');

-- CreateEnum
CREATE TYPE "public"."CallStatus" AS ENUM ('PENDING', 'RINGING', 'ACCEPTED', 'DECLINED', 'ENDED', 'MISSED', 'BUSY');

-- CreateTable
CREATE TABLE "public"."calls" (
    "id" TEXT NOT NULL,
    "callerId" TEXT NOT NULL,
    "calleeId" TEXT NOT NULL,
    "type" "public"."CallType" NOT NULL DEFAULT 'VOICE',
    "status" "public"."CallStatus" NOT NULL DEFAULT 'PENDING',
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "calls_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "public"."calls" ADD CONSTRAINT "calls_callerId_fkey" FOREIGN KEY ("callerId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."calls" ADD CONSTRAINT "calls_calleeId_fkey" FOREIGN KEY ("calleeId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
