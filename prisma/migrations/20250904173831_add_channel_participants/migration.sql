-- AlterTable
ALTER TABLE "public"."channels" ADD COLUMN     "isDM" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "public"."channel_participants" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "channelId" TEXT NOT NULL,

    CONSTRAINT "channel_participants_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "channel_participants_userId_channelId_key" ON "public"."channel_participants"("userId", "channelId");

-- AddForeignKey
ALTER TABLE "public"."channel_participants" ADD CONSTRAINT "channel_participants_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."channel_participants" ADD CONSTRAINT "channel_participants_channelId_fkey" FOREIGN KEY ("channelId") REFERENCES "public"."channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;
