/*
  Warnings:

  - You are about to drop the column `responseMs` on the `TargetCheck` table. All the data in the column will be lost.
  - Added the required column `responseTimeMs` to the `TargetCheck` table without a default value. This is not possible if the table is not empty.

*/
-- CreateTable
CREATE TABLE "UserUsage" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "userId" INTEGER NOT NULL,
    "credits" REAL NOT NULL DEFAULT 3000,
    "updatedAt" DATETIME NOT NULL,
    "resetAt" DATETIME NOT NULL,
    CONSTRAINT "UserUsage_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_TargetCheck" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "targetId" INTEGER NOT NULL,
    "up" BOOLEAN NOT NULL,
    "statusCode" INTEGER,
    "responseTimeMs" INTEGER NOT NULL,
    "timestamp" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "TargetCheck_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_TargetCheck" ("id", "statusCode", "targetId", "timestamp", "up") SELECT "id", "statusCode", "targetId", "timestamp", "up" FROM "TargetCheck";
DROP TABLE "TargetCheck";
ALTER TABLE "new_TargetCheck" RENAME TO "TargetCheck";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE UNIQUE INDEX "UserUsage_userId_key" ON "UserUsage"("userId");
