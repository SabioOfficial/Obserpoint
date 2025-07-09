/*
  Warnings:

  - Added the required column `userId` to the `Target` table without a default value. This is not possible if the table is not empty.

*/
-- CreateTable
CREATE TABLE "TargetCheck" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "targetId" INTEGER NOT NULL,
    "up" BOOLEAN NOT NULL,
    "statusCode" INTEGER,
    "responseMs" INTEGER NOT NULL,
    "timestamp" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "TargetCheck_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Target" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "intervalSeconds" INTEGER NOT NULL,
    "userId" INTEGER NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Target_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_Target" ("id", "intervalSeconds", "name", "url") SELECT "id", "intervalSeconds", "name", "url" FROM "Target";
DROP TABLE "Target";
ALTER TABLE "new_Target" RENAME TO "Target";
CREATE UNIQUE INDEX "Target_url_key" ON "Target"("url");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
