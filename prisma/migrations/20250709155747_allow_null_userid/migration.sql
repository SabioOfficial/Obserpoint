-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Target" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "intervalSeconds" INTEGER NOT NULL,
    "userId" INTEGER,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Target_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Target" ("createdAt", "id", "intervalSeconds", "name", "url", "userId") SELECT "createdAt", "id", "intervalSeconds", "name", "url", "userId" FROM "Target";
DROP TABLE "Target";
ALTER TABLE "new_Target" RENAME TO "Target";
CREATE UNIQUE INDEX "Target_url_key" ON "Target"("url");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
