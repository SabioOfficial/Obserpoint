-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_TargetCheck" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "targetId" INTEGER NOT NULL,
    "up" BOOLEAN NOT NULL,
    "statusCode" INTEGER,
    "responseTimeMs" INTEGER,
    "timestamp" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "TargetCheck_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_TargetCheck" ("id", "responseTimeMs", "statusCode", "targetId", "timestamp", "up") SELECT "id", "responseTimeMs", "statusCode", "targetId", "timestamp", "up" FROM "TargetCheck";
DROP TABLE "TargetCheck";
ALTER TABLE "new_TargetCheck" RENAME TO "TargetCheck";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
