import { customType } from "drizzle-orm/pg-core";

/**
 * Custom Drizzle column type for encrypted binary data stored as PostgreSQL bytea.
 *
 * The application is responsible for encrypting/decrypting the value — this type
 * only handles the base64 ↔ Buffer conversion at the driver boundary.
 *
 * Usage:
 *   privateKeyEncryptedForAdmin: encryptedText("private_key_encrypted_for_admin"),
 */
export const encryptedText = customType<{
  data: string;
  driverData: Buffer;
}>({
  dataType() {
    return "bytea";
  },
  toDriver(value: string): Buffer {
    // App provides base64-encoded encrypted bytes; store as raw binary.
    return Buffer.from(value || "", "base64");
  },
  fromDriver(value: Buffer): string {
    // Return base64 so the app layer can decrypt it.
    return value.toString("base64");
  },
});
