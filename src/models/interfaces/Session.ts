export interface SessionDetails {
  userId: number;
  refreshToken: string;
  expiresAt: Date;
  createdAt: Date;
  ipAddress: string;
  userAgent: string;
  revoked: boolean;
}
