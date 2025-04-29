import { JwtPayload } from '../index'; // Import JwtPayload from main file

declare module 'express-serve-static-core' {
  interface Request {
    user?: JwtPayload; // Add user property to Request
  }
}
