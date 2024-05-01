import JwtSecretKeyStorage from '../repo/jwtSecretKeyStorage.js';
import { verify, JsonWebTokenError, TokenExpiredError, NotBeforeError } from 'jsonwebtoken';
import { APIGatewaySimpleAuthorizerResult } from 'aws-lambda';

type LegitJwtPayload = {
    userId: string;
}

class AuthValidateError {
    private reason: string;
    constructor(reason: string) {
        this.reason = reason;
    }
}

export default class AuthService {
    private path: string;
    private authHeader: string;

    constructor(path: string, authHeader: string) {
        this.path = path;
        this.authHeader = authHeader;
    }
    private parseJwtFromHeader(): string {
        const parts = this.authHeader.split(' ');
        if (parts.length !== 2) {
            throw new AuthValidateError("Invalid authorization header");
        }
        const scheme = parts[0];
        const jwt = parts[1];

        if (!/^Bearer$/i.test(scheme)) {
            throw new AuthValidateError("Invalid authorization header");
        }

        return jwt;
    }
    private async verifyToken(jwt: string): Promise<LegitJwtPayload> {
        const jwtSecretKeyStorage = JwtSecretKeyStorage.getInstance();
        try {
            const secretKey = await jwtSecretKeyStorage.getSecretKey();

            const decoded = verify(jwt, secretKey);

            return decoded as LegitJwtPayload;

        } catch (err) {
            if (err instanceof JsonWebTokenError || err instanceof TokenExpiredError || err instanceof NotBeforeError) {
                throw new AuthValidateError("Invalid token");
            }
            throw err;
        }
    }

    private async getUserUUIDFromToken(legitJwtPayload: LegitJwtPayload): Promise<string> {
        return legitJwtPayload.userId;
    }

    private checkPathMatchWithUserId(userId: string): void {
        const legitPathPrefix = `/account/${userId}`;
        
        if (!this.path.startsWith(legitPathPrefix)) {
            throw new AuthValidateError("Requested path does not match with userId");
        }
    }
    private generateAllowPolicy(userId: string): APIGatewaySimpleAuthorizerResult {
        return {
            isAuthorized: true,
            context: {
                userUUID: userId
            }
        };
    }
    private generateDenyPolicy(): APIGatewaySimpleAuthorizerResult {
        return {
            isAuthorized: false
        };
    }
    public async authorize(): Promise<APIGatewaySimpleAuthorizerResult> {
        try {
            const jwt = this.parseJwtFromHeader();
            const legitJwtPayload = await this.verifyToken(jwt);
            const userId = await this.getUserUUIDFromToken(legitJwtPayload);
            this.checkPathMatchWithUserId(userId);
            return this.generateAllowPolicy(userId);
            
        } catch (err) {
            if (err instanceof AuthValidateError) {
                return this.generateDenyPolicy();
            }
            throw err;
        }
    }
}