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
    private jwt: string;

    constructor(path: string, jwt: string) {
        this.path = path;
        this.jwt = jwt;
    }
    private async verifyToken(): Promise<LegitJwtPayload> {
        const jwtSecretKeyStorage = JwtSecretKeyStorage.getInstance();
        try {
            const secretKey = await jwtSecretKeyStorage.getSecretKey();

            const decoded = verify(this.jwt, secretKey);

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
            const legitJwtPayload = await this.verifyToken();
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