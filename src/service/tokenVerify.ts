import JwtSecretKeyStorage from '../repo/jwtSecretKeyStorage.js';
import jwt from 'jsonwebtoken';

export default class TokenVerify {
    public async verify (token: string): Promise<Array<any>> {
        const secretKeyStorage = JwtSecretKeyStorage.getInstance();
        const secretKey = await secretKeyStorage.getSecretKey();
        
        try {
            const decoded = jwt.verify(token, secretKey);
            return [true, decoded];
        } catch (err) {
            return [false];
        }
    }
}