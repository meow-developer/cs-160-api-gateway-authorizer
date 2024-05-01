import { APIGatewayEventRequestContextV2, APIGatewaySimpleAuthorizerResult } from 'aws-lambda';
import AuthService from './service/authService.js';

export const handler = async(
    event: APIGatewayEventRequestContextV2
): Promise<APIGatewaySimpleAuthorizerResult> => {
    try {
        const token = event.headers.Authorization;

        const authService = new AuthService(event.http.path, token);
        const result = await authService.authorize();

        return result;

    } catch (error) {
        console.error(error);
        return {
            isAuthorized: false
        }
    }
};