import { APIGatewayTokenAuthorizerEvent, APIGatewayAuthorizerResult, Context, Callback } from 'aws-lambda';
import PolicyGenerator from './service/authorization.js';
import TokenVerify from './service/tokenVerify.js';

export const handler = async(
    event: APIGatewayTokenAuthorizerEvent,
    context: Context,
    callback: Callback<APIGatewayAuthorizerResult>
): Promise<void> => {
    const token = event.authorizationToken;

    const tokenVerify = new TokenVerify();
    const policyGenerator = new PolicyGenerator(event.methodArn);
    
    const [isTokenValid, decoded] = await tokenVerify.verify(token);


    if (isTokenValid) {
        callback(null, policyGenerator.generateAllowPolicy(decoded.userId));
    } else {
        callback("Unauthorized");
    }
};


