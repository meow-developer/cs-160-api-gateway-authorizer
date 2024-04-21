import { APIGatewayAuthorizerResult } from 'aws-lambda';


export default class PolicyGenerator {
    private resource: string;
    constructor(resource: string) {
        this.resource = resource;
    }
    private generatePolicy( principalId: string, effect: string): APIGatewayAuthorizerResult {
        const authResponse: APIGatewayAuthorizerResult = {
            principalId: principalId,
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: effect,
                        Resource: this.resource
                    }
                ]
            }
        };
        
        return authResponse;
    }

    public generateAllowPolicy(userId: string): APIGatewayAuthorizerResult {
        return this.generatePolicy(userId, 'Allow');
    }

    public generateDenyPolicy(): APIGatewayAuthorizerResult {
        const INVALID_USER_ID = 'invalid-user';
        return this.generatePolicy(INVALID_USER_ID, 'Deny');
    }
}