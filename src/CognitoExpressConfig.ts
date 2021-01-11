export type CognitoExpressConfig = {
  cognitoUserPoolId: string;
  tokenUse: string;
  /** Refer: maxAge from https://github.com/auth0/node-jsonwebtoken */
  tokenExpiration?: string;
  region: string;
};

export default CognitoExpressConfig;
