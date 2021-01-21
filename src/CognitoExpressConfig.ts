export type CognitoExpressConfig = {
  cognitoUserPoolId: string;
  tokenUse: string;
  /** Refer: maxAge from https://github.com/auth0/node-jsonwebtoken */
  tokenExpiration?: string | number;
  region: string;
};

export default CognitoExpressConfig;
