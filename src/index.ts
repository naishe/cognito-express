import * as jwkToPem from 'jwk-to-pem';
import * as request from 'request-promise';
import * as jwt from 'jsonwebtoken';
import { CognitoExpressConfig } from './CognitoExpressConfig';
import JwtVerifyParams from './JwtVerifyParams';
import DecodedJwt from './DecodedJwt';
import ValidateCallback from './ValidateCallback';

export const DEFAULT_TOKEN_EXPIRATION = `3600000`;

class CognitoExpress {
  userPoolId: string;
  tokenUse: string;
  tokenExpiration: string;
  iss: string;
  pems: Record<string, string> = {};

  constructor(config: CognitoExpressConfig) {
    if (!config)
      throw new TypeError(
        'Options not found. Please refer to README for usage example at https://github.com/ghdna/cognito-express',
      );

    validateConfig(config);
    this.userPoolId = config.cognitoUserPoolId;
    this.tokenUse = config.tokenUse;
    this.tokenExpiration = config.tokenExpiration || DEFAULT_TOKEN_EXPIRATION;
    this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${this.userPoolId}`;
  }

  async init(callback: (isOk: boolean) => void): Promise<void> {
    try {
      const response = await request(`${this.iss}/.well-known/jwks.json`);
      const keys = JSON.parse(response)['keys'];
      for (let i = 0; i < keys.length; i++) {
        const key_id = keys[i].kid;
        const modulus = keys[i].n;
        const exponent = keys[i].e;
        const key_type = keys[i].kty;
        const jwk = { kty: key_type, n: modulus, e: exponent };
        const pem = jwkToPem(jwk);
        this.pems[key_id] = pem;
      }
      callback(true);
    } catch (err) {
      callback(false);
      throw new TypeError('Unable to generate certificate due to \n' + err);
    }
  }

  validate(token: string, callback: ValidateCallback): void;
  validate(token: string): Promise<Record<string, unknown>>;
  validate(token: string, callback?: ValidateCallback): void | Promise<Record<string, unknown>> {
    const decodedJwt = jwt.decode(token, {
      complete: true,
    }) as DecodedJwt | null;

    if (!decodedJwt) return callbackElseThrow(new Error(`Not a valid JWT token`), callback);

    if (decodedJwt.payload.iss !== this.iss)
      return callbackElseThrow(new Error(`token is not from your User Pool`), callback);

    if (decodedJwt.payload.token_use !== this.tokenUse)
      return callbackElseThrow(new Error(`Not an ${this.tokenUse} token`), callback);

    const kid = decodedJwt.header.kid;
    const pem = this.pems && this.pems[kid];

    if (!pem) return callbackElseThrow(new Error(`Invalid ${this.tokenUse} token`), callback);

    const params = {
      token: token,
      pem: pem,
      iss: this.iss,
      maxAge: this.tokenExpiration,
    };

    if (callback) {
      jwtVerify(params, callback);
    } else {
      return new Promise((resolve, reject) => {
        jwtVerify(params, (err, result) => {
          if (err) {
            reject(err);
          } else {
            resolve(result as Record<string, undefined>);
          }
        });
      });
    }
    // });

    // if (!callback) {
    //   return p;
    // }
  }
}

function validateConfig(config: CognitoExpressConfig): boolean | never {
  let configurationPassed = false;
  switch (true) {
    case !config.region:
      throw new TypeError('AWS Region not specified in constructor');
      break;
    case !config.cognitoUserPoolId:
      throw new TypeError('Cognito User Pool ID is not specified in constructor');
      break;
    case !config.tokenUse:
      throw new TypeError("Token use not specified in constructor. Possible values 'access' | 'id'");
      break;
    case !(config.tokenUse == 'access' || config.tokenUse == 'id'):
      throw new TypeError("Token use values not accurate in the constructor. Possible values 'access' | 'id'");
      break;
    default:
      configurationPassed = true;
  }
  return configurationPassed;
}

function jwtVerify(params: JwtVerifyParams, callback: jwt.VerifyCallback): void {
  jwt.verify(
    params.token,
    params.pem,
    {
      issuer: params.iss,
      maxAge: params.maxAge,
    },
    function (err, payload) {
      if (err) return callback(err, undefined);
      return callback(null, payload);
    },
  );
}

function callbackElseThrow(err: Error, callback?: ValidateCallback) {
  if (callback) {
    callback(err);
  } else {
    throw err;
  }
}

export default CognitoExpress;
