import * as jwkToPem from 'jwk-to-pem';
import * as request from 'request-promise';
import * as jwt from 'jsonwebtoken';
import { CognitoExpressConfig } from './CognitoExpressConfig';
import JwtVerifyParams from './JwtVerifyParams';

export const DEFAULT_TOKEN_EXPIRATION = `3600000`;

class CognitoExpress {
  userPoolId: string;
  tokenUse: string;
  tokenExpiration: string;
  iss: string;
  promise: Promise<void>;
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
    this.promise = this.init((callback) => {});
  }

  async init(callback: (isOk: boolean) => void) {
    return request(`${this.iss}/.well-known/jwks.json`)
      .then((response) => {
        let keys = JSON.parse(response)['keys'];
        for (let i = 0; i < keys.length; i++) {
          let key_id = keys[i].kid;
          let modulus = keys[i].n;
          let exponent = keys[i].e;
          let key_type = keys[i].kty;
          let jwk = { kty: key_type, n: modulus, e: exponent };
          let pem = jwkToPem(jwk);
          this.pems[key_id] = pem;
        }
        callback(true);
      })
      .catch((err) => {
        callback(false);
        throw new TypeError('Unable to generate certificate due to \n' + err);
      });
  }

  validate(token: string, callback: jwt.VerifyCallback): void;
  validate(token: string): Promise<object>;
  validate(token: string, callback?: jwt.VerifyCallback) {
    const p = this.promise.then(() => {
      let decodedJwt = jwt.decode(token, {
        complete: true,
      }) as { [k: string]: any } | null;

      if (!decodedJwt) return callback(new Error(`Not a valid JWT token`), null);

      if (decodedJwt.payload.iss !== this.iss) return callback(new Error(`token is not from your User Pool`), null);

      if (decodedJwt.payload.token_use !== this.tokenUse)
        return callback(new Error(`Not an ${this.tokenUse} token`), null);

      let kid = decodedJwt.header.kid;
      let pem = this.pems && this.pems[kid];

      if (!pem) return callback(new Error(`Invalid ${this.tokenUse} token`), null);

      let params = {
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
              resolve(result);
            }
          });
        });
      }
    });

    if (!callback) {
      return p;
    }
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

function jwtVerify(params: JwtVerifyParams, callback: jwt.VerifyCallback) {
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

export default CognitoExpress;
