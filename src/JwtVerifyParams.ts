export type JwtVerifyParams = {
  token: string;
  pem: string;
  iss: string;
  maxAge: string;
};

export default JwtVerifyParams;
