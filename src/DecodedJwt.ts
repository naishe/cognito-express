export type DecodedJwt = {
  payload: {
    iss: string;
    token_use: string;
  };
  header: { kid: string };
};

export default DecodedJwt;
