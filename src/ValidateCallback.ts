import { VerifyErrors } from 'jsonwebtoken';

export type ValidateCallback = (err: VerifyErrors | Error | null, decoded?: object) => void;
export default ValidateCallback;
