import { User } from '@twogate/auth0-spa-js';
import { AuthState } from './auth-state';
declare type Action =
  | {
      type: 'LOGIN_POPUP_STARTED';
    }
  | {
      type:
        | 'INITIALISED'
        | 'LOGIN_POPUP_COMPLETE'
        | 'GET_ACCESS_TOKEN_COMPLETE'
        | 'HANDLE_REDIRECT_COMPLETE';
      user?: User;
    }
  | {
      type: 'LOGOUT';
    }
  | {
      type: 'ERROR';
      error: Error;
    };
/**
 * Handles how that state changes in the `useAuth0` hook.
 */
export declare const reducer: (
  state: AuthState<User>,
  action: Action
) => AuthState<User>;
export {};
//# sourceMappingURL=reducer.d.ts.map
