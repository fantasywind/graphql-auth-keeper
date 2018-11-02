const jwt = require('jsonwebtoken');
const debug = require('debug')('AuthKeeper:GraphQL');

function checkShouldHavePermission(permissionCode, actionCodes = [], orMode = false) {
  let shouldHaveActionCodes = actionCodes;

  if (!Array.isArray(actionCodes)) {
    shouldHaveActionCodes = [actionCodes];
  }

  if (orMode) {
    return shouldHaveActionCodes.some(code => (permissionCode & code) === code);
  }

  const intersectionPermission = shouldHaveActionCodes.reduce((last, next) => last | next, 0);

  return (permissionCode & intersectionPermission) === intersectionPermission;
}

const FLAG = Symbol('graphqlAuthKeeper');

class GraphQLAuthKeeper {
  constructor({
    syncFn,
    secret,
    onFailed,
  }) {
    this.syncFn = syncFn;
    this.secret = secret;
    this.onFailed = onFailed || new Error('[GraphQLAuthKeeper] Auth Error');
  }

  getPermissions() {
    return this.payload.permissions;
  }

  verifyToken(token, ignoreExpiration = false) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.secret, { ignoreExpiration }, (err, payload) => {
        if (err) {
          reject(err);
        } else {
          resolve(payload);
        }
      })
    });
  }

  apolloServerOptions(options = {}) {
    return {
      ...options,
      context: async ({ req }) => {
        const token = req.headers.authorization ?
          req.headers.authorization.replace(/^Bearer\s/, '') : req.query.access_token;

        if (!token) {
          return {
            ...(options.context || {}),
            [FLAG]: this,
          };
        }

        try {
          this.payload = await this.verifyToken(token);

          return {
            ...(options.context || {}),
            [FLAG]: this,
            authPayload: this.payload,
          };
        } catch (ex) {
          debug('Failed to parse JWT', ex);

          return {
            ...(options.context || {}),
            [FLAG]: this,
          };
        }
      },
    };
  }

  apolloServerKoaOptions(options = {}) {
    return {
      ...options,
      context: async ({ ctx }) => {
        const token = ctx.request.headers.authorization ?
          ctx.request.headers.authorization.replace(/^Bearer\s/, '') : ctx.query.access_token;

        if (!token) {
          return {
            ...(options.context || {}),
            [FLAG]: this,
          };
        }

        try {
          this.payload = await this.verifyToken(token);

          return {
            ...(options.context || {}),
            [FLAG]: this,
            authPayload: this.payload,
          };
        } catch (ex) {
          debug('Failed to parse JWT', ex);

          return {
            ...(options.context || {}),
            [FLAG]: this,
          };
        }
      },
    };
  }

  middleware(options = {}) {
    return async (ctx) => {
      let optionsObj = typeof options === 'function' ? await options() : options;

      const token = ctx.request.header.authorization ?
        ctx.request.header.authorization.replace(/^Bearer\s/, '') : ctx.query.access_token;

      try {
        this.payload = await this.verifyToken(token);

        return {
          ...optionsObj,
          context: {
            ...(optionsObj.context || {}),
            [FLAG]: this,
            authPayload: this.payload,
          },
        };
      } catch (ex) {
        return {
          ...optionsObj,
          context: {
            ...(optionsObj.context || {}),
            [FLAG]: this,
          },
        };
      }
    };
  }

  subscriptionOperationMiddleware(options = {}) {
    return async (message, params, socket) => {
      let optionsObj = typeof options === 'function' ? await options() : options;

      const token = (message.payload.authorization || socket.upgradeReq.headers.authorization || '').replace(/^Bearer\s/, '');

      try {
        this.payload = await this.verifyToken(token, true);

        return {
          ...params,
          ...optionsObj,
          context: {
            ...(optionsObj.context || {}),
            [FLAG]: this,
            authPayload: this.payload,
          },
        };
      } catch (ex) {
        return {
          ...params,
          ...optionsObj,
          context: {
            ...(optionsObj.context || {}),
            [FLAG]: this,
          },
        };
      }
    };
  }

  async sync() {
    if (this.syncFn) {
      this.payload = await this.syncFn(this.payload);
    }
  }

  executeOnFailed(onFailed) {
    const onFailedHandler = onFailed || this.onFailed;

    if (onFailedHandler instanceof Error) {
      throw onFailedHandler;
    }

    return typeof onFailedHandler === 'function' ? onFailedHandler() : onFailedHandler;
  }
}

function authKeeper({
  logined,
  actions,
  onlineData,
  onFailed,
  orMode,
}) {
  return handler => async (root, args, context, ast) => {
    const keeper = context[FLAG];

    if ((logined || actions || onlineData) && !context.authPayload) {
      return keeper.executeOnFailed(onFailed);
    }

    if (actions) {
      const willCheckedActions = (
        Array.isArray(actions) ? actions : [actions]
      );

      if (!checkShouldHavePermission(
        keeper.getPermissions(),
        willCheckedActions.map(action => action.code),
        !!orMode,
      )) {
        return keeper.executeOnFailed(onFailed);
      }
    }

    const mixinContext = {
      ...context,
      authPayload: keeper.payload,
      jwtPayload: keeper.payload,
    };

    if (onlineData) {
      await keeper.sync();

      mixinContext.authPayload = keeper.payload;
    }

    return handler(root, args, mixinContext, ast);
  };
}

Object.defineProperty(exports, "__esModule", {
  value: true
});

module.exports.default = GraphQLAuthKeeper;
module.exports.authKeeper = authKeeper;
