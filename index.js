const jwt = require('jsonwebtoken');

function executeOnFailed(onFailed) {
  if (onFailed instanceof Error) {
    throw onFailed;
  }

  return typeof onFailed === 'function' ? onFailed() : onFailed;
}

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
  }) {
    this.syncFn = syncFn;
    this.secret = secret;
  }

  getPermissions() {
    return this.payload.permissions;
  }

  verifyToken(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.secret, (err, payload) => {
        if (err) {
          reject(err);
        } else {
          resolve(payload);
        }
      })
    });
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
          },
        };
      } catch (ex) {
        return optionsObj;
      }
    };
  }

  async sync() {
    if (this.syncFn) {
      this.payload = await this.syncFn(this.payload);
    }
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

    if ((logined || actions || onlineData) && !keeper) {
      return executeOnFailed(onFailed);
    }

    if (onlineData) {
      await keeper.sync();
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
        return executeOnFailed(onFailed);
      }
    }

    return handler(root, args, {
      ...context,
      authPayload: keeper.payload,
    }, ast);
  };
}

Object.defineProperty(exports, "__esModule", {
  value: true
});

module.exports.default = GraphQLAuthKeeper;
module.exports.authKeeper = authKeeper;
