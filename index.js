const jwtDecode = require('jwt-decode');

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
  constructor(token, syncFn) {
    this.syncFn = syncFn;
    this.token = token;
    this.payload = jwtDecode(token);
  }

  getPermissions() {
    return this.payload.permissions;
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
      executeOnFailed(onFailed);
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

    return handler(root, args, context, ast);
  };
}

function graphqlAuthKeeper(ctx, syncFn) {
  const token = ctx.header.authorization ?
    ctx.header.authorization.replace(/^Bearer\s/, '') : ctx.query.access_token;

  return token ? new GraphQLAuthKeeper(token, syncFn) : null;
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

module.exports.default = graphqlAuthKeeper;
module.exports.authKeeper = authKeeper;
module.exports.FLAG = FLAG;
