# graphql-auth-keeper
Endpoint Auth Keeper for GraphQL Application

## Apollo Server Support
```javascript
const authKeeper = new GraphQLAuthKeeper({
  secret: 'JWT_SECRET',
});

const server = new ApolloServer(authKeeper.apolloServerOptions({ schema }));
```

## Example

### Member Action Check
```javascript
import {
  GraphQLInt,
  GraphQLNonNull,
  GraphQLString,
} from 'graphql';
import Koa from 'koa';
import Router from 'koa-router';
import koaBody from 'koa-bodyparser';
import { graphqlKoa, graphiqlKoa } from 'apollo-server-koa';
import GraphQLAuthKeeper, { authKeeper } from 'graphql-auth-keeper';
import { SubscriptionServer } from 'subscriptions-transport-ws';
import { db } from './db';
import { memberType } from './memberType';

const CREATE_MEMBER = {
  name: 'Create Member',
  code: 1,
};

const meQuery = {
  type: memberType,
  resolve: authKeeper({
    onFailed: new Error('Auth Failed'),
    onlineData: true,
  })(member => member),
};

const createMemberMutation = {
  type: GraphQLInt,
  args: {
    account: {
      type: new GraphQLNonNull(GraphQLString),
    },
    password: {
      type: new GraphQLNonNull(GraphQLString),
    },
  },
  resolve: authKeeper({
    onFailed: new Error('Auth Failed'),
    actions: CREATE_MEMBER,    
  })(async (member, {
    account,
    password,
  }) => {
    const createdMember = await db.models.Member.create({
      account,
      password,
      CreatorId: member.id,
    });

    return createdMember.id;
  }),
};

const schema = new GraphQLSchema({
  query: new GraphQLObjectType({
    name: 'Query',
    fields: {
      me: meQuery,
    },
  }),
  mutation: new GraphQLObjectType({
    name: 'Mutation',
    fields: {
      createMember: createMemberMutation,
    },
  }),
});

const app = new Koa();
const router = new Router();
const authKeeper = new GraphQLAuthKeeper({
  syncFn: payload => db.models.Member.findOne({
    where: {
      id: payload.id,
    },
  }),
  secret: 'JWT_SECRET',
});

router.post('/graphql', koaBody(), graphqlKoa(authKeeper.middleware({
  schema,
})));

app.use(router.routes());
app.use(router.allowedMethods());

const server = createServer(app.callback());

SubscriptionServer.create({
  schema,
  subscribe,
  execute,
  onOperation: authKeeper.subscriptionOperationMiddleware(),
}, {
  server,
  path: '/graphql',
});

server.listen(3000);
```

## Keeper Options

- secret(string)[required]: JWT Secret
- syncFn(Function): Should return live data by payload info

## Route Options

- logined(boolean): Require valid JWT token or not
- actions(Action | Array<Action>): Required actions
- onlineData(boolean): Should return online (syncd) data on resolve payload
- onFailed(Error | Function | any): If Error given will throw it. Function will execute and return it result or return data directly.
- orMode(boolean): The actions should be match all or partial.
